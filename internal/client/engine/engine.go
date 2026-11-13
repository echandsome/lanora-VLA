// Package engine runs one room connection from start to finish: it joins
// the room, creates the virtual adapter, runs WireGuard over the transport,
// keeps the signalling session alive, and reports what is happening.
//
// The data plane and the control plane fail independently. Once peers are
// known, traffic between them does not involve the server, so when the
// signalling connection drops the engine keeps the adapter and all peer
// connections up and reconnects in the background.
package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wireguard/device"

	"lanora/internal/client/control"
	"lanora/internal/client/netcfg"
	"lanora/internal/client/transport"
	"lanora/internal/client/vnet"
	"lanora/internal/proto"
)

// Phase is the coarse state of a connection.
type Phase int

const (
	PhaseIdle         Phase = iota // not started
	PhaseConnecting                // first connection in progress
	PhaseConnected                 // in the room
	PhaseReconnecting              // in the room, signalling connection lost
	PhaseStopped                   // finished (see State.Error)
)

func (p Phase) String() string {
	return [...]string{"idle", "connecting", "connected", "reconnecting", "stopped"}[p]
}

// State is a snapshot of the connection for display.
type State struct {
	Phase  Phase
	Detail string // what is happening right now, in plain words

	// Error and ErrorCode are set when the connection stopped because of a
	// failure rather than at the user's request.
	Error     string
	ErrorCode proto.ErrorCode

	Room     proto.RoomInfo
	IP       netip.Addr
	Nickname string
	Since    time.Time // when the room was entered

	Peers []Peer
	// Relay is how the relay is reached: "udp", "tcp" or "" when it is not.
	Relay      string
	PublicAddr netip.AddrPort
	Rx, Tx     uint64
}

// Peer is one other member of the room.
type Peer struct {
	IP       netip.Addr
	Nickname string
	Via      string         // proto.ViaDirect, proto.ViaRelay or proto.ViaNone
	Addr     netip.AddrPort // direct address in use
	RTT      time.Duration  // -1 when not measured yet
}

// Options configures an Engine.
type Options struct {
	Server   control.Address
	RoomID   string
	Password string
	Nickname string
	Identity ed25519.PrivateKey

	// Adapter is the template for the virtual adapter; the engine fills in
	// the address, subnet and MTU the server assigns.
	Adapter     netcfg.Config
	OpenAdapter netcfg.OpenFunc

	// Port is the local UDP port; zero picks a free one.
	Port uint16
	// RelayOnly sends everything through the relay and never reveals this
	// device's addresses to other room members.
	RelayOnly bool
	// AllowLoopback is for tests running several clients on one machine.
	AllowLoopback bool
	// Header is added to every request to the server (see control.Client).
	Header http.Header
	// Persistent makes the engine keep trying when the first connection
	// attempt cannot reach the server, instead of reporting the failure.
	// It is used when connecting automatically at startup.
	Persistent bool

	// OnState is called with every new state. Calls are serialised and
	// must not block for long.
	OnState func(State)
	Logger  *slog.Logger
}

// Engine is one room connection. Create it with New and call Run once.
type Engine struct {
	opts Options
	log  *slog.Logger

	mu    sync.Mutex
	state State
	stack *stack

	// epoch is the server run the last welcome came from.
	epoch string

	// Signalling messages queued by the transport.
	punches   chan netip.Addr
	endpoints atomic.Pointer[[]netip.AddrPort]
	kick      chan struct{}
}

// errRestart makes Run start over from the join: the server assigned this
// device a different address than the one the adapter was built for.
var errRestart = errors.New("engine: network parameters changed")

// New returns an engine that has not started.
func New(opts Options) *Engine {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Engine{
		opts:    opts,
		log:     opts.Logger.With("component", "engine"),
		punches: make(chan netip.Addr, 512),
		kick:    make(chan struct{}, 1),
	}
}

// Identity returns the device identity the engine joins with.
func (e *Engine) Identity() ed25519.PrivateKey { return e.opts.Identity }

// State returns the current state.
func (e *Engine) State() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snapshotLocked()
}

// update changes the state and notifies the listener.
func (e *Engine) update(fn func(*State)) {
	e.mu.Lock()
	fn(&e.state)
	s := e.snapshotLocked()
	if e.opts.OnState != nil {
		// Called under the lock so that listeners see states in order.
		e.opts.OnState(s)
	}
	e.mu.Unlock()
}

// snapshotLocked merges the engine's own state with live figures from the
// transport.
func (e *Engine) snapshotLocked() State {
	s := e.state
	s.Peers = nil
	if st := e.stack; st != nil {
		paths := make(map[netip.Addr]transport.PeerStatus)
		for _, p := range st.tr.Peers() {
			paths[p.IP] = p
		}
		for ip, info := range st.peers {
			peer := Peer{IP: ip, Nickname: info.Nickname, Via: proto.ViaNone, RTT: -1}
			if p, ok := paths[ip]; ok {
				peer.Via, peer.Addr, peer.RTT = p.Via, p.Addr, p.RTT
			}
			s.Peers = append(s.Peers, peer)
		}
		sort.Slice(s.Peers, func(i, j int) bool { return s.Peers[i].IP.Less(s.Peers[j].IP) })
		s.Relay, s.PublicAddr = st.tr.RelayStatus()
		s.Rx, s.Tx = st.tr.Traffic()
	}
	return s
}

// Run connects and stays connected until ctx is cancelled (it then returns
// nil) or the connection cannot continue (it returns why). The returned
// error's message is written for the user.
func (e *Engine) Run(ctx context.Context) error {
	var err error
	for {
		err = e.runOnce(ctx)
		if !errors.Is(err, errRestart) {
			break
		}
	}
	if ctx.Err() != nil {
		err = nil
	}
	e.update(func(s *State) {
		s.Phase, s.Detail = PhaseStopped, ""
		if err != nil {
			s.Error = err.Error()
			var api *proto.APIError
			if errors.As(err, &api) {
				s.ErrorCode = api.Code
			}
		}
	})
	return err
}

func (e *Engine) runOnce(ctx context.Context) error {
	cl := control.New(e.opts.Server, e.opts.Identity)
	cl.Header = e.opts.Header
	defer cl.Close()

	e.update(func(s *State) { s.Phase, s.Detail = PhaseConnecting, "Contacting the server…" })
	join, err := e.join(ctx, cl, e.opts.Persistent)
	if err != nil {
		return err
	}

	e.update(func(s *State) {
		s.Detail = "Setting up the network adapter…"
		s.Room, s.IP, s.Nickname = join.Room, join.IP, join.Nickname
	})
	st, err := e.buildStack(join, cl)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.stack = st
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.stack = nil
		e.mu.Unlock()
		st.close()
	}()

	return e.sessions(ctx, cl, st, join)
}

// join authenticates to the room. Failures that retrying cannot fix are
// returned at once. Others are retried: a few times for an interactive
// connect, so the user gets an answer quickly, and indefinitely when
// keepTrying is set.
func (e *Engine) join(ctx context.Context, cl *control.Client, keepTrying bool) (proto.JoinResponse, error) {
	wait := time.Second
	for attempt := 1; ; attempt++ {
		jctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		resp, err := cl.Join(jctx, e.opts.RoomID, e.opts.Password, e.opts.Nickname)
		cancel()
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil {
			return resp, ctx.Err()
		}
		var trust *control.TrustError
		if errors.As(err, &trust) {
			return resp, err
		}
		var api *proto.APIError
		if errors.As(err, &api) {
			switch {
			case api.Code == proto.CodeRateLimited && keepTrying:
				wait = max(wait, time.Duration(api.RetryAfter)*time.Second)
			case api.Code.Fatal() || api.Code == proto.CodeRateLimited || api.Code == proto.CodeRoomFull:
				return resp, err
			}
		}
		if !keepTrying && attempt >= 3 {
			return resp, err
		}
		e.log.Warn("join failed, retrying", "attempt", attempt, "err", err)
		e.update(func(s *State) { s.Detail = "The server is not answering. Trying again…" })
		select {
		case <-ctx.Done():
			return resp, ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, 30*time.Second)
	}
}

// stack is the local half of a room connection: the adapter, WireGuard and
// the transport, plus the peers configured into them.
type stack struct {
	ip      netip.Addr
	subnet  netip.Prefix
	mtu     int
	adapter netcfg.Adapter
	vdev    *vnet.Device
	tr      *transport.Transport
	dev     *device.Device

	wgPub    proto.Key32
	discoPub proto.Key32

	peers map[netip.Addr]proto.Peer // guarded by Engine.mu
	// retained holds peers kept although the server did not list them,
	// with the time each will be dropped unless it reappears (see
	// applyWelcome). Guarded by Engine.mu.
	retained map[netip.Addr]time.Time
}

func (e *Engine) buildStack(join proto.JoinResponse, cl *control.Client) (*stack, error) {
	if !join.IP.Is4() || !join.Room.Subnet.Contains(join.IP) || join.Room.MTU < 576 {
		return nil, errors.New("The server sent network settings this version of Lanora cannot use.")
	}
	// Fresh keys for every connection: nothing long-lived protects traffic,
	// so a key that leaks later cannot decrypt an earlier session.
	var wgPriv [32]byte
	if _, err := rand.Read(wgPriv[:]); err != nil {
		return nil, err
	}
	wgPriv[0] &= 248
	wgPriv[31] = wgPriv[31]&127 | 64
	wgPubRaw, err := curve25519.X25519(wgPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	discoPub, discoPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	cfg := e.opts.Adapter
	cfg.IP, cfg.Subnet, cfg.MTU = join.IP, join.Room.Subnet, join.Room.MTU
	if cfg.Logger == nil {
		cfg.Logger = e.log.With("part", "adapter")
	}
	adapter, err := e.opts.OpenAdapter(cfg)
	if err != nil {
		return nil, err
	}

	st := &stack{
		ip: join.IP, subnet: join.Room.Subnet, mtu: join.Room.MTU,
		adapter:  adapter,
		discoPub: proto.Key32(*discoPub),
		peers:    make(map[netip.Addr]proto.Peer),
		retained: make(map[netip.Addr]time.Time),
	}
	copy(st.wgPub[:], wgPubRaw)
	st.vdev = vnet.Wrap(adapter.Device(), join.IP, join.Room.Subnet)
	st.tr = transport.New(transport.Config{
		Self:          join.IP,
		Subnet:        join.Room.Subnet,
		DiscoKey:      discoPriv,
		Signal:        e,
		Logger:        e.opts.Logger,
		Port:          e.opts.Port,
		ControlHost:   cl.Host(),
		DialStream:    cl.DialStream,
		RelayOnly:     e.opts.RelayOnly,
		AllowLoopback: e.opts.AllowLoopback,
	})
	wgLog := e.opts.Logger.With("component", "wireguard")
	st.dev = device.NewDevice(st.vdev, st.tr, &device.Logger{
		Verbosef: func(format string, args ...any) { wgLog.Debug(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { wgLog.Warn(fmt.Sprintf(format, args...)) },
	})
	// Each peer's WireGuard endpoint is the transport's stable handle for
	// that peer. WireGuard must not replace it with whatever address a
	// packet happened to arrive from: choosing paths is the transport's job.
	st.dev.DisableSomeRoamingForBrokenMobileSemantics()
	if err := st.dev.IpcSet(fmt.Sprintf("private_key=%x\n", wgPriv[:])); err != nil {
		st.close()
		return nil, fmt.Errorf("configuring the tunnel: %w", err)
	}
	if err := st.dev.Up(); err != nil {
		st.close()
		return nil, fmt.Errorf("starting the tunnel: %w", err)
	}
	return st, nil
}

func (st *stack) close() {
	if st.dev != nil {
		st.dev.Close() // closes the transport and the adapter's device
	}
	st.adapter.Close()
}

// sessions keeps a signalling session open, reconnecting as needed.
func (e *Engine) sessions(ctx context.Context, cl *control.Client, st *stack, join proto.JoinResponse) error {
	token := join.Token
	wait := time.Second
	entered := false
	for {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		wg, disco := st.wgPub, st.discoPub
		sess, err := cl.OpenSession(sctx, token, proto.Msg{WGPub: &wg, DiscoPub: &disco, Endpoints: st.tr.Endpoints()})
		cancel()
		if err == nil {
			err = e.session(ctx, cl, sess, st, &entered)
			sess.Close()
			if entered {
				wait = time.Second
			}
		}
		if ctx.Err() != nil {
			return nil
		}

		var api *proto.APIError
		if errors.As(err, &api) {
			switch {
			case api.Code == proto.CodeUnauthorized:
				// The token expired, or the room's state moved on without
				// us. Authenticate again with the password.
				fresh, jerr := e.join(ctx, cl, true)
				if jerr != nil {
					return jerr
				}
				if fresh.IP != st.ip || fresh.Room.Subnet != st.subnet || fresh.Room.MTU != st.mtu {
					return errRestart
				}
				token = fresh.Token
				continue
			case api.Code.Fatal():
				return err
			case api.Code == proto.CodeRateLimited:
				wait = max(wait, time.Duration(api.RetryAfter)*time.Second)
			}
		}

		e.log.Warn("signalling connection lost", "err", err, "retry_in", wait.String())
		e.update(func(s *State) {
			if entered {
				s.Phase, s.Detail = PhaseReconnecting, "Reconnecting to the server. Connections to room members stay up."
			} else {
				s.Detail = "The server is not answering. Trying again…"
			}
		})
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		wait = min(wait*2, 30*time.Second)
	}
}

// session runs one signalling session until it ends. The returned error
// says why; it is never nil unless ctx was cancelled.
func (e *Engine) session(ctx context.Context, cl *control.Client, sess *control.Session, st *stack, entered *bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	wctx, wcancel := context.WithTimeout(ctx, 20*time.Second)
	first, err := sess.Read(wctx)
	wcancel()
	if err != nil {
		return err
	}
	if first.T == proto.MsgBye {
		return byeError(first)
	}
	if first.T != proto.MsgWelcome || first.Self == nil || first.Room == nil {
		return errors.New("the server did not start the session correctly")
	}
	if first.Self.IP != st.ip || first.Room.Subnet != st.subnet {
		return errRestart
	}

	e.applyWelcome(st, first)
	*entered = true
	// The HTTPS connection used to join would otherwise idle on the server
	// for a minute; the session has its own.
	cl.Close()
	e.update(func(s *State) {
		s.Phase, s.Detail, s.Room = PhaseConnected, "", *first.Room
		if s.Since.IsZero() {
			s.Since = time.Now()
		}
	})

	// Writer: the only goroutine that writes to the session.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		defer sess.Close() // unblocks the reader if writing fails
		status := time.NewTicker(statusInterval)
		defer status.Stop()
		ping := time.NewTicker(pingInterval)
		defer ping.Stop()
		refresh := time.NewTicker(time.Second)
		defer refresh.Stop()
		var lastReport string
		var lastSent time.Time
		for {
			var err error
			select {
			case <-ctx.Done():
				return
			case <-e.kick:
				if eps := e.endpoints.Swap(nil); eps != nil {
					err = sess.Write(ctx, proto.Msg{T: proto.MsgEndpoints, Endpoints: *eps})
				}
			case to := <-e.punches:
				err = sess.Write(ctx, proto.Msg{T: proto.MsgPunch, To: &to})
			case now := <-status.C:
				// The report feeds the dashboard. It is sent when paths
				// changed, and otherwise only often enough to keep the
				// traffic counters fresh.
				rep := e.statusReport(st)
				key := reportKey(rep)
				if key != lastReport || now.Sub(lastSent) >= statusRefresh {
					lastReport, lastSent = key, now
					err = sess.Write(ctx, proto.Msg{T: proto.MsgStatus, Status: rep})
				}
			case <-ping.C:
				err = sess.Ping(ctx)
			case now := <-refresh.C:
				e.dropExpired(st, now)
				// Paths and latency change without any message arriving.
				e.update(func(*State) {})
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() { cancel(); <-writerDone }()

	e.resetSignals(st)

	for {
		msg, err := sess.Read(ctx)
		if err != nil {
			return err
		}
		switch msg.T {
		case proto.MsgPeerJoined, proto.MsgPeerUpdate:
			if msg.Peer != nil {
				e.upsertPeer(st, *msg.Peer)
			}
		case proto.MsgPeerLeft:
			if msg.IP != nil {
				e.removePeer(st, *msg.IP)
			}
		case proto.MsgPunch:
			if msg.From != nil {
				st.tr.HandlePunch(*msg.From, msg.Endpoints)
			}
		case proto.MsgRelay:
			if msg.Relay != nil {
				st.tr.SetRelay(*msg.Relay)
			}
		case proto.MsgBye:
			return byeError(msg)
		}
	}
}

// Signalling keepalive and reporting intervals. The server drops a session
// that has been silent for 70 seconds.
const (
	pingInterval   = 25 * time.Second
	statusInterval = 20 * time.Second
	statusRefresh  = time.Minute
)

// reportKey summarises the part of a status report whose change is worth
// telling the server about at once: which path each peer is on.
func reportKey(rep *proto.StatusReport) string {
	var b []byte
	for _, p := range rep.Peers {
		b = append(b, p.IP.String()...)
		b = append(b, '=')
		b = append(b, p.Via...)
		b = append(b, ' ')
	}
	return string(b)
}

func byeError(m *proto.Msg) error {
	msg := m.Message
	if msg == "" {
		msg = "The server ended the session."
	}
	return &proto.APIError{ErrorBody: proto.ErrorBody{Code: m.Code, Message: msg}}
}

// restartGrace is how long peers the server no longer lists are kept after
// a server restart, to give them time to reconnect to it.
const restartGrace = 30 * time.Second

// applyWelcome brings the local peer set in line with the room's.
//
// Normally the server's list is the truth and a peer missing from it is
// removed at once: it left, or was removed, while this client's signalling
// was down. After a server restart the list means something else. The
// server starts with an empty room and learns of members as they reconnect,
// so the first client back is told the room is empty while its connections
// to the others are still working. Dropping them would interrupt everyone
// for nothing. In that case the missing peers are kept for a grace period
// and dropped only if they have not reappeared by then.
func (e *Engine) applyWelcome(st *stack, w *proto.Msg) {
	if w.Relay != nil {
		st.tr.SetRelay(*w.Relay)
	}
	want := make(map[netip.Addr]bool, len(w.Peers))
	for _, p := range w.Peers {
		want[p.IP] = true
	}
	e.mu.Lock()
	restarted := e.epoch != "" && w.Epoch != e.epoch
	e.epoch = w.Epoch
	deadline := time.Now().Add(restartGrace)
	var gone []netip.Addr
	for ip := range st.peers {
		switch {
		case want[ip]:
		case restarted:
			st.retained[ip] = deadline
		default:
			if _, kept := st.retained[ip]; !kept {
				gone = append(gone, ip)
			}
		}
	}
	e.mu.Unlock()
	if restarted {
		st.tr.RebindRelay()
	}
	for _, ip := range gone {
		e.removePeer(st, ip)
	}
	for _, p := range w.Peers {
		e.upsertPeer(st, p)
	}
}

// dropExpired removes retained peers whose grace period ran out.
func (e *Engine) dropExpired(st *stack, now time.Time) {
	e.mu.Lock()
	var gone []netip.Addr
	for ip, deadline := range st.retained {
		if now.After(deadline) {
			gone = append(gone, ip)
		}
	}
	e.mu.Unlock()
	for _, ip := range gone {
		e.removePeer(st, ip)
	}
}

// upsertPeer adds a room member, or applies a change to one.
func (e *Engine) upsertPeer(st *stack, p proto.Peer) {
	if !p.IP.Is4() || p.IP == st.ip || !st.subnet.Contains(p.IP) || p.WGPub.IsZero() || p.DiscoPub.IsZero() {
		return
	}
	e.mu.Lock()
	old, known := st.peers[p.IP]
	e.mu.Unlock()
	if known && old.WGPub != p.WGPub {
		// A new WireGuard key means a new session of that member: the old
		// peer entry must go, or its address could not be re-assigned.
		e.removePeer(st, p.IP)
		known = false
	}
	// The transport must know the peer before WireGuard is given its
	// endpoint, which names the peer by address.
	st.tr.SetPeer(p)
	if !known {
		conf := fmt.Sprintf("public_key=%s\nendpoint=%s\nallowed_ip=%s/32\n", p.WGPub.Hex(), p.IP, p.IP)
		if err := st.dev.IpcSet(conf); err != nil {
			e.log.Error("adding peer to the tunnel", "peer", p.IP.String(), "err", err)
			st.tr.RemovePeer(p.IP)
			return
		}
	}
	e.mu.Lock()
	st.peers[p.IP] = p
	delete(st.retained, p.IP) // the server knows it again
	e.setBroadcastPeersLocked(st)
	e.mu.Unlock()
	e.update(func(*State) {})
}

func (e *Engine) removePeer(st *stack, ip netip.Addr) {
	e.mu.Lock()
	p, ok := st.peers[ip]
	delete(st.retained, ip)
	if ok {
		delete(st.peers, ip)
		e.setBroadcastPeersLocked(st)
	}
	e.mu.Unlock()
	if !ok {
		return
	}
	if err := st.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", p.WGPub.Hex())); err != nil {
		e.log.Error("removing peer from the tunnel", "peer", ip.String(), "err", err)
	}
	st.tr.RemovePeer(ip)
	e.update(func(*State) {})
}

func (e *Engine) setBroadcastPeersLocked(st *stack) {
	ips := make([]netip.Addr, 0, len(st.peers))
	for ip := range st.peers {
		ips = append(ips, ip)
	}
	st.vdev.SetPeers(ips)
}

func (e *Engine) statusReport(st *stack) *proto.StatusReport {
	paths := st.tr.Peers()
	rep := &proto.StatusReport{Peers: make([]proto.PeerStatus, 0, len(paths))}
	for _, p := range paths {
		rtt := -1
		if p.RTT >= 0 {
			rtt = int(p.RTT.Round(time.Millisecond) / time.Millisecond)
		}
		rep.Peers = append(rep.Peers, proto.PeerStatus{IP: p.IP, Via: p.Via, RTT: rtt})
	}
	rep.Rx, rep.Tx = st.tr.Traffic()
	return rep
}

// PublishEndpoints implements transport.Signaler. Only the newest list
// matters, so it replaces any that is still waiting to be sent.
func (e *Engine) PublishEndpoints(eps []netip.AddrPort) {
	e.endpoints.Store(&eps)
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// RequestPunch implements transport.Signaler.
func (e *Engine) RequestPunch(peer netip.Addr) {
	select {
	case e.punches <- peer:
	default:
	}
}

// resetSignals prepares the signalling queues for a new session. Punch
// requests queued earlier are only useful at the moment they were made and
// are dropped. The endpoint list is sent once more: the transport may have
// learned its public address after the hello message was built, and it only
// announces changes.
func (e *Engine) resetSignals(st *stack) {
	for {
		select {
		case <-e.punches:
			continue
		default:
		}
		break
	}
	e.PublishEndpoints(st.tr.Endpoints())
}

// Rebind tells the engine the local network may have changed, so paths are
// re-verified immediately instead of at the next probe.
func (e *Engine) Rebind() {
	e.mu.Lock()
	st := e.stack
	e.mu.Unlock()
	if st != nil {
		st.tr.Rebind()
	}
}
