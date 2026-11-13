package transport

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"lanora/internal/proto"
)

// Relay binding timing.
const (
	bindRetry     = time.Second      // between bind attempts while unbound
	bindKeepalive = 5 * time.Second  // refresh while bound (also keeps the NAT mapping open)
	bindLost      = 16 * time.Second // no ack for this long: the binding is gone

	// A network on which UDP to the relay works for a moment and then dies
	// (seen on a mobile carrier) must not be allowed to pull the client off
	// a working TCP stream again and again: every such switch is a silence
	// of bindLost. After UDP has failed once, it is left alone for a while
	// and must then answer several probes in a row before it is used again.
	udpHoldFirst   = 30 * time.Second
	udpHoldMax     = 10 * time.Minute
	probeEvery     = 2 * time.Second
	probesNeeded   = 5
	udpProven      = 5 * time.Minute // bound this long: the earlier failures are forgiven
	streamGiveUp   = 20 * time.Second
	streamAfter    = 5 * time.Second  // UDP silent this long: also try the TCP fallback
	streamKeep     = 20 * time.Second // idle keepalive on the stream
	streamQueueLen = 512
	resolveEvery   = 5 * time.Minute
)

// StreamConn is the TCP-fallback relay connection: a message-oriented
// stream in which every message is one relayed packet.
type StreamConn interface {
	Read(ctx context.Context) ([]byte, error)
	Write(ctx context.Context, msg []byte) error
	Close() error
}

// StreamDialer opens the stream relay at url (which may be a path relative
// to the control server), presenting authorization as the bearer ticket.
type StreamDialer func(ctx context.Context, url, authorization string) (StreamConn, error)

// relayClient maintains this client's session with the room's relay.
type relayClient struct {
	t *Transport

	mu         sync.Mutex
	info       proto.RelayInfo
	host       string // "host:port" the current address was resolved from
	resolvedAt time.Time
	resolving  bool
	addr       netip.AddrPort
	tx         proto.TxID
	cookie     [proto.CookieLen]byte
	hasCookie  bool
	firstTry   time.Time // start of the current run of unanswered attempts
	lastTry    time.Time
	lastAck    time.Time
	reflexive  netip.AddrPort
	rejected   bool // the relay refused our ticket; wait for a new one
	dialing    bool

	udpFailures  int       // UDP bindings lost in a row
	udpHoldUntil time.Time // no UDP attempts before this
	probeTx      proto.TxID
	probeSentAt  time.Time
	probeWaiting bool // the last probe has not been answered
	probeOK      int  // probes answered in a row
	boundSince   time.Time

	// Read on the packet path without the lock.
	bound  atomic.Bool
	cur    atomic.Pointer[netip.AddrPort]
	stream atomic.Pointer[streamLink]
}

type streamLink struct {
	conn   StreamConn
	queue  chan []byte
	cancel context.CancelFunc
}

// SetRelay installs relay information received from the control server: a
// new ticket, and possibly a new relay.
func (t *Transport) SetRelay(info proto.RelayInfo) {
	r := &t.relay
	r.mu.Lock()
	host := ""
	if len(info.UDP) > 0 {
		host = info.UDP[0]
	}
	moved := host != r.host
	r.info, r.rejected = info, false
	if moved {
		r.host = host
		r.addr = netip.AddrPort{}
		r.cur.Store(nil)
		r.bound.Store(false)
		r.hasCookie = false
		r.resolvedAt = time.Time{}
		r.firstTry, r.lastTry = time.Time{}, time.Time{}
	}
	r.mu.Unlock()
	if moved {
		r.closeStream()
	}
	t.wake()
}

// resolve looks up the relay's address off the maintenance goroutine, since
// DNS can take seconds.
func (r *relayClient) resolve(hostPort string) {
	defer func() {
		r.mu.Lock()
		r.resolving = false
		r.mu.Unlock()
	}()
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return
	}
	if host == "" {
		host = r.t.cfg.ControlHost
	}
	p, err := net.LookupPort("udp", port)
	if err != nil || host == "" {
		return
	}
	var addr netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addr = ip.Unmap()
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		cancel()
		if err != nil {
			r.t.log.Warn("cannot resolve relay", "host", host, "err", err)
			return
		}
		// Prefer IPv4: it is what the reflexive address used for hole
		// punching is needed for.
		for _, ip := range ips {
			if ip = ip.Unmap(); ip.Is4() {
				addr = ip
				break
			}
		}
		if !addr.IsValid() && len(ips) > 0 && r.t.conn6 != nil {
			addr = ips[0].Unmap()
		}
	}
	if !addr.IsValid() {
		return
	}
	resolved := netip.AddrPortFrom(addr, uint16(p))

	r.mu.Lock()
	if r.host == hostPort {
		r.resolvedAt = time.Now()
		if r.addr != resolved {
			r.addr = resolved
			r.cur.Store(&resolved)
			r.bound.Store(false)
			r.hasCookie = false
			r.firstTry, r.lastTry = time.Time{}, time.Time{}
		}
	}
	r.mu.Unlock()
	r.t.wake()
}

// tick drives binding and keepalive. It is called from the maintenance loop.
func (r *relayClient) tick(now time.Time) {
	r.mu.Lock()
	if r.host == "" || len(r.info.Claims) != proto.ClaimsLen {
		r.mu.Unlock()
		return
	}
	if !r.resolving && (!r.addr.IsValid() || now.Sub(r.resolvedAt) > resolveEvery) {
		r.resolving = true
		r.resolvedAt = now // do not start another lookup while this one runs
		go r.resolve(r.host)
	}
	if !r.addr.IsValid() || r.rejected || now.Unix() >= r.info.ExpiresAt {
		if r.bound.Swap(false) {
			r.t.log.Warn("relay ticket expired; waiting for the server to issue a new one")
		}
		r.mu.Unlock()
		return
	}

	var frame []byte
	needStream := false
	canStream := r.info.WS != "" && r.t.cfg.DialStream != nil
	switch {
	case !r.bound.Load() && r.udpFailures > 0 && canStream && r.probeOK < probesNeeded &&
		(r.stream.Load() != nil || r.firstTry.IsZero() || now.Sub(r.firstTry) < streamGiveUp):
		// UDP has failed before and TCP is available: stay on TCP, and
		// only probe UDP once the hold is over.
		if r.firstTry.IsZero() {
			r.firstTry = now.Add(-streamAfter)
		}
		needStream = true
		if !now.Before(r.udpHoldUntil) && now.Sub(r.probeSentAt) >= probeEvery {
			if r.probeWaiting {
				r.probeOK = 0
			}
			r.probeTx, r.probeSentAt, r.probeWaiting = proto.NewTxID(), now, true
			frame = proto.AppendProbe(nil, r.probeTx)
		}
	case !r.bound.Load():
		if now.Sub(r.lastTry) >= bindRetry {
			if r.firstTry.IsZero() {
				r.firstTry = now
			}
			r.lastTry, r.tx = now, proto.NewTxID()
			frame = proto.AppendBindRequest(nil, r.tx, r.info.Claims)
		}
		needStream = !r.firstTry.IsZero() && now.Sub(r.firstTry) >= streamAfter
	case now.Sub(r.lastAck) >= bindLost:
		r.bound.Store(false)
		r.lastTry = time.Time{}
		r.firstTry = now.Add(-streamAfter) // go to TCP at once
		needStream = true
		r.udpFailures++
		hold := udpHoldFirst << min(r.udpFailures-1, 8)
		r.udpHoldUntil = now.Add(min(hold, udpHoldMax))
		r.probeOK, r.probeWaiting = 0, false
		r.t.log.Warn("relay stopped answering over UDP; using TCP", "udp_failures", r.udpFailures, "next_udp_try_in", min(hold, udpHoldMax).String())
	case now.Sub(r.lastTry) >= bindKeepalive:
		if r.udpFailures > 0 && now.Sub(r.boundSince) >= udpProven {
			r.udpFailures = 0
		}
		r.lastTry, r.tx = now, proto.NewTxID()
		frame = proto.AppendBindConfirm(nil, r.tx, r.info.Claims, r.cookie, r.info.Key)
	}
	addr := r.addr
	startStream := needStream && !r.dialing && r.stream.Load() == nil && r.info.WS != "" && r.t.cfg.DialStream != nil
	if startStream {
		r.dialing = true
	}
	r.mu.Unlock()

	if frame != nil {
		r.t.writeTo(frame, addr)
	}
	if startStream {
		r.t.wg.Add(1)
		go r.runStream(r.t.stop)
	}
}

// handle processes a bind reply from the relay.
func (r *relayClient) handle(frame []byte) {
	r.mu.Lock()
	var reply []byte
	changed := false
	switch frame[1] {
	case proto.FrameBindChallenge:
		if len(frame) == proto.BindChallengeLen && proto.FrameTxID(frame) == r.tx {
			copy(r.cookie[:], frame[proto.HeaderLen+proto.TxIDLen:])
			r.hasCookie = true
			reply = proto.AppendBindConfirm(nil, r.tx, r.info.Claims, r.cookie, r.info.Key)
		}

	case proto.FrameBindAck:
		// The ack is authenticated with the ticket key, so an off-path
		// attacker cannot forge one to plant a false public address.
		if len(frame) == proto.BindAckLen && proto.FrameTxID(frame) == r.tx && proto.VerifyMAC(frame, r.info.Key) {
			observed := proto.GetAddrPort(frame[proto.HeaderLen+proto.TxIDLen:])
			r.lastAck = time.Now()
			r.firstTry = time.Time{}
			if !r.bound.Swap(true) {
				r.boundSince = r.lastAck
				r.t.log.Info("bound to relay", "relay", r.addr.String(), "public", observed.String())
				changed = true
			}
			if observed != r.reflexive {
				r.reflexive, changed = observed, true
			}
		}

	case proto.FrameProbeReply:
		if len(frame) == proto.ProbeLen && r.probeWaiting && proto.FrameTxID(frame) == r.probeTx {
			r.probeWaiting = false
			r.probeOK++
		}

	case proto.FrameBindReject:
		if len(frame) == proto.BindRejectLen && proto.FrameTxID(frame) == r.tx {
			reason := frame[proto.BindRejectLen-1]
			r.bound.Store(false)
			if reason == proto.RejectBusy {
				// Capacity may free up: keep trying, slowly.
				r.lastTry = time.Now().Add(5 * time.Second)
			} else {
				r.rejected = true
			}
			r.t.log.Warn("relay refused the bind", "reason", reason)
		}

	case proto.FrameRelayUnbound:
		// The relay has no session for us any more (it restarted, or our
		// public address changed). Bind again right away.
		if r.bound.Swap(false) {
			r.firstTry, r.lastTry = time.Time{}, time.Time{}
			changed = true
		}
	}
	addr := r.addr
	r.mu.Unlock()

	if reply != nil {
		r.t.writeTo(reply, addr)
	}
	if changed {
		if r.bound.Load() {
			// UDP works: the TCP fallback is no longer needed.
			r.closeStream()
		}
		r.t.wake()
	}
}

// isRelay reports whether a datagram's source is the relay in use.
func (r *relayClient) isRelay(from netip.AddrPort) bool {
	cur := r.cur.Load()
	return cur != nil && *cur == from
}

// up reports whether packets can currently be relayed.
func (r *relayClient) up() bool { return r.bound.Load() || r.stream.Load() != nil }

// send transmits a complete relay frame, over UDP when bound and over the
// stream otherwise. It reports whether the frame was handed off.
func (r *relayClient) send(frame []byte) bool {
	if r.bound.Load() {
		if cur := r.cur.Load(); cur != nil {
			_, err := r.t.writeTo(frame, *cur)
			return err == nil
		}
	}
	if s := r.stream.Load(); s != nil {
		// On the stream a message is the frame without its two-byte header.
		msg := make([]byte, len(frame)-proto.HeaderLen)
		copy(msg, frame[proto.HeaderLen:])
		select {
		case s.queue <- msg:
			return true
		default:
		}
	}
	return false
}

// rebind forgets the current binding so the next tick starts a fresh one.
func (r *relayClient) rebind() {
	r.mu.Lock()
	r.bound.Store(false)
	r.hasCookie = false
	r.firstTry, r.lastTry = time.Time{}, time.Time{}
	// A different network: what UDP did on the old one says nothing.
	r.udpFailures, r.udpHoldUntil, r.probeOK, r.probeWaiting = 0, time.Time{}, 0, false
	r.mu.Unlock()
}

// publicAddr returns this client's address as last seen by the relay.
func (r *relayClient) publicAddr() netip.AddrPort {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.bound.Load() {
		return netip.AddrPort{}
	}
	return r.reflexive
}

func (r *relayClient) closeStream() {
	if s := r.stream.Swap(nil); s != nil {
		s.cancel()
		s.conn.Close()
	}
}

// runStream keeps a TCP-fallback connection to the relay for as long as UDP
// binding is not working.
func (r *relayClient) runStream(stop <-chan struct{}) {
	defer r.t.wg.Done()
	defer func() {
		r.mu.Lock()
		r.dialing = false
		r.mu.Unlock()
	}()
	backoff := 2 * time.Second
	for {
		if r.bound.Load() {
			return
		}
		r.mu.Lock()
		url, claims, key := r.info.WS, r.info.Claims, r.info.Key
		expired := time.Now().Unix() >= r.info.ExpiresAt
		r.mu.Unlock()
		if url == "" || expired {
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-stop:
				cancel()
			case <-ctx.Done():
			}
		}()
		dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
		conn, err := r.t.cfg.DialStream(dctx, url, proto.StreamAuthorization(claims, key))
		dcancel()
		if err == nil {
			link := &streamLink{conn: conn, queue: make(chan []byte, streamQueueLen), cancel: cancel}
			r.stream.Store(link)
			r.t.log.Info("UDP to the relay is not getting through; relaying over TCP instead")
			r.t.wake()
			r.serveStream(ctx, link)
			r.stream.CompareAndSwap(link, nil)
			conn.Close()
			backoff = 2 * time.Second
		}
		cancel()

		select {
		case <-stop:
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// serveStream pumps packets over an established stream until it fails.
func (r *relayClient) serveStream(ctx context.Context, link *streamLink) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer cancel()
		keep := time.NewTicker(streamKeep)
		defer keep.Stop()
		for {
			var msg []byte
			select {
			case <-ctx.Done():
				return
			case msg = <-link.queue:
			case <-keep.C:
				msg = []byte{} // empty message: keepalive
			}
			wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
			err := link.conn.Write(wctx, msg)
			wcancel()
			if err != nil {
				return
			}
		}
	}()

	for {
		msg, err := link.conn.Read(ctx)
		if err != nil {
			return
		}
		if len(msg) < proto.PeerIDLen {
			continue
		}
		if payload, p := r.t.handleRelayed(msg); p != nil {
			select {
			case r.t.streamIn <- streamPacket{p: p, data: payload}:
			default: // wireguard is not keeping up; drop like a full link would
			}
		}
	}
}
