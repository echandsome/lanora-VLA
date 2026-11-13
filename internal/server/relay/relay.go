// Package relay forwards encrypted packets between room members that cannot
// reach each other directly.
//
// The relay never sees plaintext: everything it carries is already encrypted
// end to end by WireGuard. Its job is only to prove that a client is allowed
// to use it (see the bind exchange in package proto), remember where each
// member of a room can be reached, and move packets between members of the
// same room as cheaply as possible. The hot path does two lock-free map
// lookups, rewrites six header bytes in place and sends the same buffer on.
//
// A relay holds no durable state and needs only the secret it shares with
// the control server, so any number of relay nodes can run side by side.
package relay

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"lanora/internal/proto"
)

// Defaults for Options fields left zero.
const (
	DefaultMaxSessions = 200_000
	DefaultIdleTimeout = 50 * time.Second

	maxDatagram    = 2048
	socketBuffer   = 4 << 20
	cookieRotation = time.Minute
	// unboundPerSecond caps how many "you are not bound" notices are sent
	// per second in total, so stray or hostile traffic cannot make the relay
	// emit a reply for every packet it receives.
	unboundPerSecond = 2000
)

// Options configures a Relay.
type Options struct {
	// Secret is shared with the control server; ticket session keys are
	// derived from it.
	Secret []byte
	// MaxSessions bounds the number of bound clients.
	MaxSessions int
	// IdleTimeout is how long a session survives without a bind refresh.
	IdleTimeout time.Duration
	// RateLimit is the per-client forwarding budget in bytes per second;
	// zero means unlimited. It can be changed later with SetRateLimit.
	RateLimit int64
	// Sockets is the number of UDP sockets to share the port between (Linux
	// only); zero picks one per CPU up to eight.
	Sockets int
	Logger  *slog.Logger
}

// Stats is a snapshot of relay activity.
type Stats struct {
	Sessions       int    `json:"sessions"`
	Packets        uint64 `json:"packets"`
	Bytes          uint64 `json:"bytes"`
	DroppedNoPeer  uint64 `json:"dropped_no_peer"`
	DroppedUnbound uint64 `json:"dropped_unbound"`
	DroppedLimited uint64 `json:"dropped_limited"`
	DroppedQueue   uint64 `json:"dropped_queue"`
	BindsAccepted  uint64 `json:"binds_accepted"`
	BindsRejected  uint64 `json:"binds_rejected"`
}

type peerKey struct {
	room uint64
	peer proto.PeerID
}

// session is one bound client.
type session struct {
	key      peerKey
	addr     atomic.Pointer[netip.AddrPort] // nil while the client is not bound over UDP
	stream   atomic.Pointer[streamPeer]     // TCP fallback transport, if connected
	expiry   atomic.Int64                   // ticket expiry, Unix seconds
	lastSeen atomic.Int64                   // Unix seconds
	rx       atomic.Uint64                  // bytes received from this client
	tx       atomic.Uint64                  // bytes sent to this client
	limit    bucket
}

// Relay is a packet relay. Create one with New, then call Listen and Serve.
type Relay struct {
	opts  Options
	log   *slog.Logger
	conns []*net.UDPConn

	byAddr sync.Map // netip.AddrPort → *session
	byPeer sync.Map // peerKey → *session
	count  atomic.Int64

	// revoked records when a member's (or, with a zero peer, a whole
	// room's) relay access was withdrawn. Tickets issued before that moment
	// are refused even though they have not expired.
	revoked sync.Map // peerKey → int64 (Unix seconds)

	rate atomic.Int64 // bytes per second per session; 0 = unlimited
	now  atomic.Int64 // coarse clock, Unix seconds

	cookieMu sync.RWMutex
	cookie   [2][32]byte // current and previous cookie secrets

	unbound bucket

	packets, bytes                                  atomic.Uint64
	dropNoPeer, dropUnbound, dropLimited, dropQueue atomic.Uint64
	bindsOK, bindsBad                               atomic.Uint64

	closeOnce sync.Once
	closed    chan struct{}
}

// New returns a relay that is not yet listening.
func New(opts Options) *Relay {
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = DefaultMaxSessions
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	r := &Relay{opts: opts, log: opts.Logger.With("component", "relay"), closed: make(chan struct{})}
	r.rate.Store(opts.RateLimit)
	r.now.Store(time.Now().Unix())
	mustRandom(r.cookie[0][:])
	mustRandom(r.cookie[1][:])
	return r
}

func mustRandom(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("relay: system random source failed: " + err.Error())
	}
}

// Listen binds the relay's UDP port. On Linux several sockets share the
// port so that packet handling spreads across CPU cores.
func (r *Relay) Listen(addr string) error {
	n := r.opts.Sockets
	if n <= 0 {
		n = min(runtime.GOMAXPROCS(0), 8)
	}
	if !reusePortSupported {
		n = 1
	}
	lc := net.ListenConfig{Control: socketControl(n > 1)}
	for i := 0; i < n; i++ {
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			r.closeConns()
			return fmt.Errorf("relay: listen udp %s: %w", addr, err)
		}
		conn := pc.(*net.UDPConn)
		// Best effort: the kernel may clamp these to its configured maximum.
		conn.SetReadBuffer(socketBuffer)
		conn.SetWriteBuffer(socketBuffer)
		r.conns = append(r.conns, conn)
		if i == 0 {
			// Later sockets must bind the port the first one was given
			// (relevant when addr asks for an ephemeral port).
			addr = conn.LocalAddr().String()
		}
	}
	return nil
}

// Addr returns the UDP address the relay is listening on.
func (r *Relay) Addr() netip.AddrPort {
	if len(r.conns) == 0 {
		return netip.AddrPort{}
	}
	return r.conns[0].LocalAddr().(*net.UDPAddr).AddrPort()
}

// Serve runs the relay until ctx is cancelled.
func (r *Relay) Serve(ctx context.Context) error {
	if len(r.conns) == 0 {
		return errors.New("relay: Serve called before Listen")
	}
	var wg sync.WaitGroup
	for _, c := range r.conns {
		wg.Add(1)
		go func(c *net.UDPConn) {
			defer wg.Done()
			r.readLoop(c)
		}(c)
	}
	r.log.Info("relay listening", "addr", r.Addr().String(), "sockets", len(r.conns))

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastSweep, lastRotate := time.Now(), time.Now()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-r.closed:
			break loop
		case t := <-tick.C:
			r.now.Store(t.Unix())
			if t.Sub(lastSweep) >= 5*time.Second {
				lastSweep = t
				r.sweep(t)
			}
			if t.Sub(lastRotate) >= cookieRotation {
				lastRotate = t
				r.rotateCookie()
			}
		}
	}
	r.Close()
	wg.Wait()
	return nil
}

// Close stops the relay and disconnects every client.
func (r *Relay) Close() {
	r.closeOnce.Do(func() {
		close(r.closed)
		r.closeConns()
		r.byPeer.Range(func(_, v any) bool {
			if sp := v.(*session).stream.Load(); sp != nil {
				sp.close()
			}
			return true
		})
	})
}

func (r *Relay) closeConns() {
	for _, c := range r.conns {
		c.Close()
	}
}

// SetRateLimit changes the per-client forwarding budget (bytes per second,
// zero for unlimited).
func (r *Relay) SetRateLimit(bytesPerSecond int64) { r.rate.Store(max(bytesPerSecond, 0)) }

// Stats returns a snapshot of the relay's counters.
func (r *Relay) Stats() Stats {
	return Stats{
		Sessions:       int(r.count.Load()),
		Packets:        r.packets.Load(),
		Bytes:          r.bytes.Load(),
		DroppedNoPeer:  r.dropNoPeer.Load(),
		DroppedUnbound: r.dropUnbound.Load(),
		DroppedLimited: r.dropLimited.Load(),
		DroppedQueue:   r.dropQueue.Load(),
		BindsAccepted:  r.bindsOK.Load(),
		BindsRejected:  r.bindsBad.Load(),
	}
}

// Traffic returns the bytes received from and sent to one member, and
// whether that member currently has a relay session.
func (r *Relay) Traffic(room uint64, peer proto.PeerID) (rx, tx uint64, ok bool) {
	v, ok := r.byPeer.Load(peerKey{room, peer})
	if !ok {
		return 0, 0, false
	}
	s := v.(*session)
	return s.rx.Load(), s.tx.Load(), true
}

// Revoke ends a member's relay session and refuses the tickets it holds:
// the member was removed from the room. A ticket issued afterwards (the
// member was allowed back in) works normally.
func (r *Relay) Revoke(room uint64, peer proto.PeerID) {
	key := peerKey{room, peer}
	r.revoked.Store(key, time.Now().Unix())
	if v, ok := r.byPeer.Load(key); ok {
		r.remove(v.(*session))
	}
}

// ticketRevoked reports whether a ticket was issued before its holder's
// access was withdrawn. Tickets carry their expiry, and all are issued with
// the same lifetime, so the issue time follows from it.
func (r *Relay) ticketRevoked(c proto.Claims) bool {
	issued := c.Expiry - int64(TicketTTL/time.Second)
	for _, key := range [2]peerKey{{c.Room, c.Peer}, {c.Room, proto.PeerID{}}} {
		if at, ok := r.revoked.Load(key); ok && issued < at.(int64) {
			return true
		}
	}
	return false
}

// RevokeRoom ends every relay session of a room and refuses the tickets its
// members hold.
func (r *Relay) RevokeRoom(room uint64) {
	r.revoked.Store(peerKey{room, proto.PeerID{}}, time.Now().Unix())
	r.byPeer.Range(func(k, v any) bool {
		if k.(peerKey).room == room {
			r.remove(v.(*session))
		}
		return true
	})
}

func (r *Relay) remove(s *session) {
	if _, loaded := r.byPeer.LoadAndDelete(s.key); !loaded {
		return
	}
	r.count.Add(-1)
	if ap := s.addr.Swap(nil); ap != nil {
		r.byAddr.CompareAndDelete(*ap, s)
	}
	if sp := s.stream.Swap(nil); sp != nil {
		sp.close()
	}
}

// sweep drops sessions that stopped refreshing or whose ticket ran out.
func (r *Relay) sweep(now time.Time) {
	idle := now.Add(-r.opts.IdleTimeout).Unix()
	unix := now.Unix()
	// A revocation only matters while a ticket issued before it can still
	// be alive.
	forget := now.Add(-TicketTTL).Unix()
	r.revoked.Range(func(k, v any) bool {
		if v.(int64) < forget {
			r.revoked.Delete(k)
		}
		return true
	})
	r.byPeer.Range(func(_, v any) bool {
		s := v.(*session)
		if s.expiry.Load() <= unix {
			r.remove(s)
			return true
		}
		if s.lastSeen.Load() < idle {
			if s.stream.Load() != nil {
				// A stream-connected client is alive as long as its
				// connection is; only its stale UDP binding is dropped.
				if ap := s.addr.Swap(nil); ap != nil {
					r.byAddr.CompareAndDelete(*ap, s)
				}
			} else {
				r.remove(s)
			}
		}
		return true
	})
}

func (r *Relay) rotateCookie() {
	r.cookieMu.Lock()
	r.cookie[1] = r.cookie[0]
	mustRandom(r.cookie[0][:])
	r.cookieMu.Unlock()
}

// makeCookie binds a bind attempt to the address it came from.
func makeCookie(secret *[32]byte, addr netip.AddrPort, claims []byte) (out [proto.CookieLen]byte) {
	var a [proto.AddrLen]byte
	proto.PutAddrPort(a[:], addr)
	m := hmac.New(sha256.New, secret[:])
	m.Write(a[:])
	m.Write(claims)
	copy(out[:], m.Sum(nil))
	return out
}

func (r *Relay) currentCookie(addr netip.AddrPort, claims []byte) [proto.CookieLen]byte {
	r.cookieMu.RLock()
	defer r.cookieMu.RUnlock()
	return makeCookie(&r.cookie[0], addr, claims)
}

func (r *Relay) cookieValid(got []byte, addr netip.AddrPort, claims []byte) bool {
	r.cookieMu.RLock()
	defer r.cookieMu.RUnlock()
	for i := range r.cookie {
		want := makeCookie(&r.cookie[i], addr, claims)
		if hmac.Equal(got, want[:]) {
			return true
		}
	}
	return false
}

func (r *Relay) readLoop(conn *net.UDPConn) {
	buf := make([]byte, maxDatagram)
	scratch := make([]byte, 0, 128)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-r.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient errors (for example ICMP port-unreachable surfacing
			// on the socket) must not stop the relay.
			continue
		}
		if n < proto.HeaderLen || buf[0] != proto.Magic {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if buf[1] == proto.FrameRelaySend {
			r.forward(conn, buf[:n], from)
			continue
		}
		if reply := r.control(scratch[:0], buf[:n], from); len(reply) > 0 {
			conn.WriteToUDPAddrPort(reply, from)
		}
	}
}

// forward handles a data frame: the hot path.
func (r *Relay) forward(conn *net.UDPConn, frame []byte, from netip.AddrPort) {
	if len(frame) < proto.RelayHeaderLen {
		return
	}
	v, ok := r.byAddr.Load(from)
	if !ok {
		r.dropUnbound.Add(1)
		if r.unbound.allow(1, unboundPerSecond, unboundPerSecond, time.Now().UnixNano()) {
			conn.WriteToUDPAddrPort([]byte{proto.Magic, proto.FrameRelayUnbound}, from)
		}
		return
	}
	src := v.(*session)
	r.route(conn, src, frame)
}

// route delivers a relay frame from src to the peer named in its header.
// frame is modified in place.
func (r *Relay) route(conn *net.UDPConn, src *session, frame []byte) {
	// A client may burst up to one second's budget (never less than 64 KiB,
	// so a low limit still passes full-size packets).
	if rate := r.rate.Load(); rate > 0 && !src.limit.allow(len(frame), rate, max(rate, 64<<10), time.Now().UnixNano()) {
		r.dropLimited.Add(1)
		return
	}
	v, ok := r.byPeer.Load(peerKey{src.key.room, proto.RelayPeer(frame)})
	if !ok {
		r.dropNoPeer.Add(1)
		return
	}
	dst := v.(*session)
	src.rx.Add(uint64(len(frame)))

	// The frame goes out unchanged except for its type and the peer field,
	// which now names the sender instead of the destination.
	frame[1] = proto.FrameRelayRecv
	copy(frame[proto.HeaderLen:proto.RelayHeaderLen], src.key.peer[:])

	if ap := dst.addr.Load(); ap != nil {
		if _, err := conn.WriteToUDPAddrPort(frame, *ap); err != nil {
			return
		}
	} else if sp := dst.stream.Load(); sp != nil {
		if !sp.enqueue(frame[proto.HeaderLen:]) {
			r.dropQueue.Add(1)
			return
		}
	} else {
		r.dropNoPeer.Add(1)
		return
	}
	dst.tx.Add(uint64(len(frame)))
	r.packets.Add(1)
	r.bytes.Add(uint64(len(frame)))
}

// control handles bind and probe frames and returns the reply to send, if
// any, appended to out.
func (r *Relay) control(out, frame []byte, from netip.AddrPort) []byte {
	switch frame[1] {
	case proto.FrameProbe:
		if len(frame) < proto.ProbeLen {
			return nil
		}
		return proto.AppendProbeReply(out, proto.FrameTxID(frame), from)

	case proto.FrameBindRequest:
		if len(frame) < proto.BindRequestLen {
			return nil
		}
		claims := frame[proto.HeaderLen+proto.TxIDLen : proto.BindRequestLen]
		return proto.AppendBindChallenge(out, proto.FrameTxID(frame), r.currentCookie(from, claims))

	case proto.FrameBindConfirm:
		if len(frame) != proto.BindConfirmLen {
			return nil
		}
		tx := proto.FrameTxID(frame)
		off := proto.HeaderLen + proto.TxIDLen
		claimBytes := frame[off : off+proto.ClaimsLen]
		cookie := frame[off+proto.ClaimsLen : off+proto.ClaimsLen+proto.CookieLen]
		if !r.cookieValid(cookie, from, claimBytes) {
			// Stale cookie (rotated away, or the client's address changed):
			// hand out a fresh one and let the client confirm again.
			return proto.AppendBindChallenge(out, tx, r.currentCookie(from, claimBytes))
		}
		claims, err := proto.ParseClaims(claimBytes)
		if err != nil {
			return nil
		}
		now := time.Now().Unix()
		if claims.Expiry <= now {
			r.bindsBad.Add(1)
			return proto.AppendBindReject(out, tx, proto.RejectExpired)
		}
		key := proto.RelaySessionKey(r.opts.Secret, claimBytes)
		if !proto.VerifyMAC(frame, key) {
			r.bindsBad.Add(1)
			return proto.AppendBindReject(out, tx, proto.RejectInvalid)
		}
		if r.ticketRevoked(claims) {
			r.bindsBad.Add(1)
			return proto.AppendBindReject(out, tx, proto.RejectExpired)
		}
		s := r.bind(claims, now)
		if s == nil {
			r.bindsBad.Add(1)
			return proto.AppendBindReject(out, tx, proto.RejectBusy)
		}
		r.attachAddr(s, from)
		r.bindsOK.Add(1)
		return proto.AppendBindAck(out, tx, from, key)
	}
	return nil
}

// bind returns the session for a verified ticket, creating it if needed. It
// returns nil when the relay is full.
func (r *Relay) bind(claims proto.Claims, now int64) *session {
	key := peerKey{claims.Room, claims.Peer}
	if v, ok := r.byPeer.Load(key); ok {
		s := v.(*session)
		s.expiry.Store(claims.Expiry)
		s.lastSeen.Store(now)
		return s
	}
	if r.count.Load() >= int64(r.opts.MaxSessions) {
		return nil
	}
	s := &session{key: key}
	s.expiry.Store(claims.Expiry)
	s.lastSeen.Store(now)
	if v, loaded := r.byPeer.LoadOrStore(key, s); loaded {
		s = v.(*session)
		s.expiry.Store(claims.Expiry)
		s.lastSeen.Store(now)
		return s
	}
	r.count.Add(1)
	return s
}

// attachAddr records the UDP address a session is reachable at.
func (r *Relay) attachAddr(s *session, addr netip.AddrPort) {
	if old := s.addr.Load(); old != nil && *old == addr {
		return
	}
	// The address may still be mapped to another session (a client that
	// rejoined as a different member from the same socket).
	if v, ok := r.byAddr.Load(addr); ok {
		if other := v.(*session); other != s {
			if cur := other.addr.Load(); cur != nil && *cur == addr {
				other.addr.CompareAndSwap(cur, nil)
			}
		}
	}
	if old := s.addr.Swap(&addr); old != nil {
		r.byAddr.CompareAndDelete(*old, s)
	}
	r.byAddr.Store(addr, s)
}

// bucket is a small token bucket guarded by a mutex. A session's packets
// arrive on one flow, so the lock is effectively uncontended.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   int64
}

// allow takes n units from a bucket that holds at most burst units and is
// refilled at rate units per second. now is in Unix nanoseconds.
func (b *bucket) allow(n int, rate, burst, now int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	capacity := float64(burst)
	if b.last == 0 {
		b.tokens = capacity
	} else if elapsed := now - b.last; elapsed > 0 {
		b.tokens = min(capacity, b.tokens+float64(elapsed)/1e9*float64(rate))
	}
	b.last = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}
