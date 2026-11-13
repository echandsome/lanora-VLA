// Package transport carries a client's WireGuard packets to its peers.
//
// It plugs into wireguard-go as a conn.Bind. WireGuard sees every peer as
// one stable endpoint; behind that endpoint this package decides, packet by
// packet, how the peer is actually reached:
//
//   - directly, over a UDP path that both sides have verified with an
//     authenticated ping/pong (see disco frames in package proto), or
//   - through the room's relay, which is always tried first and stays
//     available as the fallback.
//
// Paths are probed continuously. A peer is moved onto a direct path as soon
// as one answers, onto a better one when it appears, and back to the relay
// the moment its direct path stops answering, so connectivity never depends
// on hole punching succeeding.
package transport

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"lanora/internal/proto"
)

// Signaler lets the transport ask the control connection to pass messages
// to peers. Calls must not block; a message that cannot be sent right now is
// simply dropped, and the transport tries again on its next round.
type Signaler interface {
	// PublishEndpoints announces the UDP addresses this client can be
	// reached at.
	PublishEndpoints(eps []netip.AddrPort)
	// RequestPunch asks a peer to start probing this client's addresses, so
	// that both sides open their NAT mappings at the same moment.
	RequestPunch(peer netip.Addr)
}

// Config configures a Transport.
type Config struct {
	Self     netip.Addr   // this client's virtual address
	Subnet   netip.Prefix // the room's virtual subnet
	DiscoKey *[32]byte    // private key for path discovery
	Signal   Signaler
	Logger   *slog.Logger
	// Port is the local UDP port to bind; zero picks a free one.
	Port uint16
	// ControlHost is the host of the control server, used when the relay
	// is advertised without one.
	ControlHost string
	// DialStream opens the TCP-fallback relay connection. It may be nil,
	// in which case only the UDP relay is used.
	DialStream StreamDialer
	// RelayOnly disables direct connections: no addresses are published or
	// probed and all traffic goes through the relay. It hides this client's
	// IP address from other room members at the cost of latency.
	RelayOnly bool
	// AllowLoopback permits loopback addresses as candidates. It exists for
	// tests that run several clients on one machine.
	AllowLoopback bool
}

const maxPacket = 2048

// Transport implements conn.Bind.
type Transport struct {
	cfg  Config
	log  *slog.Logger
	self proto.PeerID

	// Sockets. They exist only while the bind is open.
	mu     sync.Mutex
	conn4  *net.UDPConn
	conn6  *net.UDPConn
	port   uint16
	stop   chan struct{}
	wg     sync.WaitGroup
	isOpen atomic.Bool

	peersMu sync.RWMutex
	peers   map[proto.PeerID]*peer
	byAddr  sync.Map // netip.AddrPort → *peer: direct addresses we have heard a peer from

	relay relayClient

	// Packets arriving over the stream relay are handed to wireguard through
	// this queue.
	streamIn chan streamPacket

	localMu     sync.Mutex
	published   []netip.AddrPort
	rebind      chan struct{} // wakes the maintenance loop
	forceRebind atomic.Bool

	pool sync.Pool // *[]byte scratch buffers for framing

	rxBytes, txBytes atomic.Uint64
}

// New returns a transport that is not yet open. wireguard-go opens it when
// the device is brought up.
func New(cfg Config) *Transport {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	t := &Transport{
		cfg:      cfg,
		log:      cfg.Logger.With("component", "transport"),
		self:     proto.PeerIDOf(cfg.Self),
		peers:    make(map[proto.PeerID]*peer),
		streamIn: make(chan streamPacket, 512),
		rebind:   make(chan struct{}, 1),
	}
	t.pool.New = func() any { b := make([]byte, maxPacket); return &b }
	t.relay.t = t
	return t
}

// Open implements conn.Bind. It binds the UDP sockets and starts the
// background work that keeps paths alive.
func (t *Transport) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.isOpen.Load() {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if port == 0 {
		port = t.cfg.Port
	}
	conn4, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	actual := uint16(conn4.LocalAddr().(*net.UDPAddr).Port)
	// IPv6 is optional: without it peers are still reachable over IPv4.
	conn6, err := net.ListenUDP("udp6", &net.UDPAddr{Port: int(actual)})
	if err != nil {
		conn6 = nil
	}
	for _, c := range []*net.UDPConn{conn4, conn6} {
		if c != nil {
			c.SetReadBuffer(4 << 20)
			c.SetWriteBuffer(4 << 20)
		}
	}
	t.conn4, t.conn6, t.port = conn4, conn6, actual
	t.stop = make(chan struct{})
	t.isOpen.Store(true)

	fns := []conn.ReceiveFunc{t.receiveFunc(conn4), t.receiveStream}
	if conn6 != nil {
		fns = append(fns, t.receiveFunc(conn6))
	}
	t.wg.Add(1)
	go t.maintain(t.stop)
	return fns, actual, nil
}

// Close implements conn.Bind.
func (t *Transport) Close() error {
	t.mu.Lock()
	if !t.isOpen.Swap(false) {
		t.mu.Unlock()
		return nil
	}
	close(t.stop)
	err := t.conn4.Close()
	if t.conn6 != nil {
		t.conn6.Close()
	}
	t.mu.Unlock()

	t.relay.closeStream()
	t.wg.Wait()
	return err
}

// SetMark implements conn.Bind. Firewall marks are not used.
func (t *Transport) SetMark(uint32) error { return nil }

// BatchSize implements conn.Bind.
func (t *Transport) BatchSize() int { return 1 }

// Port returns the local UDP port, or zero while the transport is closed.
func (t *Transport) Port() uint16 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.isOpen.Load() {
		return 0
	}
	return t.port
}

// endpoint is the stable handle wireguard-go holds for a peer.
type endpoint struct{ p *peer }

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "" }
func (e *endpoint) DstToString() string { return e.p.ip.String() }
func (e *endpoint) DstIP() netip.Addr   { return e.p.ip }
func (e *endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *endpoint) DstToBytes() []byte {
	b := e.p.ip.As4()
	return append(b[:], 0, 0)
}

// addrEndpoint stands for a sender wireguard-go has not been told about: a
// packet arrived from an address no peer has been seen at. Peers'
// endpoints are pinned, so this only ever serves as the return address for
// a handshake cookie.
type addrEndpoint struct{ addr netip.AddrPort }

func (e *addrEndpoint) ClearSrc()           {}
func (e *addrEndpoint) SrcToString() string { return "" }
func (e *addrEndpoint) DstToString() string { return e.addr.String() }
func (e *addrEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *addrEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *addrEndpoint) DstToBytes() []byte {
	b, _ := e.addr.MarshalBinary()
	return b
}

// ParseEndpoint implements conn.Bind. The engine configures each WireGuard
// peer with its virtual address as the endpoint.
func (t *Transport) ParseEndpoint(s string) (conn.Endpoint, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || !ip.Is4() {
		return nil, errors.New("transport: endpoint must be a peer's virtual IPv4 address")
	}
	p := t.peer(proto.PeerIDOf(ip))
	if p == nil {
		return nil, errors.New("transport: unknown peer " + s)
	}
	return p.ep, nil
}

func (t *Transport) peer(id proto.PeerID) *peer {
	t.peersMu.RLock()
	p := t.peers[id]
	t.peersMu.RUnlock()
	return p
}

// Send implements conn.Bind: it transmits WireGuard packets to a peer over
// its current best path.
func (t *Transport) Send(bufs [][]byte, ep conn.Endpoint) error {
	if !t.isOpen.Load() {
		return net.ErrClosed
	}
	switch e := ep.(type) {
	case *endpoint:
		p := e.p
		now := time.Now().UnixNano()
		p.lastSend.Store(now)
		direct := p.best.Load()
		if direct != nil {
			for _, b := range bufs {
				if _, err := t.writeTo(b, *direct); err != nil {
					// The path is unusable right now (no route, interface
					// gone). Send this batch through the relay and let the
					// prober decide what to do with the path.
					direct = nil
					break
				}
				t.txBytes.Add(uint64(len(b)))
			}
		}
		// While a direct path is unconfirmed (a pong is overdue), packets
		// also go through the relay. WireGuard discards the duplicates, and
		// nothing is lost if the path turns out to be dead.
		if direct == nil || p.suspect.Load() {
			for _, b := range bufs {
				t.sendRelayed(p.id, b)
			}
		}
		return nil
	case *addrEndpoint:
		for _, b := range bufs {
			t.writeTo(b, e.addr)
		}
		return nil
	}
	return conn.ErrWrongEndpointType
}

// writeTo sends a datagram from the socket matching the address family.
func (t *Transport) writeTo(b []byte, addr netip.AddrPort) (int, error) {
	c := t.conn4
	if addr.Addr().Is6() {
		if c = t.conn6; c == nil {
			return 0, errors.New("transport: IPv6 is not available")
		}
	}
	return c.WriteToUDPAddrPort(b, addr)
}

// sendRelayed sends one payload to a peer through the relay.
func (t *Transport) sendRelayed(dst proto.PeerID, payload []byte) {
	if len(payload)+proto.RelayHeaderLen > maxPacket {
		return
	}
	bp := t.pool.Get().(*[]byte)
	frame := proto.AppendRelaySend((*bp)[:0], dst)
	frame = append(frame, payload...)
	if t.relay.send(frame) {
		t.txBytes.Add(uint64(len(payload)))
	}
	t.pool.Put(bp)
}

// receiveFunc returns the wireguard receive function for one UDP socket.
// Lanora frames are consumed here; only WireGuard packets are returned.
func (t *Transport) receiveFunc(c *net.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		buf := packets[0]
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				if !t.isOpen.Load() || errors.Is(err, net.ErrClosed) {
					return 0, net.ErrClosed
				}
				// Transient: for example an ICMP error for an earlier send
				// surfacing on the socket. Keep receiving.
				continue
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			if n >= proto.HeaderLen && buf[0] == proto.Magic {
				payload, p := t.handleFrame(buf[:n], from)
				if p == nil {
					continue
				}
				// A relayed WireGuard packet: move it to the front of the
				// buffer, where wireguard expects the packet to start.
				sizes[0] = copy(buf, payload)
				eps[0] = p.ep
				t.rxBytes.Add(uint64(sizes[0]))
				return 1, nil
			}
			sizes[0] = n
			t.rxBytes.Add(uint64(n))
			if v, ok := t.byAddr.Load(from); ok {
				p := v.(*peer)
				p.lastRecv.Store(time.Now().UnixNano())
				eps[0] = p.ep
			} else {
				eps[0] = &addrEndpoint{addr: from}
			}
			return 1, nil
		}
	}
}

// handleFrame processes one Lanora frame received over UDP. For relayed
// WireGuard data it returns the payload and the sending peer; every other
// frame is handled internally and (nil, nil) is returned.
func (t *Transport) handleFrame(frame []byte, from netip.AddrPort) ([]byte, *peer) {
	switch frame[1] {
	case proto.FrameDisco:
		t.handleDisco(frame, from, false)

	case proto.FrameRelayRecv:
		// Only the relay we are bound to may speak for other peers.
		if len(frame) < proto.RelayHeaderLen || !t.relay.isRelay(from) {
			return nil, nil
		}
		return t.handleRelayed(frame[proto.HeaderLen:])

	case proto.FrameBindChallenge, proto.FrameBindAck, proto.FrameBindReject, proto.FrameRelayUnbound:
		if t.relay.isRelay(from) {
			t.relay.handle(frame)
		}
	}
	return nil, nil
}

// handleRelayed processes a packet that came through the relay (over UDP or
// the stream): msg is the sender's ID followed by the payload.
func (t *Transport) handleRelayed(msg []byte) ([]byte, *peer) {
	var id proto.PeerID
	copy(id[:], msg)
	p := t.peer(id)
	if p == nil {
		return nil, nil
	}
	payload := msg[proto.PeerIDLen:]
	if proto.IsFrame(payload) {
		if payload[1] == proto.FrameDisco {
			t.handleDisco(payload, netip.AddrPort{}, true)
		}
		return nil, nil
	}
	p.lastRecv.Store(time.Now().UnixNano())
	return payload, p
}

type streamPacket struct {
	p    *peer
	data []byte
}

// receiveStream is the wireguard receive function for packets that arrive
// over the stream relay.
func (t *Transport) receiveStream(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	t.mu.Lock()
	stop := t.stop
	t.mu.Unlock()
	select {
	case <-stop:
		return 0, net.ErrClosed
	case pkt := <-t.streamIn:
		sizes[0] = copy(packets[0], pkt.data)
		eps[0] = pkt.p.ep
		t.rxBytes.Add(uint64(sizes[0]))
		return 1, nil
	}
}

// RelayStatus reports how the relay is currently reached ("udp", "tcp", or
// "" when it is not) and this client's public address as the relay sees it.
func (t *Transport) RelayStatus() (via string, public netip.AddrPort) {
	switch {
	case t.relay.bound.Load():
		return "udp", t.relay.publicAddr()
	case t.relay.stream.Load() != nil:
		return "tcp", netip.AddrPort{}
	}
	return "", netip.AddrPort{}
}

// Traffic returns the bytes of WireGuard traffic received and sent.
func (t *Transport) Traffic() (rx, tx uint64) { return t.rxBytes.Load(), t.txBytes.Load() }
