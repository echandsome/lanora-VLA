package relay

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"lanora/internal/proto"
)

var testSecret = []byte("relay test secret")

func startRelay(t *testing.T, opts Options) *Relay {
	t.Helper()
	opts.Secret = testSecret
	r := New(opts)
	if err := r.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return r
}

// testClient is a minimal relay client over a real UDP socket.
type testClient struct {
	t      *testing.T
	conn   *net.UDPConn
	relay  netip.AddrPort
	claims []byte
	key    []byte
	peer   proto.PeerID
}

func newClient(t *testing.T, r *Relay, room uint64, ip string, ttl time.Duration) *testClient {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	peer := proto.PeerIDOf(netip.MustParseAddr(ip))
	claims := proto.Claims{Room: room, Peer: peer, Expiry: time.Now().Add(ttl).Unix()}.Bytes()
	return &testClient{t: t, conn: conn, relay: r.Addr(), claims: claims, key: proto.RelaySessionKey(testSecret, claims), peer: peer}
}

func (c *testClient) send(b []byte) {
	c.t.Helper()
	if _, err := c.conn.WriteToUDPAddrPort(b, c.relay); err != nil {
		c.t.Fatal(err)
	}
}

// recv returns the next datagram, or nil if none arrives in time.
func (c *testClient) recv(wait time.Duration) []byte {
	buf := make([]byte, 2048)
	c.conn.SetReadDeadline(time.Now().Add(wait))
	n, _, err := c.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// bind runs the full bind exchange and returns the final reply frame.
func (c *testClient) bind() []byte {
	c.t.Helper()
	tx := proto.NewTxID()
	c.send(proto.AppendBindRequest(nil, tx, c.claims))
	ch := c.recv(time.Second)
	if len(ch) != proto.BindChallengeLen || ch[1] != proto.FrameBindChallenge || proto.FrameTxID(ch) != tx {
		c.t.Fatalf("expected a challenge, got % x", ch)
	}
	var cookie [proto.CookieLen]byte
	copy(cookie[:], ch[proto.HeaderLen+proto.TxIDLen:])
	c.send(proto.AppendBindConfirm(nil, tx, c.claims, cookie, c.key))
	return c.recv(time.Second)
}

func (c *testClient) mustBind() netip.AddrPort {
	c.t.Helper()
	ack := c.bind()
	if len(ack) != proto.BindAckLen || ack[1] != proto.FrameBindAck || !proto.VerifyMAC(ack, c.key) {
		c.t.Fatalf("expected an authenticated ack, got % x", ack)
	}
	return proto.GetAddrPort(ack[proto.HeaderLen+proto.TxIDLen:])
}

func (c *testClient) sendTo(dst *testClient, payload string) {
	c.send(append(proto.AppendRelaySend(nil, dst.peer), payload...))
}

// expectFrom asserts that the next datagram is payload relayed from src.
func (c *testClient) expectFrom(src *testClient, payload string) {
	c.t.Helper()
	got := c.recv(time.Second)
	if len(got) < proto.RelayHeaderLen || got[1] != proto.FrameRelayRecv {
		c.t.Fatalf("expected relayed data, got % x", got)
	}
	if proto.RelayPeer(got) != src.peer || string(got[proto.RelayHeaderLen:]) != payload {
		c.t.Fatalf("got %q from %v, want %q from %v", got[proto.RelayHeaderLen:], proto.RelayPeer(got).Addr(), payload, src.peer.Addr())
	}
}

func (c *testClient) expectNothing() {
	c.t.Helper()
	if got := c.recv(150 * time.Millisecond); got != nil {
		c.t.Fatalf("unexpected datagram % x", got)
	}
}

func TestBindAndForward(t *testing.T) {
	r := startRelay(t, Options{})
	a := newClient(t, r, 1, "10.77.0.1", time.Hour)
	b := newClient(t, r, 1, "10.77.0.2", time.Hour)

	// The ack reports the address the relay saw, which is what a client
	// advertises to peers for hole punching.
	if got, want := a.mustBind(), a.conn.LocalAddr().(*net.UDPAddr).AddrPort(); got != want {
		t.Fatalf("observed address %s, want %s", got, want)
	}
	b.mustBind()

	a.sendTo(b, "hello b")
	b.expectFrom(a, "hello b")
	b.sendTo(a, "hello a")
	a.expectFrom(b, "hello a")

	st := r.Stats()
	if st.Sessions != 2 || st.Packets != 2 || st.BindsAccepted != 2 {
		t.Fatalf("stats %+v", st)
	}
	if rx, tx, ok := r.Traffic(1, a.peer); !ok || rx == 0 || tx == 0 {
		t.Fatalf("traffic for a: %d/%d/%v", rx, tx, ok)
	}
}

func TestRoomsAreIsolated(t *testing.T) {
	r := startRelay(t, Options{})
	a := newClient(t, r, 1, "10.77.0.1", time.Hour)
	// Same virtual address, different room.
	other := newClient(t, r, 2, "10.77.0.2", time.Hour)
	a.mustBind()
	other.mustBind()

	a.sendTo(other, "leak?")
	other.expectNothing()
	if r.Stats().DroppedNoPeer != 1 {
		t.Fatalf("cross-room packet was not dropped: %+v", r.Stats())
	}
}

func TestUnboundSenderIsToldToRebind(t *testing.T) {
	r := startRelay(t, Options{})
	a := newClient(t, r, 1, "10.77.0.1", time.Hour)
	b := newClient(t, r, 1, "10.77.0.2", time.Hour)
	b.mustBind()

	a.sendTo(b, "not bound yet")
	got := a.recv(time.Second)
	if len(got) != proto.HeaderLen || got[1] != proto.FrameRelayUnbound {
		t.Fatalf("expected an unbound notice, got % x", got)
	}
	b.expectNothing()
}

func TestBindRejections(t *testing.T) {
	r := startRelay(t, Options{})

	expired := newClient(t, r, 1, "10.77.0.1", -time.Minute)
	if got := expired.bind(); len(got) != proto.BindRejectLen || got[1] != proto.FrameBindReject || got[len(got)-1] != proto.RejectExpired {
		t.Fatalf("expired ticket: % x", got)
	}

	forged := newClient(t, r, 1, "10.77.0.2", time.Hour)
	forged.key = proto.RelaySessionKey([]byte("not the relay secret"), forged.claims)
	if got := forged.bind(); len(got) != proto.BindRejectLen || got[len(got)-1] != proto.RejectInvalid {
		t.Fatalf("forged ticket: % x", got)
	}

	// Claims altered after issue (asking for someone else's address) fail
	// the MAC even with the original key.
	tampered := newClient(t, r, 1, "10.77.0.3", time.Hour)
	tampered.claims = proto.Claims{Room: 1, Peer: proto.PeerIDOf(netip.MustParseAddr("10.77.0.99")), Expiry: time.Now().Add(time.Hour).Unix()}.Bytes()
	if got := tampered.bind(); len(got) != proto.BindRejectLen || got[len(got)-1] != proto.RejectInvalid {
		t.Fatalf("tampered claims: % x", got)
	}

	if st := r.Stats(); st.Sessions != 0 || st.BindsRejected != 3 {
		t.Fatalf("stats %+v", st)
	}
}

func TestReplayedConfirmFromAnotherAddressIsRefused(t *testing.T) {
	r := startRelay(t, Options{})
	victim := newClient(t, r, 1, "10.77.0.1", time.Hour)
	peer := newClient(t, r, 1, "10.77.0.2", time.Hour)
	peer.mustBind()

	// Capture the victim's confirm, as an on-path observer could.
	tx := proto.NewTxID()
	victim.send(proto.AppendBindRequest(nil, tx, victim.claims))
	ch := victim.recv(time.Second)
	var cookie [proto.CookieLen]byte
	copy(cookie[:], ch[proto.HeaderLen+proto.TxIDLen:])
	confirm := proto.AppendBindConfirm(nil, tx, victim.claims, cookie, victim.key)
	victim.send(confirm)
	if ack := victim.recv(time.Second); len(ack) != proto.BindAckLen {
		t.Fatalf("victim bind failed: % x", ack)
	}

	// Replay it from a different socket. The cookie was minted for the
	// victim's address, so the relay must answer with a new challenge, not
	// move the session.
	attacker := newClient(t, r, 1, "10.77.0.1", time.Hour)
	attacker.send(confirm)
	if got := attacker.recv(time.Second); len(got) != proto.BindChallengeLen || got[1] != proto.FrameBindChallenge {
		t.Fatalf("replayed confirm produced % x", got)
	}
	// The attacker cannot complete the new challenge without the session key.
	// Traffic for the victim still reaches the victim.
	peer.sendTo(victim, "for the victim")
	victim.expectFrom(peer, "for the victim")
	attacker.expectNothing()
}

func TestRebindFromNewAddressMovesSession(t *testing.T) {
	r := startRelay(t, Options{})
	a := newClient(t, r, 1, "10.77.0.1", time.Hour)
	b := newClient(t, r, 1, "10.77.0.2", time.Hour)
	a.mustBind()
	b.mustBind()

	// The same member comes back from another socket (its NAT mapping or
	// network changed).
	a2 := newClient(t, r, 1, "10.77.0.1", time.Hour)
	a2.mustBind()

	b.sendTo(a2, "after move")
	a2.expectFrom(b, "after move")
	a.expectNothing()

	// The old address no longer speaks for the member.
	a.sendTo(b, "stale")
	if got := a.recv(time.Second); len(got) != proto.HeaderLen || got[1] != proto.FrameRelayUnbound {
		t.Fatalf("stale address was not unbound: % x", got)
	}
	if r.Stats().Sessions != 2 {
		t.Fatalf("sessions = %d", r.Stats().Sessions)
	}
}

func TestRevokeAndExpiry(t *testing.T) {
	r := startRelay(t, Options{IdleTimeout: time.Hour})
	// Tickets as the control server issues them, handed out a minute ago.
	issuedEarlier := TicketTTL - time.Minute
	a := newClient(t, r, 1, "10.77.0.1", issuedEarlier)
	b := newClient(t, r, 1, "10.77.0.2", issuedEarlier)
	c := newClient(t, r, 7, "10.77.7.1", issuedEarlier)
	a.mustBind()
	b.mustBind()
	c.mustBind()

	r.Revoke(1, b.peer)
	a.sendTo(b, "kicked")
	b.expectNothing()
	// The removed member's ticket is still within its lifetime, but it was
	// issued before the removal and must not bind again.
	if got := b.bind(); len(got) != proto.BindRejectLen || got[len(got)-1] != proto.RejectExpired {
		t.Fatalf("revoked ticket: % x", got)
	}
	// A ticket issued after the removal (the member was let back in) works.
	later := proto.Claims{Room: 1, Peer: b.peer, Expiry: time.Now().Add(TicketTTL + time.Minute).Unix()}.Bytes()
	b.claims, b.key = later, proto.RelaySessionKey(testSecret, later)
	b.mustBind()

	r.RevokeRoom(1)
	if r.Stats().Sessions != 1 {
		t.Fatalf("sessions after RevokeRoom = %d", r.Stats().Sessions)
	}
	if got := a.bind(); len(got) != proto.BindRejectLen || got[len(got)-1] != proto.RejectExpired {
		t.Fatalf("ticket of a closed room: % x", got)
	}

	// Sessions whose ticket has run out are swept.
	short := newClient(t, r, 7, "10.77.7.2", 2*time.Second)
	short.mustBind()
	r.sweep(time.Now().Add(3 * time.Second))
	if _, _, ok := r.Traffic(7, short.peer); ok {
		t.Fatal("expired session survived the sweep")
	}
	// Idle sessions too.
	r.sweep(time.Now().Add(2 * time.Hour))
	if r.Stats().Sessions != 0 {
		t.Fatalf("idle sessions survived: %d", r.Stats().Sessions)
	}
}

func TestSessionLimit(t *testing.T) {
	r := startRelay(t, Options{MaxSessions: 1})
	newClient(t, r, 1, "10.77.0.1", time.Hour).mustBind()
	if got := newClient(t, r, 1, "10.77.0.2", time.Hour).bind(); len(got) != proto.BindRejectLen || got[len(got)-1] != proto.RejectBusy {
		t.Fatalf("over-capacity bind: % x", got)
	}
}

func TestRateLimit(t *testing.T) {
	r := startRelay(t, Options{RateLimit: 1}) // effectively: the 64 KiB burst only
	a := newClient(t, r, 1, "10.77.0.1", time.Hour)
	b := newClient(t, r, 1, "10.77.0.2", time.Hour)
	a.mustBind()
	b.mustBind()

	payload := strings.Repeat("x", 1000)
	for i := 0; i < 100; i++ { // ~100 KB, more than the burst
		a.sendTo(b, payload)
	}
	received := 0
	for b.recv(200*time.Millisecond) != nil {
		received++
	}
	st := r.Stats()
	if received == 0 || received >= 100 || st.DroppedLimited == 0 {
		t.Fatalf("received %d of 100 with stats %+v", received, st)
	}

	r.SetRateLimit(0)
	a.sendTo(b, "unlimited again")
	b.expectFrom(a, "unlimited again")
}

func TestProbe(t *testing.T) {
	r := startRelay(t, Options{})
	c := newClient(t, r, 1, "10.77.0.1", time.Hour)
	tx := proto.NewTxID()
	c.send(proto.AppendProbe(nil, tx))
	got := c.recv(time.Second)
	if len(got) != proto.ProbeLen || got[1] != proto.FrameProbeReply || proto.FrameTxID(got) != tx {
		t.Fatalf("probe reply % x", got)
	}
	if addr := proto.GetAddrPort(got[proto.HeaderLen+proto.TxIDLen:]); addr != c.conn.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatalf("probe observed %s", addr)
	}
	// A truncated probe (which would make the reply larger than the request)
	// is ignored.
	c.send(proto.AppendProbe(nil, tx)[:proto.HeaderLen+proto.TxIDLen])
	c.expectNothing()
}

func TestGarbageIsIgnored(t *testing.T) {
	r := startRelay(t, Options{})
	c := newClient(t, r, 1, "10.77.0.1", time.Hour)
	for _, junk := range [][]byte{
		{}, {proto.Magic}, {0x01, 0x00, 0x00, 0x00}, // a WireGuard handshake prefix
		{proto.Magic, 0xEE, 1, 2, 3}, {proto.Magic, proto.FrameBindConfirm, 1, 2},
		bytes.Repeat([]byte{proto.Magic}, 1500),
	} {
		c.send(junk)
	}
	c.expectNothing()
	c.mustBind() // and the relay still works
}

// waitStream waits until the relay has a stream attached for a member.
func waitStream(t *testing.T, r *Relay, room uint64, peer proto.PeerID) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := r.byPeer.Load(peerKey{room, peer}); ok && v.(*session).stream.Load() != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the relay never attached the stream")
}

// dialStream connects a stream (WebSocket) relay client.
func dialStream(t *testing.T, url string, claims, key []byte) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {proto.StreamAuthorization(claims, key)}},
	})
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("stream dial: %v (HTTP %d)", err, status)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func TestStreamRelayBridgesToUDP(t *testing.T) {
	r := startRelay(t, Options{})
	srv := httptest.NewServer(r)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	udp := newClient(t, r, 1, "10.77.0.1", time.Hour)
	udp.mustBind()

	// A second member that can only use TCP.
	tcpPeer := proto.PeerIDOf(netip.MustParseAddr("10.77.0.2"))
	claims := proto.Claims{Room: 1, Peer: tcpPeer, Expiry: time.Now().Add(time.Hour).Unix()}.Bytes()
	ws := dialStream(t, url, claims, proto.RelaySessionKey(testSecret, claims))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	waitStream(t, r, 1, tcpPeer)

	// Stream → UDP.
	if err := ws.Write(ctx, websocket.MessageBinary, append(udp.peer[:], "from tcp"...)); err != nil {
		t.Fatal(err)
	}
	got := udp.recv(time.Second)
	if len(got) < proto.RelayHeaderLen || proto.RelayPeer(got) != tcpPeer || string(got[proto.RelayHeaderLen:]) != "from tcp" {
		t.Fatalf("udp side received % x", got)
	}

	// UDP → stream.
	udp.send(append(proto.AppendRelaySend(nil, tcpPeer), "from udp"...))
	typ, msg, err := ws.Read(ctx)
	if err != nil || typ != websocket.MessageBinary || !bytes.Equal(msg[:4], udp.peer[:]) || string(msg[4:]) != "from udp" {
		t.Fatalf("stream side received %v % x %v", typ, msg, err)
	}

	// Stream → stream.
	thirdPeer := proto.PeerIDOf(netip.MustParseAddr("10.77.0.3"))
	claims3 := proto.Claims{Room: 1, Peer: thirdPeer, Expiry: time.Now().Add(time.Hour).Unix()}.Bytes()
	ws3 := dialStream(t, url, claims3, proto.RelaySessionKey(testSecret, claims3))
	waitStream(t, r, 1, thirdPeer)
	if err := ws3.Write(ctx, websocket.MessageBinary, append(tcpPeer[:], "tcp to tcp"...)); err != nil {
		t.Fatal(err)
	}
	_, msg, err = ws.Read(ctx)
	if err != nil || !bytes.Equal(msg[:4], thirdPeer[:]) || string(msg[4:]) != "tcp to tcp" {
		t.Fatalf("stream-to-stream received % x %v", msg, err)
	}

	// Closing the stream removes the session.
	ws.Close(websocket.StatusNormalClosure, "")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, _, ok := r.Traffic(1, tcpPeer); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream session not removed after close")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A client that had a UDP binding and then falls back to the stream (its
// UDP stopped working) must receive over the stream, not at the address its
// dead UDP binding left behind.
func TestStreamTakesOverFromStaleUDPBinding(t *testing.T) {
	r := startRelay(t, Options{})
	srv := httptest.NewServer(r)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	sender := newClient(t, r, 1, "10.77.0.1", time.Hour)
	sender.mustBind()
	victim := newClient(t, r, 1, "10.77.0.2", time.Hour)
	victim.mustBind()

	// The same member now connects over the stream with the same ticket.
	ws := dialStream(t, url, victim.claims, victim.key)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The dial returns when the handshake is done, which can be a moment
	// before the relay has switched the member over to the stream.
	waitStream(t, r, 1, victim.peer)

	sender.sendTo(victim, "after fallback")
	_, msg, err := ws.Read(ctx)
	if err != nil || !bytes.Equal(msg[:4], sender.peer[:]) || string(msg[4:]) != "after fallback" {
		t.Fatalf("stream received % x, %v", msg, err)
	}
	victim.expectNothing()

	// When UDP works again the client binds again and UDP is preferred.
	victim.mustBind()
	sender.sendTo(victim, "udp is back")
	victim.expectFrom(sender, "udp is back")
}

func TestStreamRelayRejectsBadTickets(t *testing.T) {
	r := startRelay(t, Options{})
	srv := httptest.NewServer(r)
	defer srv.Close()

	claims := proto.Claims{Room: 1, Peer: proto.PeerIDOf(netip.MustParseAddr("10.77.0.2")), Expiry: time.Now().Add(time.Hour).Unix()}.Bytes()
	expired := proto.Claims{Room: 1, Peer: proto.PeerIDOf(netip.MustParseAddr("10.77.0.2")), Expiry: time.Now().Add(-time.Hour).Unix()}.Bytes()
	cases := map[string]string{
		"none":      "",
		"garbage":   "Bearer nonsense",
		"wrong key": proto.StreamAuthorization(claims, proto.RelaySessionKey([]byte("other"), claims)),
		"expired":   proto.StreamAuthorization(expired, proto.RelaySessionKey(testSecret, expired)),
	}
	for name, auth := range cases {
		req, _ := http.NewRequest("GET", srv.URL, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: HTTP %d, want 401", name, resp.StatusCode)
		}
	}
	if r.Stats().Sessions != 0 {
		t.Fatalf("a rejected stream bind created a session")
	}
}

func BenchmarkForward(b *testing.B) {
	r := New(Options{Secret: testSecret})
	if err := r.Listen("127.0.0.1:0"); err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	sink, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer sink.Close()

	srcAddr := netip.MustParseAddrPort("127.0.0.1:40000")
	now := time.Now().Unix()
	src := r.bind(proto.Claims{Room: 1, Peer: proto.PeerIDOf(netip.MustParseAddr("10.77.0.1")), Expiry: now + 3600}, now)
	r.attachAddr(src, srcAddr)
	dstPeer := proto.PeerIDOf(netip.MustParseAddr("10.77.0.2"))
	dst := r.bind(proto.Claims{Room: 1, Peer: dstPeer, Expiry: now + 3600}, now)
	r.attachAddr(dst, sink.LocalAddr().(*net.UDPAddr).AddrPort())

	frame := append(proto.AppendRelaySend(nil, dstPeer), make([]byte, 1200)...)
	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame[1] = proto.FrameRelaySend
		copy(frame[proto.HeaderLen:], dstPeer[:])
		r.forward(r.conns[0], frame, srcAddr)
	}
}
