package e2e

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"lanora/internal/client/engine"
	"lanora/internal/proto"
)

const password = "correct-horse-battery"

// TestDirectConnection is the basic scenario: two members join, find a
// direct path to each other and exchange data over it.
func TestDirectConnection(t *testing.T) {
	s := startServer(t, nil)
	room := s.room("LAN party", password, 8)

	a := s.client("alice", room.PublicID, password)
	b := s.client("bob", proto.FormatRoomID(room.PublicID), password) // the dashed form users type
	sa, sb := a.waitConnected(), b.waitConnected()
	if sa.Phase != engine.PhaseConnected || sb.Phase != engine.PhaseConnected {
		t.Fatalf("not connected: %q / %q", sa.Error, sb.Error)
	}
	// The two join concurrently, so which of them gets the first address is
	// not fixed; together they hold the first two.
	got := map[string]bool{sa.IP.String(): true, sb.IP.String(): true}
	if !got["10.214.0.1"] || !got["10.214.0.2"] || sa.Room.Subnet.String() != "10.214.0.0/24" {
		t.Fatalf("addresses %s, %s in %s", sa.IP, sb.IP, sa.Room.Subnet)
	}

	pa := a.waitPeer(b.ip(), proto.ViaDirect, 15*time.Second)
	pb := b.waitPeer(a.ip(), proto.ViaDirect, 15*time.Second)
	if pa.Nickname != "bob" || pb.Nickname != "alice" {
		t.Fatalf("nicknames %q, %q", pa.Nickname, pb.Nickname)
	}

	b.echoServer(7000)
	if err := a.exchange(b.ip(), 7000, 1<<20); err != nil {
		t.Fatal(err)
	}
	// Nothing went through the relay: both sides had a verified direct path
	// before any data was sent.
	if st := s.app.Relay.Stats(); st.Bytes > 64<<10 {
		t.Fatalf("%d bytes were relayed although a direct path was available", st.Bytes)
	}
}

// TestRelayFallback forces both members onto the relay and checks that the
// virtual network still works.
func TestRelayFallback(t *testing.T) {
	s := startServer(t, nil)
	room := s.room("relayed", password, 8)

	a := s.client("alice", room.PublicID, password, relayOnly)
	b := s.client("bob", room.PublicID, password, relayOnly)
	a.waitConnected()
	b.waitConnected()

	a.waitPeer(b.ip(), proto.ViaRelay, 15*time.Second)
	b.waitPeer(a.ip(), proto.ViaRelay, 15*time.Second)
	if st := a.wait("relay bound", 5*time.Second, func(s engine.State) bool { return s.Relay != "" }); st.Relay != "udp" {
		t.Fatalf("relay reached over %q, want udp", st.Relay)
	}

	b.echoServer(7000)
	if err := a.exchange(b.ip(), 7000, 256<<10); err != nil {
		t.Fatal(err)
	}
	st := s.app.Relay.Stats()
	if st.Bytes < 512<<10 || st.Sessions != 2 {
		t.Fatalf("relay stats after a relayed transfer: %+v", st)
	}
}

// TestMixedPaths has one member that only relays among members that connect
// directly, in a room of three.
func TestMixedPaths(t *testing.T) {
	s := startServer(t, nil)
	room := s.room("three", password, 8)

	a := s.client("alice", room.PublicID, password)
	b := s.client("bob", room.PublicID, password)
	c := s.client("carol", room.PublicID, password, relayOnly)
	for _, cl := range []*testClient{a, b, c} {
		cl.waitConnected()
	}
	a.waitPeer(b.ip(), proto.ViaDirect, 15*time.Second)
	a.waitPeer(c.ip(), proto.ViaRelay, 15*time.Second)
	c.waitPeer(a.ip(), proto.ViaRelay, 15*time.Second)
	c.waitPeer(b.ip(), proto.ViaRelay, 15*time.Second)

	for _, cl := range []*testClient{a, b, c} {
		cl.echoServer(7000)
	}
	for _, pair := range [][2]*testClient{{a, b}, {b, a}, {a, c}, {c, a}, {b, c}, {c, b}} {
		if err := pair[0].exchange(pair[1].ip(), 7000, 64<<10); err != nil {
			t.Fatalf("%s → %s: %v", pair[0].name, pair[1].name, err)
		}
	}
}

// TestStreamRelayFallback points the UDP relay somewhere that never answers,
// so clients must fall back to the relay's TCP transport.
func TestStreamRelayFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the UDP bind attempts to time out")
	}
	// A UDP port with nothing behind it.
	s := startServer(t, map[string]string{"LANORA_RELAY_PUBLIC": "127.0.0.1:9"})
	room := s.room("tcp only", password, 8)

	a := s.client("alice", room.PublicID, password, relayOnly)
	b := s.client("bob", room.PublicID, password, relayOnly)
	a.waitConnected()
	b.waitConnected()
	for _, cl := range []*testClient{a, b} {
		if st := cl.wait("stream relay", 20*time.Second, func(s engine.State) bool { return s.Relay != "" }); st.Relay != "tcp" {
			t.Fatalf("%s reaches the relay over %q, want tcp", cl.name, st.Relay)
		}
	}
	a.waitPeer(b.ip(), proto.ViaRelay, 20*time.Second)
	b.echoServer(7000)
	if err := a.exchange(b.ip(), 7000, 128<<10); err != nil {
		t.Fatal(err)
	}
}

// udpPacket builds an IPv4/UDP packet by hand.
func udpPacket(src, dst netip.Addr, sport, dport uint16, payload string) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = 64, 17
	s4, d4 := src.As4(), dst.As4()
	copy(p[12:16], s4[:])
	copy(p[16:20], d4[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

// TestBroadcastReachesEveryMember sends LAN discovery packets from one
// member's adapter and expects every other member's adapter to receive
// them byte for byte.
func TestBroadcastReachesEveryMember(t *testing.T) {
	s := startServer(t, nil)
	room := s.room("discovery", password, 8)

	var ta, tb, tc *chanTUN
	a := s.client("alice", room.PublicID, password, withRawAdapter(&ta))
	b := s.client("bob", room.PublicID, password, withRawAdapter(&tb), relayOnly)
	c := s.client("carol", room.PublicID, password, withRawAdapter(&tc))
	for _, cl := range []*testClient{a, b, c} {
		cl.waitConnected()
	}
	a.waitPeer(b.ip(), "", 15*time.Second)
	a.waitPeer(c.ip(), "", 15*time.Second)

	expect := func(who string, dev *chanTUN, want []byte) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case got := <-dev.toOS:
				if string(got) == string(want) {
					return
				}
			case <-deadline:
				t.Fatalf("%s's adapter never received the packet", who)
			}
		}
	}
	for _, dst := range []string{"255.255.255.255", "10.214.0.255", "224.0.2.60"} {
		pkt := udpPacket(a.ip(), netip.MustParseAddr(dst), 40000, 4445, "is anyone hosting a game? ("+dst+")")
		ta.fromOS <- pkt
		expect("bob", tb, pkt)
		expect("carol", tc, pkt)
	}

	// A unicast reply goes only to its destination.
	reply := udpPacket(b.ip(), a.ip(), 4445, 40000, "yes: join me")
	tb.fromOS <- reply
	expect("alice", ta, reply)
	select {
	case got := <-tc.toOS:
		if string(got) == string(reply) {
			t.Fatal("carol received a packet addressed to alice")
		}
	case <-time.After(300 * time.Millisecond):
	}
}

// TestRoomsAreSeparate checks that members of different rooms get different
// subnets and cannot reach each other, even through the relay.
func TestRoomsAreSeparate(t *testing.T) {
	s := startServer(t, nil)
	r1, r2 := s.room("one", password, 8), s.room("two", password, 8)

	a := s.client("alice", r1.PublicID, password)
	b := s.client("bob", r1.PublicID, password)
	x := s.client("mallory", r2.PublicID, password)
	sa := a.waitConnected()
	b.waitConnected()
	sx := x.waitConnected()
	if sa.Room.Subnet == sx.Room.Subnet {
		t.Fatalf("two rooms share the subnet %s", sa.Room.Subnet)
	}
	a.waitPeer(b.ip(), "", 15*time.Second)
	if len(x.eng.State().Peers) != 0 {
		t.Fatalf("a member of another room sees peers: %+v", x.eng.State().Peers)
	}

	a.echoServer(7000)
	if err := b.exchange(a.ip(), 7000, 4<<10); err != nil {
		t.Fatalf("same-room exchange failed: %v", err)
	}
	// From the other room the address is simply unreachable.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := x.stack().DialContextTCPAddrPort(ctx, netip.AddrPortFrom(a.ip(), 7000)); err == nil {
		conn.Close()
		t.Fatal("a member of another room connected to a member of this one")
	}
}

func TestJoinFailures(t *testing.T) {
	s := startServer(t, nil)
	room := s.room("small", password, 2)

	wrong := s.client("eve", room.PublicID, "not-the-password")
	st := wrong.waitStopped(15 * time.Second)
	if st.ErrorCode != proto.CodeInvalidCredentials {
		t.Fatalf("wrong password: code %q, message %q", st.ErrorCode, st.Error)
	}
	missing := s.client("eve", "ZZZZZZZZZ", password)
	st2 := missing.waitStopped(15 * time.Second)
	if st2.ErrorCode != proto.CodeInvalidCredentials || st2.Error != st.Error {
		t.Fatalf("an unknown room must fail exactly like a wrong password, got %q / %q", st2.ErrorCode, st2.Error)
	}
	malformed := s.client("eve", "nope", password)
	if st := malformed.waitStopped(15 * time.Second); st.ErrorCode != proto.CodeBadRequest {
		t.Fatalf("malformed room ID: %q", st.ErrorCode)
	}

	a := s.client("alice", room.PublicID, password)
	b := s.client("bob", room.PublicID, password)
	a.waitConnected()
	b.waitConnected()
	full := s.client("carol", room.PublicID, password)
	if st := full.waitStopped(15 * time.Second); st.ErrorCode != proto.CodeRoomFull {
		t.Fatalf("third member of a room for two: code %q, message %q", st.ErrorCode, st.Error)
	}
}

// TestAdminActions covers kicking, banning, disabling and changing the
// password of a room with members online.
func TestAdminActions(t *testing.T) {
	s := startServer(t, nil)
	room := s.room("moderated", password, 8)
	ctx := context.Background()

	a := s.client("alice", room.PublicID, password)
	b := s.client("bob", room.PublicID, password)
	a.waitConnected()
	b.waitConnected()
	a.waitPeer(b.ip(), "", 15*time.Second)
	bobIP := b.ip()

	members, err := s.app.Store.ListMembers(ctx, room.ID)
	if err != nil || len(members) != 2 {
		t.Fatalf("members: %v, %v", members, err)
	}
	bob := members[0]
	if bob.IP != bobIP {
		bob = members[1]
	}

	// Kick: bob is told why, alice sees him leave.
	if !s.app.Hub.Kick(room.ID, bob.ID, proto.CodeKicked, "Removed by an administrator.") {
		t.Fatal("kick did not find the session")
	}
	if st := b.waitStopped(10 * time.Second); st.ErrorCode != proto.CodeKicked || !strings.Contains(st.Error, "administrator") {
		t.Fatalf("kicked client stopped with %q: %q", st.ErrorCode, st.Error)
	}
	a.wait("bob gone", 10*time.Second, func(s engine.State) bool { return len(s.Peers) == 0 })

	// A kicked member may come back, and gets the same address.
	b2 := s.client("bob", room.PublicID, password, func(o *engine.Options) { o.Identity = b.eng.Identity() })
	if st := b2.waitConnected(); st.IP != bobIP {
		t.Fatalf("returning member got %s, had %s", st.IP, bobIP)
	}

	// Ban: he is disconnected and cannot rejoin.
	if _, err := s.app.Store.SetMemberBan(ctx, bob.ID, true, "cheating"); err != nil {
		t.Fatal(err)
	}
	s.app.Hub.Kick(room.ID, bob.ID, proto.CodeBanned, "You were banned from this room.")
	if st := b2.waitStopped(10 * time.Second); st.ErrorCode != proto.CodeBanned {
		t.Fatalf("banned client stopped with %q", st.ErrorCode)
	}
	b3 := s.client("bob", room.PublicID, password, func(o *engine.Options) { o.Identity = b.eng.Identity() })
	if st := b3.waitStopped(15 * time.Second); st.ErrorCode != proto.CodeBanned || !strings.Contains(st.Error, "cheating") {
		t.Fatalf("banned member rejoining: %q %q", st.ErrorCode, st.Error)
	}

	// Changing the password signs everyone out, and the old one stops working.
	hash, _ := s.hasher.Hash(ctx, "a-brand-new-password")
	if _, err := s.app.Store.SetRoomPassword(ctx, room.ID, hash); err != nil {
		t.Fatal(err)
	}
	s.app.Hub.CloseRoom(room.ID, proto.CodeInvalidCredentials, "The room password was changed.")
	if st := a.waitStopped(10 * time.Second); st.ErrorCode != proto.CodeInvalidCredentials {
		t.Fatalf("after a password change the client stopped with %q", st.ErrorCode)
	}
	old := s.client("alice", room.PublicID, password)
	if st := old.waitStopped(15 * time.Second); st.ErrorCode != proto.CodeInvalidCredentials {
		t.Fatalf("old password accepted: %q", st.ErrorCode)
	}
	fresh := s.client("alice", room.PublicID, "a-brand-new-password")
	if st := fresh.waitConnected(); st.Phase != engine.PhaseConnected {
		t.Fatalf("new password rejected: %q", st.Error)
	}

	// Disabling the room ends the session with that reason.
	enabled := false
	if _, err := s.app.Store.UpdateRoom(ctx, room.ID, storePatchEnabled(enabled)); err != nil {
		t.Fatal(err)
	}
	s.app.Hub.CloseRoom(room.ID, proto.CodeRoomDisabled, "This room was disabled.")
	if st := fresh.waitStopped(10 * time.Second); st.ErrorCode != proto.CodeRoomDisabled {
		t.Fatalf("disabled room: %q", st.ErrorCode)
	}
}

// TestSignallingLossKeepsPeersConnected drops every signalling session and
// checks that traffic between members continues while they reconnect.
func TestSignallingLossKeepsPeersConnected(t *testing.T) {
	s := startServer(t, nil)
	room := s.room("resilient", password, 8)

	a := s.client("alice", room.PublicID, password)
	b := s.client("bob", room.PublicID, password)
	a.waitConnected()
	b.waitConnected()
	a.waitPeer(b.ip(), proto.ViaDirect, 15*time.Second)
	b.echoServer(7000)

	// End both sessions the way a server restart would.
	n := s.app.Hub.DisconnectWhere(func(*hubSession) bool { return true }, proto.CodeUnavailable, "The server is restarting.")
	if n != 2 {
		t.Fatalf("%d sessions dropped", n)
	}
	a.wait("reconnecting", 10*time.Second, func(s engine.State) bool { return s.Phase == engine.PhaseReconnecting })

	// The members still reach each other while the server is "away".
	if err := a.exchange(b.ip(), 7000, 64<<10); err != nil {
		t.Fatalf("traffic stopped when signalling dropped: %v", err)
	}

	a.wait("reconnected", 20*time.Second, func(s engine.State) bool { return s.Phase == engine.PhaseConnected })
	b.wait("reconnected", 20*time.Second, func(s engine.State) bool { return s.Phase == engine.PhaseConnected })
	a.waitPeer(b.ip(), "", 15*time.Second)
	if err := a.exchange(b.ip(), 7000, 64<<10); err != nil {
		t.Fatalf("after reconnecting: %v", err)
	}
}

// TestPeerRestart checks that when a member leaves and returns with new
// keys, the others pick up the new session.
func TestPeerRestart(t *testing.T) {
	s := startServer(t, nil)
	room := s.room("restart", password, 8)

	a := s.client("alice", room.PublicID, password)
	b := s.client("bob", room.PublicID, password)
	a.waitConnected()
	b.waitConnected()
	a.waitPeer(b.ip(), "", 15*time.Second)
	ip := b.ip()

	b.close()
	a.wait("bob gone", 10*time.Second, func(s engine.State) bool { return len(s.Peers) == 0 })

	b2 := s.client("bob", room.PublicID, password, func(o *engine.Options) { o.Identity = b.eng.Identity() })
	if st := b2.waitConnected(); st.IP != ip {
		t.Fatalf("address changed across a restart: %s → %s", ip, st.IP)
	}
	a.waitPeer(ip, "", 15*time.Second)
	b2.echoServer(7000)
	if err := a.exchange(ip, 7000, 64<<10); err != nil {
		t.Fatal(err)
	}
}

func TestSelfSignedTLSWithPin(t *testing.T) {
	s := startServer(t, map[string]string{"LANORA_TLS": "selfsigned"})
	room := s.room("tls", password, 8)
	if s.addr.Pin == "" || s.addr.Base.Scheme != "https" {
		t.Fatalf("server address %s has no pin", s.addr)
	}

	a := s.client("alice", room.PublicID, password)
	b := s.client("bob", room.PublicID, password)
	if st := a.waitConnected(); st.Phase != engine.PhaseConnected {
		t.Fatalf("pinned connection failed: %q", st.Error)
	}
	b.waitConnected()
	a.waitPeer(b.ip(), "", 15*time.Second)

	// Without the pin, or with the wrong one, the client must refuse to talk
	// to the server at all rather than send it a password.
	noPin := s.addr
	noPin.Pin = ""
	c := s.client("carol", room.PublicID, password, func(o *engine.Options) { o.Server = noPin })
	if st := c.waitStopped(20 * time.Second); !strings.Contains(st.Error, "not trusted") {
		t.Fatalf("unpinned connection to a self-signed server: %q", st.Error)
	}
	wrongPin := s.addr
	wrongPin.Pin = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	d := s.client("dave", room.PublicID, password, func(o *engine.Options) { o.Server = wrongPin })
	if st := d.waitStopped(20 * time.Second); !strings.Contains(st.Error, "does not match the pin") {
		t.Fatalf("connection with the wrong pin: %q", st.Error)
	}
}

// freePort returns a port that is currently free for both TCP and UDP on
// loopback.
func freePort(t *testing.T) string {
	t.Helper()
	for i := 0; i < 20; i++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		tcp.Close()
		if err == nil {
			udp.Close()
			return fmt.Sprint(port)
		}
	}
	t.Fatal("no port free for both TCP and UDP")
	return ""
}

// TestServerRestartDoesNotInterruptMembers stops the server and starts a new
// one on the same address and database. The first client to reconnect is
// told the room is empty, because the others have not reconnected yet; it
// must not drop its working connections to them.
func TestServerRestartDoesNotInterruptMembers(t *testing.T) {
	port := freePort(t)
	env := map[string]string{
		"LANORA_DATA_DIR":     t.TempDir(),
		"LANORA_LISTEN":       "127.0.0.1:" + port,
		"LANORA_RELAY_LISTEN": "127.0.0.1:" + port,
	}
	s := startServer(t, env)
	room := s.room("survives restarts", password, 8)

	a := s.client("alice", room.PublicID, password)
	b := s.client("bob", room.PublicID, password)
	a.waitConnected()
	b.waitConnected()
	a.waitPeer(b.ip(), proto.ViaDirect, 15*time.Second)
	b.waitPeer(a.ip(), proto.ViaDirect, 15*time.Second)
	b.echoServer(7000)

	// Exchange data continuously for the whole restart, and watch that
	// neither client ever loses sight of the other.
	stop := make(chan struct{})
	problems := make(chan string, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := a.exchange(b.ip(), 7000, 2<<10); err != nil {
				select {
				case problems <- "data exchange failed: " + err.Error():
				default:
				}
			}
			for _, c := range []*testClient{a, b} {
				if n := len(c.eng.State().Peers); n != 1 {
					select {
					case problems <- fmt.Sprintf("%s sees %d peers", c.name, n):
					default:
					}
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	s.shutdown()
	a.wait("notice the server is gone", 15*time.Second, func(s engine.State) bool { return s.Phase == engine.PhaseReconnecting })
	b.wait("notice the server is gone", 15*time.Second, func(s engine.State) bool { return s.Phase == engine.PhaseReconnecting })

	startServer(t, env) // a new server process, same address, same database
	a.wait("reconnect", 60*time.Second, func(s engine.State) bool { return s.Phase == engine.PhaseConnected })
	b.wait("reconnect", 60*time.Second, func(s engine.State) bool { return s.Phase == engine.PhaseConnected })
	time.Sleep(2 * time.Second)
	close(stop)
	<-done

	close(problems)
	for p := range problems {
		t.Error(p)
	}
	// And the room is in order again on the new server.
	a.waitPeer(b.ip(), proto.ViaDirect, 10*time.Second)
}
