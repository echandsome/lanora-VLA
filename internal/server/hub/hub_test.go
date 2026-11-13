package hub

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"lanora/internal/proto"
)

type fakeRelays struct {
	mu      sync.Mutex
	issued  int
	revoked []netip.Addr
	rooms   []int64
	ttl     time.Duration
}

func (f *fakeRelays) Ticket(room int64, peer netip.Addr) proto.RelayInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued++
	ttl := f.ttl
	if ttl == 0 {
		ttl = time.Hour
	}
	return proto.RelayInfo{UDP: []string{":8443"}, Claims: []byte{1}, Key: []byte{2}, ExpiresAt: time.Now().Add(ttl).Unix()}
}
func (f *fakeRelays) Revoke(_ int64, peer netip.Addr) {
	f.mu.Lock()
	f.revoked = append(f.revoked, peer)
	f.mu.Unlock()
}
func (f *fakeRelays) RevokeRoom(room int64) {
	f.mu.Lock()
	f.rooms = append(f.rooms, room)
	f.mu.Unlock()
}

var subnet = netip.MustParsePrefix("10.77.0.0/24")

func roomInfo(capacity int) proto.RoomInfo {
	return proto.RoomInfo{ID: "ABCDEFGHJ", Name: "test", Subnet: subnet, MTU: 1280, Capacity: capacity}
}

func join(t *testing.T, h *Hub, roomID int64, host int, capacity int) *Session {
	t.Helper()
	s, err := tryJoin(h, roomID, host, capacity)
	if err != nil {
		t.Fatalf("join host %d: %v", host, err)
	}
	return s
}

func tryJoin(h *Hub, roomID int64, host int, capacity int) (*Session, error) {
	ip := netip.AddrFrom4([4]byte{10, 77, 0, byte(host)})
	var wg, disco proto.Key32
	wg[0], disco[0] = byte(host), byte(host)+100
	return h.Join(JoinParams{
		RoomID: roomID, Room: roomInfo(capacity),
		Member: MemberInfo{ID: int64(host), IP: ip, Nickname: fmt.Sprintf("peer%d", host)},
		WGPub:  wg, DiscoPub: disco,
		Endpoints:  []netip.AddrPort{netip.MustParseAddrPort(fmt.Sprintf("198.51.100.%d:4000", host))},
		RemoteAddr: "203.0.113.1",
	})
}

// next returns the next queued message for a session, or fails.
func next(t *testing.T, s *Session) proto.Msg {
	t.Helper()
	select {
	case raw := <-s.Outbound():
		var m proto.Msg
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("bad message %s: %v", raw, err)
		}
		return m
	case <-time.After(time.Second):
		t.Fatal("no message queued")
		return proto.Msg{}
	}
}

func expectNone(t *testing.T, s *Session) {
	t.Helper()
	select {
	case raw := <-s.Outbound():
		t.Fatalf("unexpected message %s", raw)
	default:
	}
}

func TestJoinLeaveSignalling(t *testing.T) {
	relays := &fakeRelays{}
	var left []int64
	h := New(Options{Relays: relays, OnLeave: func(id int64) { left = append(left, id) }})

	a := join(t, h, 1, 1, 8)
	w := next(t, a)
	if w.T != proto.MsgWelcome || w.Self.IP.String() != "10.77.0.1" || len(w.Peers) != 0 || w.Relay == nil || w.Room.Subnet != subnet {
		t.Fatalf("first welcome: %+v", w)
	}

	b := join(t, h, 1, 2, 8)
	w = next(t, b)
	if len(w.Peers) != 1 || w.Peers[0].IP != a.Member.IP || w.Peers[0].WGPub != a.wgPub || len(w.Peers[0].Endpoints) != 1 {
		t.Fatalf("second welcome peers: %+v", w.Peers)
	}
	if m := next(t, a); m.T != proto.MsgPeerJoined || m.Peer.IP != b.Member.IP || m.Peer.DiscoPub != b.discoPub {
		t.Fatalf("a did not learn about b: %+v", m)
	}
	expectNone(t, b)

	if h.Online() != 2 || h.ActiveRooms() != 1 || !h.IsOnline(1, a.Member.IP) || h.IsOnline(1, netip.MustParseAddr("10.77.0.9")) {
		t.Fatalf("presence: online=%d rooms=%d", h.Online(), h.ActiveRooms())
	}

	h.Leave(b)
	h.Leave(b) // idempotent
	if m := next(t, a); m.T != proto.MsgPeerLeft || *m.IP != b.Member.IP {
		t.Fatalf("a did not learn b left: %+v", m)
	}
	h.Leave(a)
	if h.Online() != 0 || h.ActiveRooms() != 0 {
		t.Fatalf("after leaving: online=%d rooms=%d", h.Online(), h.ActiveRooms())
	}
	// An ordinary disconnect does not revoke relay access: the member may
	// only have lost its signalling connection.
	if len(left) != 2 || len(relays.revoked) != 0 {
		t.Fatalf("OnLeave calls %v, relay revocations %v", left, relays.revoked)
	}
}

func TestRoomsDoNotSeeEachOther(t *testing.T) {
	h := New(Options{Relays: &fakeRelays{}})
	a := join(t, h, 1, 1, 8)
	b := join(t, h, 2, 1, 8) // same address, another room
	if w := next(t, a); len(w.Peers) != 0 {
		t.Fatal("a sees peers")
	}
	if w := next(t, b); len(w.Peers) != 0 {
		t.Fatal("b sees a member of another room")
	}
	expectNone(t, a)

	// A punch aimed across rooms goes nowhere.
	target := b.Member.IP
	h.Handle(a, &proto.Msg{T: proto.MsgPunch, To: &target})
	expectNone(t, b)
	expectNone(t, a)
}

func TestCapacityAndReplacement(t *testing.T) {
	h := New(Options{Relays: &fakeRelays{}})
	a := join(t, h, 1, 1, 2)
	b := join(t, h, 1, 2, 2)
	if _, err := tryJoin(h, 1, 3, 2); err != ErrRoomFull {
		t.Fatalf("third member of a room of two: %v", err)
	}
	next(t, a) // welcome
	next(t, a) // b joined
	next(t, b) // welcome

	// The same member reconnecting replaces its old session even when the
	// room is full, and peers are told about the new keys.
	a2 := join(t, h, 1, 1, 2)
	select {
	case <-a.Done():
	default:
		t.Fatal("old session not ended")
	}
	if bye := a.Bye(); bye == nil || bye.Code != proto.CodeReplaced {
		t.Fatalf("old session bye: %+v", bye)
	}
	if m := next(t, b); m.T != proto.MsgPeerJoined || m.Peer.IP != a2.Member.IP {
		t.Fatalf("b not told about the replacement: %+v", m)
	}
	if h.Online() != 2 {
		t.Fatalf("online = %d after replacement", h.Online())
	}
	// The dead session's late Leave must not evict the live one.
	h.Leave(a)
	expectNone(t, b)
	if !h.IsOnline(1, a2.Member.IP) || h.Online() != 2 {
		t.Fatal("replacement was evicted by the old session's Leave")
	}
}

func TestEndpointsAndPunch(t *testing.T) {
	h := New(Options{Relays: &fakeRelays{}})
	a := join(t, h, 1, 1, 8)
	b := join(t, h, 1, 2, 8)
	next(t, a)
	next(t, a)
	next(t, b)

	eps := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.50:5000"),
		netip.MustParseAddrPort("192.168.1.20:5000"),
		netip.MustParseAddrPort("10.77.0.1:5000"),       // inside the room subnet: a routing loop
		netip.MustParseAddrPort("127.0.0.1:5000"),       // loopback
		netip.MustParseAddrPort("0.0.0.0:5000"),         // unspecified
		netip.MustParseAddrPort("224.0.0.1:5000"),       // multicast
		netip.MustParseAddrPort("203.0.113.50:0"),       // no port
		netip.MustParseAddrPort("203.0.113.50:5000"),    // duplicate
		netip.MustParseAddrPort("[::ffff:192.0.2.1]:7"), // mapped IPv4 is normalised
	}
	h.Handle(a, &proto.Msg{T: proto.MsgEndpoints, Endpoints: eps})
	m := next(t, b)
	if m.T != proto.MsgPeerUpdate || m.Peer.IP != a.Member.IP {
		t.Fatalf("update: %+v", m)
	}
	want := []string{"203.0.113.50:5000", "192.168.1.20:5000", "192.0.2.1:7"}
	if len(m.Peer.Endpoints) != len(want) {
		t.Fatalf("endpoints %v, want %v", m.Peer.Endpoints, want)
	}
	for i, w := range want {
		if m.Peer.Endpoints[i].String() != w {
			t.Fatalf("endpoint %d = %s, want %s", i, m.Peer.Endpoints[i], w)
		}
	}

	// Too many candidates are truncated.
	var many []netip.AddrPort
	for i := 0; i < 100; i++ {
		many = append(many, netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), uint16(1000+i)))
	}
	h.Handle(a, &proto.Msg{T: proto.MsgEndpoints, Endpoints: many})
	if m := next(t, b); len(m.Peer.Endpoints) != proto.MaxEndpoints {
		t.Fatalf("%d endpoints accepted", len(m.Peer.Endpoints))
	}

	to := b.Member.IP
	h.Handle(a, &proto.Msg{T: proto.MsgPunch, To: &to})
	p := next(t, b)
	if p.T != proto.MsgPunch || *p.From != a.Member.IP || len(p.Endpoints) != proto.MaxEndpoints {
		t.Fatalf("punch: %+v", p)
	}

	// One member cannot flood another: repeated punches at the same target
	// are dropped, and so are endpoint updates beyond a small burst.
	for i := 0; i < 5000; i++ {
		h.Handle(a, &proto.Msg{T: proto.MsgPunch, To: &to})
		h.Handle(a, &proto.Msg{T: proto.MsgEndpoints, Endpoints: eps})
	}
	if queued := len(b.out); queued > endpointBurst {
		t.Fatalf("%d messages queued for the flooded peer", queued)
	}
	select {
	case <-b.Done():
		t.Fatal("the flooded peer was disconnected")
	default:
	}
}

func TestAdvisoryMessagesNeverDisconnect(t *testing.T) {
	h := New(Options{Relays: &fakeRelays{}})
	target := join(t, h, 1, 1, 250)
	// Fill the target's queue past the advisory threshold with state
	// messages, then punch it from many peers.
	var peers []*Session
	for host := 2; host < 2+sendQueue/2+10; host++ {
		peers = append(peers, join(t, h, 1, host, 250))
	}
	before := len(target.out)
	to := target.Member.IP
	for _, p := range peers {
		h.Handle(p, &proto.Msg{T: proto.MsgPunch, To: &to})
	}
	if len(target.out) != before {
		t.Fatalf("advisory messages were queued on a busy session (%d → %d)", before, len(target.out))
	}
	select {
	case <-target.Done():
		t.Fatal("target disconnected")
	default:
	}
}

func TestKickCloseAndSlowClients(t *testing.T) {
	relays := &fakeRelays{}
	h := New(Options{Relays: relays})
	a := join(t, h, 1, 1, 8)
	b := join(t, h, 1, 2, 8)

	if !h.Kick(1, b.Member.ID, proto.CodeKicked, "bye") || h.Kick(1, 999, proto.CodeKicked, "") || h.Kick(9, 1, proto.CodeKicked, "") {
		t.Fatal("Kick return values")
	}
	if bye := b.Bye(); bye == nil || bye.Code != proto.CodeKicked || bye.Message != "bye" {
		t.Fatalf("kicked bye: %+v", bye)
	}
	if len(relays.revoked) != 1 || relays.revoked[0] != b.Member.IP {
		t.Fatalf("a kicked member's relay access was not revoked: %v", relays.revoked)
	}
	h.Leave(b)

	if n := h.CloseRoom(1, proto.CodeRoomClosed, "deleted"); n != 1 {
		t.Fatalf("CloseRoom ended %d sessions", n)
	}
	if bye := a.Bye(); bye == nil || bye.Code != proto.CodeRoomClosed {
		t.Fatalf("closed bye: %+v", bye)
	}
	if len(relays.rooms) != 1 {
		t.Fatal("room relay sessions not revoked")
	}
	h.Leave(a)

	// A client that never reads is disconnected instead of blocking others.
	slow := join(t, h, 3, 1, 250)
	for i := 0; i < sendQueue; i++ { // each round queues a join and a leave
		h.Leave(join(t, h, 3, 2, 250))
	}
	select {
	case <-slow.Done():
	default:
		t.Fatal("slow client was not dropped")
	}
	if slow.Bye() != nil {
		t.Fatal("a dropped slow client should not get a farewell")
	}
}

func TestTicketRenewalAndSnapshots(t *testing.T) {
	relays := &fakeRelays{ttl: 5 * time.Minute} // already inside the renewal window
	h := New(Options{Relays: relays})
	a := join(t, h, 1, 1, 8)
	next(t, a)

	h.RenewTickets(time.Now())
	if m := next(t, a); m.T != proto.MsgRelay || m.Relay == nil {
		t.Fatalf("no renewed ticket: %+v", m)
	}
	relays.ttl = time.Hour
	h.RenewTickets(time.Now())
	next(t, a) // the 5-minute ticket is renewed once more with a long one
	h.RenewTickets(time.Now())
	expectNone(t, a)

	h.Handle(a, &proto.Msg{T: proto.MsgStatus, Status: &proto.StatusReport{Peers: []proto.PeerStatus{{IP: a.Member.IP, Via: proto.ViaDirect, RTT: 12}}}})
	infos := h.Sessions(1)
	if len(infos) != 1 || infos[0].Status == nil || infos[0].Status.Peers[0].RTT != 12 || infos[0].Nickname != "peer1" {
		t.Fatalf("session info: %+v", infos)
	}
	if all := h.AllSessions(); len(all) != 1 {
		t.Fatalf("all sessions: %d", len(all))
	}
	if counts := h.OnlineCounts(); counts[1] != 1 {
		t.Fatalf("counts: %v", counts)
	}

	ch, cancel := h.Subscribe()
	defer cancel()
	join(t, h, 1, 2, 8)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("subscriber not notified of a join")
	}

	n := h.DisconnectWhere(func(s *Session) bool { return s.Member.IP == a.Member.IP }, proto.CodeBanned, "banned")
	if n != 1 || a.Bye() == nil || a.Bye().Code != proto.CodeBanned {
		t.Fatalf("DisconnectWhere ended %d", n)
	}

	h.Shutdown("restarting")
	if _, err := tryJoin(h, 1, 5, 8); err != ErrClosed {
		t.Fatalf("join after shutdown: %v", err)
	}
}

func TestConcurrentJoinLeave(t *testing.T) {
	h := New(Options{Relays: &fakeRelays{}})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s, err := tryJoin(h, int64(1+i%3), 1+g, 250)
				if err != nil {
					t.Errorf("join: %v", err)
					return
				}
				h.Handle(s, &proto.Msg{T: proto.MsgEndpoints, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:1")}})
				h.Leave(s)
			}
		}(g)
	}
	wg.Wait()
	if h.Online() != 0 || h.ActiveRooms() != 0 {
		t.Fatalf("leaked state: online=%d rooms=%d", h.Online(), h.ActiveRooms())
	}
}
