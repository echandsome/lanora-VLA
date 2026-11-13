package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"lanora/internal/proto"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "lanora.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func key(n byte) proto.Key32 {
	var k proto.Key32
	for i := range k {
		k[i] = n
	}
	return k
}

var pool = netip.MustParsePrefix("10.77.0.0/16")

func newRoom(t *testing.T, s *Store, name string) Room {
	t.Helper()
	r, err := s.CreateRoom(context.Background(), NewRoom{Name: name, PasswordHash: "h", Capacity: 16, Pool: pool})
	if err != nil {
		t.Fatalf("create room %s: %v", name, err)
	}
	return r
}

func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "lanora.db")
	for i := 0; i < 3; i++ {
		s, err := Open(ctx, path)
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		v, err := s.SchemaVersion(ctx)
		if err != nil || v != 1 {
			t.Fatalf("schema version = %d, %v", v, err)
		}
		if err := s.Ping(ctx); err != nil {
			t.Fatalf("ping: %v", err)
		}
		s.Close()
	}
}

func TestRoomSubnetAllocation(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	a, b := newRoom(t, s, "a"), newRoom(t, s, "b")
	if a.Subnet.String() != "10.77.0.0/24" || b.Subnet.String() != "10.77.1.0/24" {
		t.Fatalf("subnets %s, %s", a.Subnet, b.Subnet)
	}
	if a.PublicID == b.PublicID || len(a.PublicID) != proto.RoomIDLen {
		t.Fatalf("public IDs %q, %q", a.PublicID, b.PublicID)
	}

	// Deleting a room frees its subnet for reuse.
	if err := s.DeleteRoom(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if c := newRoom(t, s, "c"); c.Subnet != a.Subnet {
		t.Fatalf("freed subnet not reused: %s", c.Subnet)
	}

	// Explicit subnets are honoured and conflicts refused.
	want := netip.MustParsePrefix("10.200.5.0/24")
	d, err := s.CreateRoom(ctx, NewRoom{Name: "d", PasswordHash: "h", Capacity: 8, Pool: pool, Subnet: want})
	if err != nil || d.Subnet != want {
		t.Fatalf("explicit subnet: %v, %v", d.Subnet, err)
	}
	if _, err := s.CreateRoom(ctx, NewRoom{Name: "e", PasswordHash: "h", Capacity: 8, Pool: pool, Subnet: want}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate subnet: %v", err)
	}

	// A pool with a single /24 runs out.
	tiny := netip.MustParsePrefix("10.99.9.0/24")
	if _, err := s.CreateRoom(ctx, NewRoom{Name: "t1", PasswordHash: "h", Capacity: 8, Pool: tiny}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRoom(ctx, NewRoom{Name: "t2", PasswordHash: "h", Capacity: 8, Pool: tiny}); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("exhausted pool: %v", err)
	}
}

func TestValidatePool(t *testing.T) {
	for in, ok := range map[string]bool{
		"10.77.0.0/16": true, "10.0.0.0/8": true, "10.77.3.0/24": true,
		"10.77.0.1/16": false, "10.77.0.0/25": false, "0.0.0.0/0": false, "fd00::/48": false,
	} {
		if err := ValidatePool(netip.MustParsePrefix(in)); (err == nil) != ok {
			t.Errorf("ValidatePool(%s) = %v, want ok=%v", in, err, ok)
		}
	}
}

func TestRoomCRUD(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	r := newRoom(t, s, "LAN party")

	got, err := s.RoomByPublicID(ctx, r.PublicID)
	if err != nil || got.ID != r.ID || !got.Enabled || got.PasswordVersion != 1 {
		t.Fatalf("lookup: %+v, %v", got, err)
	}
	name, enabled, capacity := "Renamed", false, 32
	up, err := s.UpdateRoom(ctx, r.ID, RoomPatch{Name: &name, Enabled: &enabled, Capacity: &capacity})
	if err != nil || up.Name != name || up.Enabled || up.Capacity != 32 || up.Description != r.Description {
		t.Fatalf("update: %+v, %v", up, err)
	}
	pw, err := s.SetRoomPassword(ctx, r.ID, "h2")
	if err != nil || pw.PasswordHash != "h2" || pw.PasswordVersion != 2 {
		t.Fatalf("password: %+v, %v", pw, err)
	}
	bad := 999
	if _, err := s.UpdateRoom(ctx, r.ID, RoomPatch{Capacity: &bad}); err == nil {
		t.Fatalf("capacity above the schema limit was accepted")
	}
	if _, err := s.Room(ctx, 12345); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing room: %v", err)
	}

	newRoom(t, s, "100% legit_room")
	list, total, err := s.ListRooms(ctx, RoomFilter{Search: "100%"})
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("search with LIKE metacharacters: %d rooms, %v", total, err)
	}
	list, total, _ = s.ListRooms(ctx, RoomFilter{Search: proto.FormatRoomID(r.PublicID)})
	if total != 1 || list[0].ID != r.ID {
		t.Fatalf("search by formatted room ID found %d", total)
	}
}

func TestMemberLeases(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	r := newRoom(t, s, "room")
	admit := func(k proto.Key32, nick string) Member {
		t.Helper()
		m, _, err := s.AdmitMember(ctx, Admission{RoomID: r.ID, Subnet: r.Subnet, Identity: k, Nickname: nick, Addr: "198.51.100.1"})
		if err != nil {
			t.Fatalf("admit %s: %v", nick, err)
		}
		return m
	}

	a, b := admit(key(1), "a"), admit(key(2), "b")
	if a.IP.String() != "10.77.0.1" || b.IP.String() != "10.77.0.2" {
		t.Fatalf("leases %s, %s", a.IP, b.IP)
	}
	// A returning device keeps its address and picks up its new nickname.
	again, created, err := s.AdmitMember(ctx, Admission{RoomID: r.ID, Subnet: r.Subnet, Identity: key(1), Nickname: "a2"})
	if err != nil || created || again.ID != a.ID || again.IP != a.IP || again.Nickname != "a2" {
		t.Fatalf("re-admit: %+v created=%v err=%v", again, created, err)
	}
	// A released address is the next one handed out.
	if err := s.DeleteMember(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if c := admit(key(3), "c"); c.IP != a.IP {
		t.Fatalf("released address not reused: %s", c.IP)
	}
	// The same device in another room gets that room's addressing.
	r2 := newRoom(t, s, "room2")
	other, _, err := s.AdmitMember(ctx, Admission{RoomID: r2.ID, Subnet: r2.Subnet, Identity: key(2), Nickname: "b"})
	if err != nil || other.IP.String() != "10.77.1.1" {
		t.Fatalf("second room lease: %v, %v", other.IP, err)
	}

	// Banned members are returned as banned and not updated.
	if _, err := s.SetMemberBan(ctx, b.ID, true, "cheating"); err != nil {
		t.Fatal(err)
	}
	banned, _, err := s.AdmitMember(ctx, Admission{RoomID: r.ID, Subnet: r.Subnet, Identity: key(2), Nickname: "sneaky"})
	if err != nil || !banned.Banned || banned.Nickname != "b" || banned.BanReason != "cheating" {
		t.Fatalf("banned admit: %+v, %v", banned, err)
	}

	devs, total, err := s.ListDevices(ctx, DeviceFilter{})
	if err != nil || total != 2 || len(devs) != 2 {
		t.Fatalf("devices: %d, %v", total, err)
	}
	ms, err := s.DeviceMemberships(ctx, key(2))
	if err != nil || len(ms) != 2 || ms[0].RoomName == "" {
		t.Fatalf("memberships: %+v, %v", ms, err)
	}
}

func TestLeaseRecyclingWhenSubnetIsFull(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	r := newRoom(t, s, "full")

	online := map[netip.Addr]bool{}
	admit := func(i int) (Member, error) {
		var k proto.Key32
		k[0], k[1] = byte(i), byte(i>>8)
		m, _, err := s.AdmitMember(ctx, Admission{
			RoomID: r.ID, Subnet: r.Subnet, Identity: k, Nickname: fmt.Sprint(i),
			Online: func(ip netip.Addr) bool { return online[ip] },
		})
		return m, err
	}
	var first Member
	for i := 1; i <= 254; i++ {
		m, err := admit(i)
		if err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
		if i == 1 {
			first = m
		}
		online[m.IP] = true
	}
	// Everyone is online: nothing can be recycled.
	if _, err := admit(255); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("full room with everyone online: %v", err)
	}
	// The longest-absent member's lease goes to the newcomer.
	delete(online, first.IP)
	m, err := admit(255)
	if err != nil || m.IP != first.IP {
		t.Fatalf("recycled lease: %v, %v", m.IP, err)
	}
	if _, err := s.Member(ctx, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("evicted member still present: %v", err)
	}
}

func TestConcurrentAdmissionsGetDistinctAddresses(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	r := newRoom(t, s, "busy")

	const n = 60
	ips := make([]netip.Addr, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m, _, err := s.AdmitMember(ctx, Admission{RoomID: r.ID, Subnet: r.Subnet, Identity: key(byte(i + 1)), Nickname: "n"})
			if err != nil {
				t.Errorf("admit %d: %v", i, err)
				return
			}
			ips[i] = m.IP
		}(i)
	}
	wg.Wait()
	seen := map[netip.Addr]bool{}
	for _, ip := range ips {
		if seen[ip] {
			t.Fatalf("address %s leased twice", ip)
		}
		seen[ip] = true
	}
}

func TestAdminsAndSessions(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	a, err := s.CreateAdmin(ctx, "Jack", "hash", RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAdmin(ctx, "jack", "hash", RoleAdmin); !errors.Is(err, ErrConflict) {
		t.Fatalf("case-insensitive duplicate username: %v", err)
	}
	if got, err := s.AdminByUsername(ctx, "JACK"); err != nil || got.ID != a.ID {
		t.Fatalf("lookup by username: %v", err)
	}

	tok1, tok2 := []byte("token-hash-1"), []byte("token-hash-2")
	for _, tok := range [][]byte{tok1, tok2} {
		if err := s.CreateAdminSession(ctx, tok, a.ID, time.Hour, "127.0.0.1", "test"); err != nil {
			t.Fatal(err)
		}
	}
	sess, err := s.AdminSession(ctx, tok1)
	if err != nil || sess.Admin.Username != "Jack" || sess.Admin.LastLoginAt.IsZero() {
		t.Fatalf("session: %+v, %v", sess, err)
	}
	if err := s.DeleteAdminSessionsExcept(ctx, a.ID, tok1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdminSession(ctx, tok2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other session survived: %v", err)
	}

	// Expired sessions are invisible and purgeable.
	expired := []byte("expired")
	if err := s.CreateAdminSession(ctx, expired, a.ID, -time.Minute, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdminSession(ctx, expired); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session returned: %v", err)
	}
	if err := s.PurgeAdminSessions(ctx); err != nil {
		t.Fatal(err)
	}

	// Changing the password signs every session out.
	hash := "new"
	if _, err := s.UpdateAdmin(ctx, a.ID, AdminPatch{PasswordHash: &hash}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdminSession(ctx, tok1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session survived a password change: %v", err)
	}
	if n, _ := s.CountActiveOwners(ctx); n != 1 {
		t.Fatalf("active owners = %d", n)
	}
}

func TestEventsAndSettings(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	base := time.Now().Add(-time.Hour)
	var batch []Event
	for i := 0; i < 50; i++ {
		kind, level := "room.join", LevelInfo
		if i%10 == 0 {
			kind, level = "auth.fail", LevelWarn
		}
		batch = append(batch, Event{Time: base.Add(time.Duration(i) * time.Second), Level: level, Kind: kind,
			RoomID: int64(1 + i%2), Actor: "tester", Message: fmt.Sprintf("event %d", i)})
	}
	if err := s.InsertEvents(ctx, batch); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListEvents(ctx, EventFilter{Limit: 20})
	if err != nil || len(page) != 20 || page[0].Message != "event 49" {
		t.Fatalf("first page: %d events, %v", len(page), err)
	}
	next, _ := s.ListEvents(ctx, EventFilter{Limit: 20, BeforeID: page[len(page)-1].ID})
	if len(next) != 20 || next[0].Message != "event 29" {
		t.Fatalf("second page starts at %q", next[0].Message)
	}
	if warn, _ := s.ListEvents(ctx, EventFilter{Level: LevelWarn}); len(warn) != 5 {
		t.Fatalf("warn events = %d", len(warn))
	}
	if auth, _ := s.ListEvents(ctx, EventFilter{Kind: "auth."}); len(auth) != 5 {
		t.Fatalf("auth.* events = %d", len(auth))
	}
	if room, _ := s.ListEvents(ctx, EventFilter{RoomID: 2, Limit: 500}); len(room) != 25 {
		t.Fatalf("room 2 events = %d", len(room))
	}
	removed, err := s.PurgeEvents(ctx, base.Add(10*time.Second), 30)
	if err != nil || removed != 20 {
		t.Fatalf("purge removed %d, %v", removed, err)
	}

	if _, ok, _ := s.Setting(ctx, "missing"); ok {
		t.Fatal("missing setting reported as set")
	}
	calls := 0
	gen := func() string { calls++; return "generated" }
	for i := 0; i < 3; i++ {
		v, err := s.SettingOrInit(ctx, "secret", gen)
		if err != nil || v != "generated" {
			t.Fatalf("SettingOrInit: %q, %v", v, err)
		}
	}
	if calls != 1 {
		t.Fatalf("initialiser ran %d times", calls)
	}
	if err := s.SetSettings(ctx, map[string]string{"a": "1", "secret": "changed"}); err != nil {
		t.Fatal(err)
	}
	all, _ := s.Settings(ctx)
	if all["a"] != "1" || all["secret"] != "changed" {
		t.Fatalf("settings: %v", all)
	}
}

func TestBans(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	for _, c := range []struct{ kind, in, want string }{
		{BanIP, "203.0.113.7", "203.0.113.7/32"},
		{BanIP, "203.0.113.77/24", "203.0.113.0/24"},
		{BanIP, "::ffff:203.0.113.7", "203.0.113.7/32"},
		{BanIdentity, key(9).String(), key(9).Hex()},
		{BanIdentity, key(9).Hex(), key(9).Hex()},
	} {
		got, err := NormalizeBan(c.kind, c.in)
		if err != nil || got != c.want {
			t.Errorf("NormalizeBan(%s, %s) = %q, %v", c.kind, c.in, got, err)
		}
	}
	if _, err := NormalizeBan(BanIP, "not-an-ip"); err == nil {
		t.Error("invalid address accepted")
	}
	b, err := s.AddBan(ctx, BanIP, "203.0.113.0/24", "abuse", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddBan(ctx, BanIP, "203.0.113.0/24", "again", 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate ban: %v", err)
	}
	if list, _ := s.ListBans(ctx); len(list) != 1 || list[0].ID != b.ID {
		t.Fatalf("bans: %+v", list)
	}
	if err := s.RemoveBan(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveBan(ctx, b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second removal: %v", err)
	}
}

// Session tokens, relay tickets and log entries name rooms, members and
// administrators by id, so an id must never come to mean something else.
// SQLite reuses the id of the newest row once it is deleted unless the
// column is AUTOINCREMENT.
func TestIDsAreNeverReused(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	room := newRoom(t, s, "first")
	member, _, err := s.AdmitMember(ctx, Admission{RoomID: room.ID, Subnet: room.Subnet, Identity: key(1), Nickname: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRoom(ctx, room.ID); err != nil {
		t.Fatal(err)
	}
	next := newRoom(t, s, "second")
	if next.ID == room.ID {
		t.Errorf("the new room took the deleted room's id %d", room.ID)
	}
	if next.Subnet != room.Subnet {
		t.Errorf("the freed subnet %s was not reused (got %s)", room.Subnet, next.Subnet)
	}
	successor, _, err := s.AdmitMember(ctx, Admission{RoomID: next.ID, Subnet: next.Subnet, Identity: key(2), Nickname: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if successor.ID == member.ID {
		t.Errorf("the new member took the deleted member's id %d", member.ID)
	}

	// The same when a single membership is removed and another created.
	if err := s.DeleteMember(ctx, successor.ID); err != nil {
		t.Fatal(err)
	}
	third, _, err := s.AdmitMember(ctx, Admission{RoomID: next.ID, Subnet: next.Subnet, Identity: key(3), Nickname: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if third.ID == successor.ID {
		t.Errorf("the new member took the removed member's id %d", successor.ID)
	}

	admin, err := s.CreateAdmin(ctx, "temp", "h", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAdmin(ctx, admin.ID); err != nil {
		t.Fatal(err)
	}
	again, err := s.CreateAdmin(ctx, "temp2", "h", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID == admin.ID {
		t.Errorf("the new administrator took the deleted one's id %d", admin.ID)
	}

	ban, err := s.AddBan(ctx, "ip", "203.0.113.7", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveBan(ctx, ban.ID); err != nil {
		t.Fatal(err)
	}
	ban2, err := s.AddBan(ctx, "ip", "203.0.113.8", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if ban2.ID == ban.ID {
		t.Errorf("the new ban took the lifted ban's id %d", ban.ID)
	}
}
