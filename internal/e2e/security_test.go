package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"lanora/internal/client/control"
	"lanora/internal/proto"
	"lanora/internal/server/auth"
	"lanora/internal/server/store"
)

// apiClient makes JSON requests to a test server and keeps cookies, as a
// browser would.
type apiClient struct {
	t    *testing.T
	base string
	http *http.Client
}

func (s *testServer) api() *apiClient {
	jar, _ := cookiejar.New(nil)
	return &apiClient{t: s.t, base: s.addr.Base.String(), http: &http.Client{Jar: jar, Timeout: 15 * time.Second}}
}

// do returns the status and the decoded JSON body.
func (c *apiClient) do(method, path string, body any, headers ...string) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func errorCode(body map[string]any) string {
	e, _ := body["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

func (c *apiClient) login(user, password string) int {
	status, _ := c.do("POST", "/api/admin/login", map[string]string{"username": user, "password": password})
	return status
}

func (c *apiClient) mustLogin(user, password string) {
	c.t.Helper()
	if status := c.login(user, password); status != http.StatusOK {
		c.t.Fatalf("login as %s: HTTP %d", user, status)
	}
}

const adminPassword = "test-admin-password"

func TestAdminAuthentication(t *testing.T) {
	s := startServer(t, nil)

	// Nothing under /api/admin answers without a session.
	anon := s.api()
	for _, path := range []string{"/api/admin/me", "/api/admin/rooms", "/api/admin/overview", "/api/admin/settings", "/api/admin/events", "/api/admin/admins"} {
		if status, body := anon.do("GET", path, nil); status != http.StatusUnauthorized || errorCode(body) != "unauthorized" {
			t.Errorf("GET %s without a session: HTTP %d %v", path, status, body)
		}
	}
	if status, _ := anon.do("POST", "/api/admin/rooms", map[string]any{"name": "x"}); status != http.StatusUnauthorized {
		t.Errorf("creating a room without a session: HTTP %d", status)
	}

	// The session cookie is not readable by scripts and never sent on
	// requests from other sites.
	c := s.api()
	resp, err := c.http.Post(c.base+"/api/admin/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"`+adminPassword+`"}`))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	var cookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == "lanora_admin" {
			cookie = ck
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/api/admin" || len(cookie.Value) < 40 {
		t.Fatalf("session cookie: %+v", cookie)
	}
	if status, body := c.do("GET", "/api/admin/me", nil); status != http.StatusOK || body["admin"].(map[string]any)["role"] != "owner" {
		t.Fatalf("me: HTTP %d %v", status, body)
	}

	// A request another site makes the browser send is refused even though
	// the cookie comes along.
	for _, hdr := range [][]string{
		{"Sec-Fetch-Site", "cross-site"},
		{"Origin", "https://evil.example"},
	} {
		if status, _ := c.do("POST", "/api/admin/rooms", map[string]any{"name": "forged"}, hdr...); status != http.StatusForbidden {
			t.Errorf("cross-origin request with %s: HTTP %d, want 403", hdr[0], status)
		}
	}
	if list, _ := c.do("GET", "/api/admin/rooms", nil); list != http.StatusOK {
		t.Fatal("rooms list failed")
	}
	if _, body := c.do("GET", "/api/admin/rooms", nil); body["total"].(float64) != 0 {
		t.Fatal("a forged request created a room")
	}

	// Signing out ends the session on the server, not just in the browser.
	stolen := cookie.Value
	if status, _ := c.do("POST", "/api/admin/logout", nil); status != http.StatusOK {
		t.Fatal("logout failed")
	}
	if status, _ := s.api().do("GET", "/api/admin/me", nil, "Cookie", "lanora_admin="+stolen); status != http.StatusUnauthorized {
		t.Fatalf("a signed-out session still works: HTTP %d", status)
	}

	// The security headers are on every response.
	page, err := http.Get(c.base + "/")
	if err != nil {
		t.Fatal(err)
	}
	page.Body.Close()
	if csp := page.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy: %q", csp)
	}
	if page.Header.Get("X-Content-Type-Options") != "nosniff" || page.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing hardening headers: %v", page.Header)
	}
}

func TestAdminLoginLockout(t *testing.T) {
	s := startServer(t, nil)
	c := s.api()
	for i := 0; i < 4; i++ {
		if status := c.login("admin", "wrong-password-"+fmt.Sprint(i)); status != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: HTTP %d", i, status)
		}
	}
	// An unknown user fails the same way as a wrong password.
	if status, body := c.do("POST", "/api/admin/login", map[string]string{"username": "nobody", "password": "whatever-it-is"}); status != http.StatusUnauthorized || errorCode(body) != "invalid_credentials" {
		t.Fatalf("unknown user: HTTP %d %v", status, body)
	}
	// Five failures from one address: locked out, even with the right
	// password.
	status, body := c.do("POST", "/api/admin/login", map[string]string{"username": "admin", "password": adminPassword})
	if status != http.StatusTooManyRequests || errorCode(body) != "rate_limited" {
		t.Fatalf("after five failures the correct password gave HTTP %d %v", status, body)
	}
	if retry := body["error"].(map[string]any)["retry_after"].(float64); retry < 1 || retry > 60 {
		t.Fatalf("retry_after = %v", retry)
	}
}

func TestAdminRoles(t *testing.T) {
	s := startServer(t, nil)
	owner := s.api()
	owner.mustLogin("admin", adminPassword)

	create := func(user, role string) {
		t.Helper()
		status, body := owner.do("POST", "/api/admin/admins", map[string]string{"username": user, "password": "a-long-enough-password", "role": role})
		if status != http.StatusCreated {
			t.Fatalf("create %s: HTTP %d %v", user, status, body)
		}
	}
	create("viewer1", "viewer")
	create("admin1", "admin")

	// Account rules.
	for _, bad := range []map[string]string{
		{"username": "viewer1", "password": "a-long-enough-password", "role": "viewer"}, // taken
		{"username": "VIEWER1", "password": "a-long-enough-password", "role": "viewer"}, // taken, whatever the case
		{"username": "x", "password": "a-long-enough-password", "role": "viewer"},       // too short a name
		{"username": "ok.name", "password": "short", "role": "viewer"},                  // weak password
		{"username": "ok.name", "password": "a-long-enough-password", "role": "root"},   // no such role
		{"username": "bad name!", "password": "a-long-enough-password", "role": "admin"},
	} {
		if status, _ := owner.do("POST", "/api/admin/admins", bad); status/100 == 2 {
			t.Errorf("account %v was accepted", bad)
		}
	}

	_, room := owner.do("POST", "/api/admin/rooms", map[string]any{"name": "roles"})
	roomID := int(room["room"].(map[string]any)["id"].(float64))

	viewer := s.api()
	viewer.mustLogin("viewer1", "a-long-enough-password")
	for _, path := range []string{"/api/admin/rooms", "/api/admin/overview", "/api/admin/connections", "/api/admin/events", "/api/admin/settings", "/api/admin/bans", "/api/admin/devices"} {
		if status, _ := viewer.do("GET", path, nil); status != http.StatusOK {
			t.Errorf("viewer GET %s: HTTP %d", path, status)
		}
	}
	for _, call := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/admin/rooms", map[string]any{"name": "nope"}},
		{"PATCH", fmt.Sprintf("/api/admin/rooms/%d", roomID), map[string]any{"enabled": false}},
		{"DELETE", fmt.Sprintf("/api/admin/rooms/%d", roomID), nil},
		{"POST", fmt.Sprintf("/api/admin/rooms/%d/password", roomID), map[string]any{}},
		{"PUT", "/api/admin/settings", map[string]any{"mtu": 1200}},
		{"POST", "/api/admin/bans", map[string]any{"kind": "ip", "value": "203.0.113.0/24"}},
		{"GET", "/api/admin/admins", nil},
		{"POST", "/api/admin/admins", map[string]string{"username": "sneaky", "password": "a-long-enough-password", "role": "owner"}},
	} {
		if status, body := viewer.do(call.method, call.path, call.body); status != http.StatusForbidden || errorCode(body) != "forbidden" {
			t.Errorf("viewer %s %s: HTTP %d %v, want 403", call.method, call.path, status, body)
		}
	}

	admin := s.api()
	admin.mustLogin("admin1", "a-long-enough-password")
	if status, _ := admin.do("POST", "/api/admin/rooms", map[string]any{"name": "by admin"}); status != http.StatusCreated {
		t.Errorf("admin could not create a room: HTTP %d", status)
	}
	if status, _ := admin.do("GET", "/api/admin/admins", nil); status != http.StatusForbidden {
		t.Errorf("an admin can list administrator accounts: HTTP %d", status)
	}

	// The server always keeps an owner who can sign in.
	_, me := owner.do("GET", "/api/admin/me", nil)
	ownerID := int(me["admin"].(map[string]any)["id"].(float64))
	for _, call := range []struct {
		method string
		body   any
	}{
		{"DELETE", nil},
		{"PATCH", map[string]any{"role": "admin"}},
		{"PATCH", map[string]any{"disabled": true}},
	} {
		if status, body := owner.do(call.method, fmt.Sprintf("/api/admin/admins/%d", ownerID), call.body); status != http.StatusConflict {
			t.Errorf("%s of the last owner (%v): HTTP %d %v, want 409", call.method, call.body, status, body)
		}
	}

	// Disabling an account ends its sessions immediately.
	_, list := owner.do("GET", "/api/admin/admins", nil)
	var viewerID int
	for _, a := range list["admins"].([]any) {
		if a.(map[string]any)["username"] == "viewer1" {
			viewerID = int(a.(map[string]any)["id"].(float64))
		}
	}
	if status, _ := owner.do("PATCH", fmt.Sprintf("/api/admin/admins/%d", viewerID), map[string]any{"disabled": true}); status != http.StatusOK {
		t.Fatal("disable failed")
	}
	if status, _ := viewer.do("GET", "/api/admin/rooms", nil); status != http.StatusUnauthorized {
		t.Errorf("a disabled account's session still works: HTTP %d", status)
	}
	if status := s.api().login("viewer1", "a-long-enough-password"); status != http.StatusUnauthorized {
		t.Errorf("a disabled account can sign in: HTTP %d", status)
	}
}

func TestRoomAdministrationRules(t *testing.T) {
	s := startServer(t, nil)
	c := s.api()
	c.mustLogin("admin", adminPassword)

	// A generated password is shown once and never again.
	status, created := c.do("POST", "/api/admin/rooms", map[string]any{"name": "  Game   night  ", "description": "Fridays", "capacity": 12})
	if status != http.StatusCreated {
		t.Fatalf("create: HTTP %d %v", status, created)
	}
	generated, _ := created["password"].(string)
	room := created["room"].(map[string]any)
	if len(generated) != 19 || room["name"] != "Game night" || room["capacity"].(float64) != 12 || room["subnet"] != "10.214.0.0/24" {
		t.Fatalf("created room: %v, password %q", room, generated)
	}
	id := int(room["id"].(float64))
	_, detail := c.do("GET", fmt.Sprintf("/api/admin/rooms/%d", id), nil)
	_, list := c.do("GET", "/api/admin/rooms", nil)
	for _, body := range []map[string]any{detail, list} {
		raw, _ := json.Marshal(body)
		if bytes.Contains(raw, []byte(generated)) || bytes.Contains(raw, []byte("argon2")) || bytes.Contains(raw, []byte("password")) {
			t.Fatalf("the API exposes password material: %s", raw)
		}
	}
	// The generated password works for joining.
	cl := s.client("alice", room["public_id"].(string), generated)
	if st := cl.waitConnected(); st.Error != "" {
		t.Fatalf("join with the generated password: %s", st.Error)
	}

	for name, bad := range map[string]map[string]any{
		"no name":          {"name": "   "},
		"capacity 1":       {"name": "x", "capacity": 1},
		"capacity 254":     {"name": "x", "capacity": 254},
		"short password":   {"name": "x", "password": "short"},
		"subnet not /24":   {"name": "x", "subnet": "10.99.0.0/16"},
		"subnet host bits": {"name": "x", "subnet": "10.99.0.7/24"},
		"subnet taken":     {"name": "x", "subnet": "10.214.0.0/24"},
		"IPv6 subnet":      {"name": "x", "subnet": "fd00::/64"},
	} {
		if status, body := c.do("POST", "/api/admin/rooms", bad); status/100 == 2 {
			t.Errorf("%s: accepted (%v)", name, body)
		}
	}

	// Settings are validated before they are stored.
	for name, bad := range map[string]map[string]any{
		"MTU too large":   {"mtu": 9000},
		"pool too small":  {"address_pool": "10.1.2.0/28"},
		"pool not masked": {"address_pool": "10.1.2.3/16"},
		"IPv6 pool":       {"address_pool": "fd00::/48"},
		"zero capacity":   {"default_capacity": 0},
		"empty name":      {"server_name": "  "},
		"old min client":  {"min_client_version": "0.0.1"},
	} {
		if status, body := c.do("PUT", "/api/admin/settings", bad); status != http.StatusBadRequest {
			t.Errorf("%s: HTTP %d %v", name, status, body)
		}
	}
	if status, _ := c.do("PUT", "/api/admin/settings", map[string]any{"address_pool": "10.99.0.0/16", "mtu": 1200}); status != http.StatusOK {
		t.Fatal("valid settings rejected")
	}
	_, next := c.do("POST", "/api/admin/rooms", map[string]any{"name": "after the change"})
	if subnet := next["room"].(map[string]any)["subnet"]; subnet != "10.99.0.0/24" {
		t.Fatalf("new pool not used: %v", subnet)
	}

	// Unknown routes under /api do not fall through to the dashboard page.
	if status, body := c.do("GET", "/api/admin/nonexistent", nil); status != http.StatusNotFound || errorCode(body) == "" {
		t.Errorf("unknown admin route: HTTP %d %v", status, body)
	}
	// Oversized bodies are refused, not buffered.
	big := map[string]any{"name": strings.Repeat("x", 100_000)}
	if status, _ := c.do("POST", "/api/admin/rooms", big); status != http.StatusRequestEntityTooLarge {
		t.Errorf("100 kB body: HTTP %d", status)
	}
}

// join performs a raw join request and returns the status and error code.
func rawJoin(t *testing.T, s *testServer, roomID, password string, identity ed25519.PrivateKey, mutate func(*proto.JoinRequest), headers ...string) (int, string, proto.JoinResponse) {
	t.Helper()
	c := s.api()
	_, hello := c.do("GET", "/api/v1/hello", nil, headers...)
	nonce, _ := hello["nonce"].(string)
	var pub proto.Key32
	copy(pub[:], identity.Public().(ed25519.PublicKey))
	req := proto.JoinRequest{
		RoomID: roomID, Password: password, Nickname: "raw", Identity: pub, Nonce: nonce,
		Signature:     ed25519.Sign(identity, proto.JoinTranscript(nonce, roomID, pub)),
		ClientVersion: "1.0.0", Protocol: 1, Platform: "test",
	}
	if mutate != nil {
		mutate(&req)
	}
	raw, _ := json.Marshal(req)
	hreq, _ := http.NewRequest("POST", c.base+"/api/v1/join", bytes.NewReader(raw))
	for i := 0; i+1 < len(headers); i += 2 {
		hreq.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.http.Do(hreq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var ok proto.JoinResponse
	var er proto.ErrorResponse
	json.Unmarshal(body, &ok)
	json.Unmarshal(body, &er)
	return resp.StatusCode, string(er.Error.Code), ok
}

func newIdentity() ed25519.PrivateKey {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	return k
}

func TestJoinIsAuthenticatedAndRateLimited(t *testing.T) {
	// Every simulated client gets its own address through a trusted proxy,
	// so the tests below are not throttled by each other.
	s := startServer(t, map[string]string{"LANORA_TRUSTED_PROXIES": "127.0.0.1"})
	room := s.room("guarded", password, 8)
	from := func(ip string) []string { return []string{"X-Forwarded-For", ip} }

	id := newIdentity()
	if status, code, resp := rawJoin(t, s, room.PublicID, password, id, nil, from("198.51.100.1")...); status != http.StatusOK || resp.Token == "" || resp.IP.String() != "10.214.0.1" {
		t.Fatalf("valid join: HTTP %d %s", status, code)
	}

	// A join must be signed by the identity it claims, over this server's
	// nonce.
	other := newIdentity()
	cases := map[string]func(*proto.JoinRequest){
		"signature by another key": func(r *proto.JoinRequest) {
			r.Signature = ed25519.Sign(other, proto.JoinTranscript(r.Nonce, r.RoomID, r.Identity))
		},
		"signature over another room": func(r *proto.JoinRequest) {
			r.Signature = ed25519.Sign(id, proto.JoinTranscript(r.Nonce, "ZZZZZZZZZ", r.Identity))
		},
		"no signature":       func(r *proto.JoinRequest) { r.Signature = nil },
		"made-up nonce":      func(r *proto.JoinRequest) { r.Nonce = "AAAA.BBBB" },
		"zero identity":      func(r *proto.JoinRequest) { r.Identity = proto.Key32{} },
		"wrong protocol":     func(r *proto.JoinRequest) { r.Protocol = 99 },
		"client too old":     func(r *proto.JoinRequest) { r.ClientVersion = "0.1.0" },
		"control characters": func(r *proto.JoinRequest) { r.Nickname = "\x00\x01\x02" },
	}
	n := 2
	for name, mutate := range cases {
		n++
		if status, code, _ := rawJoin(t, s, room.PublicID, password, id, mutate, from(fmt.Sprintf("198.51.100.%d", n))...); status/100 == 2 {
			t.Errorf("%s: join accepted", name)
		} else if code == "" {
			t.Errorf("%s: HTTP %d without an error code", name, status)
		}
	}

	// Guessing: five wrong passwords from one address lock it out, and the
	// right password does not get through during the lockout.
	guesser := from("198.51.100.200")
	for i := 0; i < 5; i++ {
		if status, code, _ := rawJoin(t, s, room.PublicID, fmt.Sprintf("guess-number-%d", i), newIdentity(), nil, guesser...); status != http.StatusUnauthorized || code != "invalid_credentials" {
			t.Fatalf("guess %d: HTTP %d %s", i, status, code)
		}
	}
	if status, code, _ := rawJoin(t, s, room.PublicID, password, newIdentity(), nil, guesser...); status != http.StatusTooManyRequests || code != "rate_limited" {
		t.Fatalf("correct password during a lockout: HTTP %d %s", status, code)
	}
	// Another address is unaffected, and so is another room from the same
	// address: people sharing a public address (a VPN exit, a campus) must
	// not be locked out of their rooms by a stranger's typing.
	if status, _, _ := rawJoin(t, s, room.PublicID, password, newIdentity(), nil, from("198.51.100.201")...); status != http.StatusOK {
		t.Fatalf("an unrelated address was locked out too: HTTP %d", status)
	}
	neighbour := s.room("neighbour", password, 8)
	if status, _, _ := rawJoin(t, s, neighbour.PublicID, password, newIdentity(), nil, guesser...); status != http.StatusOK {
		t.Fatalf("the lockout spread to another room: HTTP %d", status)
	}
	// The forwarded header is only believed from the configured proxy: this
	// second server trusts none, so changing the header changes nothing.
	s2 := startServer(t, nil)
	room2 := s2.room("unproxied", password, 8)
	for i := 0; i < 5; i++ {
		rawJoin(t, s2, room2.PublicID, "wrong-wrong-wrong", newIdentity(), nil, "X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i+1))
	}
	if status, code, _ := rawJoin(t, s2, room2.PublicID, password, newIdentity(), nil, "X-Forwarded-For", "203.0.113.99"); status != http.StatusTooManyRequests {
		t.Fatalf("a spoofed X-Forwarded-For header escaped the lockout: HTTP %d %s", status, code)
	}

	// The failures are in the log for the administrator to see.
	time.Sleep(700 * time.Millisecond)
	events, err := s.app.Store.ListEvents(context.Background(), store.EventFilter{Kind: "auth.", Limit: 50})
	if err != nil || len(events) < 5 {
		t.Fatalf("failed joins were not logged: %d events, %v", len(events), err)
	}
	sawLockout := false
	for _, e := range events {
		if e.Kind == "auth.lockout" && e.Addr == "198.51.100.200" {
			sawLockout = true
		}
	}
	if !sawLockout {
		t.Error("the lockout was not logged")
	}
}

func TestServerWideBans(t *testing.T) {
	s := startServer(t, map[string]string{"LANORA_TRUSTED_PROXIES": "127.0.0.1"})
	room := s.room("bans", password, 8)
	c := s.api()
	c.mustLogin("admin", adminPassword)

	banned := newIdentity()
	var pub proto.Key32
	copy(pub[:], banned.Public().(ed25519.PublicKey))
	if status, body := c.do("POST", "/api/admin/bans", map[string]string{"kind": "identity", "value": pub.String(), "reason": "abuse"}); status != http.StatusCreated {
		t.Fatalf("identity ban: HTTP %d %v", status, body)
	}
	if status, body := c.do("POST", "/api/admin/bans", map[string]string{"kind": "ip", "value": "203.0.113.0/24"}); status != http.StatusCreated {
		t.Fatalf("range ban: HTTP %d %v", status, body)
	}
	for _, bad := range []map[string]string{
		{"kind": "ip", "value": "not an address"},
		{"kind": "identity", "value": "tooshort"},
		{"kind": "country", "value": "XX"},
		{"kind": "ip", "value": "203.0.113.0/24"}, // already there
		{"kind": "ip", "value": "127.0.0.0/8"},    // would cover the administrator
	} {
		if status, _ := c.do("POST", "/api/admin/bans", bad); status/100 == 2 {
			t.Errorf("ban %v accepted", bad)
		}
	}

	if status, code, _ := rawJoin(t, s, room.PublicID, password, banned, nil, "X-Forwarded-For", "198.51.100.5"); status != http.StatusForbidden || code != "banned" {
		t.Fatalf("banned device: HTTP %d %s", status, code)
	}
	if status, code, _ := rawJoin(t, s, room.PublicID, password, newIdentity(), nil, "X-Forwarded-For", "203.0.113.77"); status != http.StatusForbidden || code != "banned" {
		t.Fatalf("banned address range: HTTP %d %s", status, code)
	}
	if status, _, _ := rawJoin(t, s, room.PublicID, password, newIdentity(), nil, "X-Forwarded-For", "198.51.100.6"); status != http.StatusOK {
		t.Fatalf("an unbanned client was refused: HTTP %d", status)
	}

	// Lifting the ban takes effect at once.
	_, list := c.do("GET", "/api/admin/bans", nil)
	for _, b := range list["bans"].([]any) {
		ban := b.(map[string]any)
		if status, _ := c.do("DELETE", fmt.Sprintf("/api/admin/bans/%d", int(ban["id"].(float64))), nil); status != http.StatusOK {
			t.Fatalf("removing ban %v: HTTP %d", ban, status)
		}
	}
	if status, _, _ := rawJoin(t, s, room.PublicID, password, banned, nil, "X-Forwarded-For", "198.51.100.5"); status != http.StatusOK {
		t.Fatalf("the device is still refused after the ban was lifted: HTTP %d", status)
	}
}

// A session token names its room and its membership by database id. When a
// room is deleted and another created (the obvious way to get rid of people
// who know the password), nobody holding a token from the old room may get
// into the new one, although the new room takes over the old one's subnet
// and its members the old members' addresses.
func TestTokensDoNotOutliveTheirRoom(t *testing.T) {
	s := startServer(t, nil)
	ctx := context.Background()
	open := func(id ed25519.PrivateKey, token string) error {
		cl := control.New(s.addr, id)
		defer cl.Close()
		octx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var k proto.Key32
		k[0] = 1
		sess, err := cl.OpenSession(octx, token, proto.Msg{WGPub: &k, DiscoPub: &k})
		if err == nil {
			sess.Close()
		}
		return err
	}

	old := s.room("first", password, 8)
	former := newIdentity()
	_, _, before := rawJoin(t, s, old.PublicID, password, former, nil)
	if err := open(former, before.Token); err != nil {
		t.Fatalf("the genuine token was refused: %v", err)
	}

	admin := s.api()
	admin.mustLogin("admin", "test-admin-password")
	if status, body := admin.do("DELETE", fmt.Sprintf("/api/admin/rooms/%d", old.ID), nil); status != http.StatusOK && status != http.StatusNoContent {
		t.Fatalf("delete room: HTTP %d %v", status, body)
	}
	const newPassword = "a-different-password-456"
	fresh := s.room("second", newPassword, 8)
	if fresh.Subnet != old.Subnet {
		t.Fatalf("the test expects the new room to take over the subnet: %s then %s", old.Subnet, fresh.Subnet)
	}
	newcomer := newIdentity()
	_, _, after := rawJoin(t, s, fresh.PublicID, newPassword, newcomer, nil)
	if after.IP != before.IP {
		t.Fatalf("the test expects the new member to take over the address: %s then %s", before.IP, after.IP)
	}

	if err := open(former, before.Token); err == nil {
		t.Error("a token from the deleted room opens a session in the room that replaced it")
	}
	if err := open(newcomer, after.Token); err != nil {
		t.Errorf("the new member's own token was refused: %v", err)
	}

	// A token is also tied to the device it was issued to: the right room
	// and membership under another device's name are refused. (Only the
	// server can sign such a token; this checks the server would not honour
	// it if its ids ever did line up.)
	members, err := s.app.Store.ListMembers(ctx, fresh.ID)
	if err != nil || len(members) != 1 {
		t.Fatalf("members of the new room: %v, %v", members, err)
	}
	claims := auth.SessionClaims{
		Room: fresh.ID, Member: members[0].ID, Device: auth.DeviceClaim(members[0].Identity),
		PasswordVersion: fresh.PasswordVersion, Expiry: time.Now().Add(time.Hour).Unix(),
	}
	if err := open(newcomer, s.app.API.Keys.IssueSession(claims)); err != nil {
		t.Fatalf("a token with the membership's own claims was refused: %v", err)
	}
	var formerKey proto.Key32
	copy(formerKey[:], former.Public().(ed25519.PublicKey))
	claims.Device = auth.DeviceClaim(formerKey)
	if err := open(former, s.app.API.Keys.IssueSession(claims)); err == nil {
		t.Error("a token naming another device's membership opens a session")
	}
	claims.Device = ""
	if err := open(former, s.app.API.Keys.IssueSession(claims)); err == nil {
		t.Error("a token naming no device opens a session")
	}
}

func TestSessionTokensCannotBeForged(t *testing.T) {
	s := startServer(t, nil)
	room := s.room("tokens", password, 8)
	other := s.room("other", password, 8)
	id := newIdentity()
	_, _, join := rawJoin(t, s, room.PublicID, password, id, nil)
	if join.Token == "" {
		t.Fatal("no token")
	}
	cl := control.New(s.addr, id)
	defer cl.Close()
	open := func(token string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var k proto.Key32
		k[0] = 1
		sess, err := cl.OpenSession(ctx, token, proto.Msg{WGPub: &k, DiscoPub: &k})
		if err == nil {
			sess.Close()
		}
		return err
	}
	if err := open(join.Token); err != nil {
		t.Fatalf("the genuine token was refused: %v", err)
	}

	payload, sig, _ := strings.Cut(join.Token, ".")
	// A token altered to name another room, with or without its signature.
	forgedPayload := strings.Replace(payload, payload[:6], "AAAAAA", 1)
	for name, tok := range map[string]string{
		"altered payload":     forgedPayload + "." + sig,
		"missing signature":   payload + ".",
		"truncated signature": payload + "." + sig[:10],
		"empty":               "",
		"garbage":             "not-a-token",
	} {
		if err := open(tok); err == nil {
			t.Errorf("%s: session opened", name)
		}
	}
	// A token for one room is useless once that room's password changes.
	hash, _ := s.hasher.Hash(context.Background(), "changed-password-123")
	if _, err := s.app.Store.SetRoomPassword(context.Background(), room.ID, hash); err != nil {
		t.Fatal(err)
	}
	if err := open(join.Token); err == nil {
		t.Error("a token issued before the password change still opens a session")
	}
	_ = other

	// The metrics endpoint does not exist unless a token is configured, and
	// then requires it.
	if resp, err := http.Get(s.addr.Base.String() + "/metrics"); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("metrics without configuration: %v %v", resp.StatusCode, err)
	}
	m := startServer(t, map[string]string{"LANORA_METRICS_TOKEN": "metrics-secret"})
	for auth, want := range map[string]int{"": 401, "Bearer wrong": 401, "Bearer metrics-secret": 200} {
		req, _ := http.NewRequest("GET", m.addr.Base.String()+"/metrics", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("metrics with %q: HTTP %d, want %d", auth, resp.StatusCode, want)
		}
		if want == 200 && !strings.Contains(string(body), "lanora_members_online") {
			t.Errorf("metrics body: %s", body)
		}
	}
}
