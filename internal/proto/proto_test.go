package proto

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestNormalizeRoomID(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"7KQ2MX9DW", "7KQ2MX9DW", true},
		{"7kq-2mx-9dw", "7KQ2MX9DW", true},
		{" 7kq 2mx 9dw ", "7KQ2MX9DW", true},
		{"OIL-000-111", "011000111", true}, // O→0, I→1, L→1
		{"7KQ2MX9D", "", false},            // too short
		{"7KQ2MX9DWX", "", false},          // too long
		{"7KQ2MX9DU", "", false},           // U is not in the alphabet
		{"7KQ2MX9D!", "", false},
		{"7KQ2MX9Dé", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, err := NormalizeRoomID(c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("NormalizeRoomID(%q) = %q, %v; want %q, ok=%v", c.in, got, err, c.want, c.ok)
		}
	}
}

func TestGeneratedIDsAndPasswords(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id := NewRoomID()
		norm, err := NormalizeRoomID(FormatRoomID(id))
		if err != nil || norm != id {
			t.Fatalf("generated ID %q does not round-trip: %q, %v", id, norm, err)
		}
		if seen[id] {
			t.Fatalf("duplicate room ID %q in 200 draws", id)
		}
		seen[id] = true

		pw := NewRoomPassword()
		if len(pw) != 19 || strings.Count(pw, "-") != 3 {
			t.Fatalf("unexpected password shape %q", pw)
		}
		if strings.ContainsAny(pw, "0o1li") {
			t.Fatalf("password %q contains a look-alike character", pw)
		}
	}
}

func TestCleanNickname(t *testing.T) {
	cases := map[string]string{
		"  Alice  ":             "Alice",
		"Bob\tthe\n\nBuilder":   "Bob the Builder",
		"evil\x00\x1b[31mname":  "evil[31mname",
		"   ":                   "",
		strings.Repeat("x", 80): strings.Repeat("x", MaxNicknameLen),
		"名前 テスト":                "名前 テスト",
	}
	for in, want := range cases {
		if got := CleanNickname(in); got != want {
			t.Errorf("CleanNickname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAddrPortRoundTrip(t *testing.T) {
	for _, s := range []string{"203.0.113.9:51820", "[2001:db8::1]:443", "10.0.0.1:1"} {
		ap := netip.MustParseAddrPort(s)
		var b [AddrLen]byte
		PutAddrPort(b[:], ap)
		if got := GetAddrPort(b[:]); got != ap {
			t.Errorf("round trip %s = %s", ap, got)
		}
	}
}

func TestBindFrames(t *testing.T) {
	secret := []byte("relay secret")
	claims := Claims{Room: 42, Peer: PeerIDOf(netip.MustParseAddr("10.77.3.9")), Expiry: 1_900_000_000}
	cb := claims.Bytes()
	if len(cb) != ClaimsLen {
		t.Fatalf("claims length %d", len(cb))
	}
	parsed, err := ParseClaims(cb)
	if err != nil || parsed != claims {
		t.Fatalf("claims round trip: %+v, %v", parsed, err)
	}
	key := RelaySessionKey(secret, cb)
	tx := NewTxID()

	req := AppendBindRequest(nil, tx, cb)
	if len(req) != BindRequestLen || !IsFrame(req) || req[1] != FrameBindRequest || FrameTxID(req) != tx {
		t.Fatalf("bad bind request % x", req)
	}

	var cookie [CookieLen]byte
	copy(cookie[:], RandomBytes(CookieLen))
	ch := AppendBindChallenge(nil, tx, cookie)
	if len(ch) != BindChallengeLen {
		t.Fatalf("challenge length %d", len(ch))
	}
	if len(ch) > len(req) {
		t.Fatalf("challenge (%d bytes) must not be larger than the request (%d bytes)", len(ch), len(req))
	}

	conf := AppendBindConfirm(nil, tx, cb, cookie, key)
	if len(conf) != BindConfirmLen || !VerifyMAC(conf, key) {
		t.Fatalf("confirm does not verify")
	}
	tampered := bytes.Clone(conf)
	tampered[HeaderLen+TxIDLen+9] ^= 1 // flip a bit of the peer address
	if VerifyMAC(tampered, key) {
		t.Fatalf("tampered confirm verified")
	}
	if VerifyMAC(conf, RelaySessionKey([]byte("other secret"), cb)) {
		t.Fatalf("confirm verified under the wrong key")
	}

	observed := netip.MustParseAddrPort("198.51.100.7:40000")
	ack := AppendBindAck(nil, tx, observed, key)
	if len(ack) != BindAckLen || !VerifyMAC(ack, key) {
		t.Fatalf("ack does not verify")
	}
	if got := GetAddrPort(ack[HeaderLen+TxIDLen:]); got != observed {
		t.Fatalf("ack observed address %s", got)
	}

	probe := AppendProbe(nil, tx)
	reply := AppendProbeReply(nil, tx, observed)
	if len(probe) != ProbeLen || len(reply) != ProbeLen {
		t.Fatalf("probe %d / reply %d bytes, want %d", len(probe), len(reply), ProbeLen)
	}
}

func TestRelayHeader(t *testing.T) {
	dst := PeerIDOf(netip.MustParseAddr("10.77.3.200"))
	f := AppendRelaySend(nil, dst)
	f = append(f, 1, 0, 0, 0, 9, 9) // a WireGuard-looking payload
	if len(f) != RelayHeaderLen+6 || RelayPeer(f) != dst || RelayPeer(f).Addr().String() != "10.77.3.200" {
		t.Fatalf("bad relay frame % x", f)
	}
	if IsFrame(f[RelayHeaderLen:]) {
		t.Fatalf("a WireGuard packet must not look like a Lanora frame")
	}
}

func TestDiscoSealOpen(t *testing.T) {
	aPub, aPriv, _ := box.GenerateKey(bytes.NewReader(RandomBytes(32)))
	bPub, bPriv, _ := box.GenerateKey(bytes.NewReader(RandomBytes(32)))
	var ab, ba [32]byte
	box.Precompute(&ab, bPub, aPriv)
	box.Precompute(&ba, aPub, bPriv)

	sender := PeerIDOf(netip.MustParseAddr("10.77.3.5"))
	tx := NewDiscoTxID()
	frame := SealDisco(nil, sender, &ab, AppendDiscoPing(nil, tx))

	got, ok := DiscoSender(frame)
	if !ok || got != sender {
		t.Fatalf("sender = %v, %v", got, ok)
	}
	plain, ok := OpenDisco(nil, frame, &ba)
	if !ok {
		t.Fatalf("peer could not open the ping")
	}
	typ, gotTx, _, ok := ParseDisco(plain)
	if !ok || typ != DiscoPing || gotTx != tx {
		t.Fatalf("ping parsed as %d %x %v", typ, gotTx, ok)
	}

	// A third party must not be able to open or forge it.
	_, cPriv, _ := box.GenerateKey(bytes.NewReader(RandomBytes(32)))
	var cb [32]byte
	box.Precompute(&cb, aPub, cPriv)
	if _, ok := OpenDisco(nil, frame, &cb); ok {
		t.Fatalf("an outsider opened the ping")
	}
	frame[len(frame)-1] ^= 1
	if _, ok := OpenDisco(nil, frame, &ba); ok {
		t.Fatalf("a modified ping was accepted")
	}

	observed := netip.MustParseAddrPort("[2001:db8::7]:9000")
	pong := SealDisco(nil, sender, &ab, AppendDiscoPong(nil, tx, observed))
	plain, ok = OpenDisco(nil, pong, &ba)
	typ, gotTx, gotAddr, ok2 := ParseDisco(plain)
	if !ok || !ok2 || typ != DiscoPong || gotTx != tx || gotAddr != observed {
		t.Fatalf("pong parsed as %d %x %s", typ, gotTx, gotAddr)
	}
}
