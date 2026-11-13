package auth

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHashAndVerify(t *testing.T) {
	ctx := context.Background()
	h := NewHasher(2)

	enc, err := h.Hash(ctx, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected encoding %q", enc)
	}
	if ok, rehash, err := h.Verify(ctx, enc, "correct horse"); !ok || rehash || err != nil {
		t.Fatalf("verify correct = %v, %v, %v", ok, rehash, err)
	}
	if ok, _, err := h.Verify(ctx, enc, "wrong horse"); ok || err != nil {
		t.Fatalf("verify wrong = %v, %v", ok, err)
	}

	other, _ := h.Hash(ctx, "correct horse")
	if other == enc {
		t.Fatal("two hashes of one password are identical: the salt is not random")
	}

	// A hash made with weaker parameters still verifies but asks for a rehash.
	weak := "$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0$" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, _, err := h.Verify(ctx, weak, "x"); err != nil {
		t.Fatalf("weak-parameter hash rejected as malformed: %v", err)
	}

	for _, bad := range []string{
		"", "plain", "$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$AAAA",
		"$argon2id$v=18$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$" + strings.Repeat("A", 43),
		"$argon2id$v=19$m=99999999,t=2,p=1$c2FsdHNhbHRzYWx0$" + strings.Repeat("A", 43), // absurd memory
		"$argon2id$v=19$m=19456,t=2,p=1$!!!$" + strings.Repeat("A", 43),
	} {
		if _, _, err := h.Verify(ctx, bad, "x"); err == nil {
			t.Errorf("malformed hash %q accepted", bad)
		}
	}
}

func TestHasherBoundsConcurrency(t *testing.T) {
	h := NewHasher(1)
	h.slots <- struct{}{} // occupy the only slot

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(ctx, "pw"); err == nil {
		t.Fatal("Hash did not wait for a free slot")
	}

	// With the queue full, further requests are refused at once rather
	// than left to time out.
	h.waiting.Store(maxWaitersPerSlot)
	start := time.Now()
	if _, _, err := h.Verify(context.Background(), h.dummy, "pw"); err != ErrBusy {
		t.Fatalf("over-full queue: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("refusal was not immediate")
	}
	h.waiting.Store(0)
	<-h.slots

	// With the slot free again many callers all complete, one at a time.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.Hash(context.Background(), "pw"); err != nil {
				t.Errorf("hash: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestSessionTokens(t *testing.T) {
	keys := DeriveKeys([]byte("master secret"), nil)
	now := time.Unix(1_800_000_000, 0)
	claims := SessionClaims{
		Room: 7, Member: 99, Device: DeviceClaim([32]byte{1, 2, 3}),
		PasswordVersion: 3, Expiry: now.Add(time.Hour).Unix(),
	}
	tok := keys.IssueSession(claims)

	got, err := keys.ParseSession(tok, now)
	if err != nil || got != claims {
		t.Fatalf("parse = %+v, %v", got, err)
	}
	if _, err := keys.ParseSession(tok, now.Add(2*time.Hour)); err != ErrTokenExpired {
		t.Fatalf("expired token: %v", err)
	}
	if _, err := DeriveKeys([]byte("another master"), nil).ParseSession(tok, now); err != ErrTokenInvalid {
		t.Fatalf("token verified under another server's key: %v", err)
	}

	// Any change to the payload or signature must be rejected.
	for i := range tok {
		if tok[i] == '.' {
			continue
		}
		c := byte('A')
		if tok[i] == 'A' {
			c = 'B'
		}
		forged := tok[:i] + string(c) + tok[i+1:]
		if _, err := keys.ParseSession(forged, now); err == nil {
			t.Fatalf("forged token accepted (byte %d changed)", i)
		}
	}
	for _, bad := range []string{"", ".", "a.b", "no-dot", strings.Repeat("A", 2000)} {
		if _, err := keys.ParseSession(bad, now); err == nil {
			t.Errorf("garbage token %q accepted", bad)
		}
	}

	// A join nonce must not be usable as a session token or vice versa.
	nonce := keys.IssueNonce(now)
	if _, err := keys.ParseSession(nonce, now); err == nil {
		t.Fatal("nonce accepted as a session token")
	}
	if err := keys.CheckNonce(tok, now); err == nil {
		t.Fatal("session token accepted as a nonce")
	}
}

func TestNonces(t *testing.T) {
	keys := DeriveKeys([]byte("master secret"), nil)
	now := time.Unix(1_800_000_000, 0)
	n := keys.IssueNonce(now)
	if err := keys.CheckNonce(n, now.Add(time.Minute)); err != nil {
		t.Fatalf("fresh nonce: %v", err)
	}
	if err := keys.CheckNonce(n, now.Add(NonceTTL+time.Second)); err != ErrTokenExpired {
		t.Fatalf("stale nonce: %v", err)
	}
	if keys.IssueNonce(now) == n {
		t.Fatal("two nonces issued in the same second are identical")
	}
}

func TestRelaySecretOverride(t *testing.T) {
	a := DeriveKeys([]byte("m"), nil)
	b := DeriveKeys([]byte("m"), []byte("shared with relays"))
	if string(a.RelaySecret()) == string(b.RelaySecret()) || string(b.RelaySecret()) != "shared with relays" {
		t.Fatal("relay secret override not applied")
	}
}

func TestOpaqueTokens(t *testing.T) {
	tok, hash := NewOpaqueToken()
	tok2, _ := NewOpaqueToken()
	if tok == tok2 || len(tok) < 40 || string(HashOpaqueToken(tok)) != string(hash) {
		t.Fatal("opaque tokens are not random or do not hash consistently")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := NewLimiter(60, 3) // 1 per second, burst of 3
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("burst request %d refused", i)
		}
	}
	ok, retry := l.Allow("a")
	if ok || retry <= 0 || retry > time.Second {
		t.Fatalf("fourth request: ok=%v retry=%v", ok, retry)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("another key was throttled by the first")
	}
	now = now.Add(retry)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("request refused after waiting the advertised retry time")
	}

	// Idle buckets are forgotten.
	now = now.Add(10 * time.Minute)
	l.Allow("c")
	if len(l.buckets) != 1 {
		t.Fatalf("%d buckets kept after sweep", len(l.buckets))
	}
}

func TestLockout(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := NewLockout(3, 10*time.Second, time.Minute)
	l.now = func() time.Time { return now }

	if d := l.Fail("k"); d != 0 {
		t.Fatalf("locked after one failure: %v", d)
	}
	l.Fail("k")
	if l.Locked("k") != 0 {
		t.Fatal("locked below the threshold")
	}
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, time.Minute, time.Minute}
	for i, w := range want {
		if d := l.Fail("k"); d != w {
			t.Fatalf("failure %d locked for %v, want %v", i+3, d, w)
		}
	}
	if l.Locked("k") != time.Minute {
		t.Fatalf("Locked = %v", l.Locked("k"))
	}
	if l.Locked("other") != 0 {
		t.Fatal("unrelated key locked")
	}
	now = now.Add(61 * time.Second)
	if l.Locked("k") != 0 {
		t.Fatal("lock did not expire")
	}
	l.Success("k")
	if d := l.Fail("k"); d != 0 {
		t.Fatalf("history not cleared by success: %v", d)
	}

	// A very long failure streak must not overflow into a zero-length lock.
	for i := 0; i < 200; i++ {
		l.Fail("streak")
	}
	if d := l.Locked("streak"); d != time.Minute {
		t.Fatalf("long streak locked for %v", d)
	}
}
