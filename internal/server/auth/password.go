// Package auth holds the server's credential handling: password hashing,
// signed tokens, and the rate limiting that protects both.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters, following the OWASP password storage guidance
// (19 MiB of memory, two passes, one lane). They are encoded into every hash,
// so they can be raised later without invalidating existing passwords:
// Verify reports when a hash was made with weaker parameters.
const (
	argonMemoryKiB = 19 * 1024
	argonTime      = 2
	argonThreads   = 1
	argonSaltLen   = 16
	argonKeyLen    = 32
)

// ErrBadHash is returned when a stored hash cannot be parsed.
var ErrBadHash = errors.New("auth: malformed password hash")

// ErrBusy is returned when more passwords are waiting to be checked than
// the server can get to in a reasonable time. Callers should tell the
// client to try again shortly: answering "busy" at once keeps a burst of
// sign-ins from turning into a queue in which every request times out.
var ErrBusy = errors.New("auth: too many sign-ins in progress")

const (
	// maxHashWait is how long a request waits for its turn to be hashed.
	maxHashWait = 4 * time.Second
	// maxWaitersPerSlot bounds the queue; beyond it requests are refused
	// immediately.
	maxWaitersPerSlot = 32
)

// Hasher hashes and verifies passwords. Argon2 is deliberately expensive in
// both CPU and memory, so the number of hashes computed at once is capped;
// callers beyond the cap wait their turn (or give up when their context is
// cancelled) instead of letting a burst of sign-in attempts exhaust the
// server's memory.
type Hasher struct {
	slots   chan struct{}
	waiting atomic.Int32
	dummy   string
}

// NewHasher returns a Hasher that computes at most concurrency hashes at a
// time.
func NewHasher(concurrency int) *Hasher {
	if concurrency < 1 {
		concurrency = 1
	}
	h := &Hasher{slots: make(chan struct{}, concurrency)}
	h.dummy = hashWith(string(randomBytes(16)), randomBytes(argonSaltLen))
	return h
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.slots <- struct{}{}:
		return nil
	default:
	}
	if int(h.waiting.Add(1)) > cap(h.slots)*maxWaitersPerSlot {
		h.waiting.Add(-1)
		return ErrBusy
	}
	defer h.waiting.Add(-1)
	timer := time.NewTimer(maxHashWait)
	defer timer.Stop()
	select {
	case h.slots <- struct{}{}:
		return nil
	case <-timer.C:
		return ErrBusy
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Hash returns the encoded Argon2id hash of password.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer func() { <-h.slots }()
	return hashWith(password, randomBytes(argonSaltLen)), nil
}

// Verify reports whether password matches the encoded hash. rehash is true
// when the password is correct but the hash was produced with parameters
// weaker than the current ones and should be replaced.
func (h *Hasher) Verify(ctx context.Context, encoded, password string) (ok, rehash bool, err error) {
	p, salt, want, err := parseHash(encoded)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer func() { <-h.slots }()
	got := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	weaker := p.memory < argonMemoryKiB || p.time < argonTime || len(want) < argonKeyLen
	return true, weaker, nil
}

// Burn spends the same effort as a real verification without a real hash to
// check against. Sign-in handlers call it when the account or room does not
// exist, so that a missing name and a wrong password take the same time and
// cannot be told apart.
func (h *Hasher) Burn(ctx context.Context, password string) {
	h.Verify(ctx, h.dummy, password)
}

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func hashWith(password string, salt []byte) string {
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// parseHash decodes the PHC string format:
// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
func parseHash(encoded string) (p argonParams, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, ErrBadHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return p, nil, nil, ErrBadHash
	}
	// Bound the parameters so a corrupted or hostile hash cannot make the
	// server allocate gigabytes.
	if p.memory < 8 || p.memory > 1<<20 || p.time < 1 || p.time > 16 || p.threads < 1 || p.threads > 16 {
		return p, nil, nil, ErrBadHash
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(salt) < 8 {
		return p, nil, nil, ErrBadHash
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(key) < 16 {
		return p, nil, nil, ErrBadHash
	}
	return p, salt, key, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("auth: system random source failed: " + err.Error())
	}
	return b
}
