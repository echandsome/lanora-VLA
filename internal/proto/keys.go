// Package proto defines everything the Lanora server and clients must agree
// on: the HTTP API payloads, the signalling messages exchanged over the
// session WebSocket, and the UDP wire frames used for relaying and for
// peer-to-peer path discovery.
package proto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// Key32 is a 32-byte public key (Ed25519 identity keys, Curve25519 WireGuard
// and discovery keys). It is transported as standard base64 text.
type Key32 [32]byte

// ErrBadKey is returned when a textual key does not decode to 32 bytes.
var ErrBadKey = errors.New("proto: key must be 32 bytes of base64")

// ParseKey32 decodes a base64 key.
func ParseKey32(s string) (Key32, error) {
	var k Key32
	if base64.StdEncoding.DecodedLen(len(s)) > len(k)+2 {
		return k, ErrBadKey
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != len(k) {
		return k, ErrBadKey
	}
	copy(k[:], b)
	return k, nil
}

// String returns the base64 form of the key.
func (k Key32) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Hex returns the lowercase hexadecimal form of the key (the format the
// WireGuard configuration protocol expects).
func (k Key32) Hex() string { return hex.EncodeToString(k[:]) }

// Short returns an abbreviated fingerprint suitable for logs and tables.
func (k Key32) Short() string { return hex.EncodeToString(k[:4]) }

// IsZero reports whether the key is all zero bytes.
func (k Key32) IsZero() bool { return k == Key32{} }

// MarshalText implements encoding.TextMarshaler.
func (k Key32) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *Key32) UnmarshalText(b []byte) error {
	parsed, err := ParseKey32(string(b))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// RandomBytes returns n cryptographically random bytes. It panics if the
// operating system's random source fails, which leaves no safe way to
// continue.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("proto: system random source failed: " + err.Error())
	}
	return b
}
