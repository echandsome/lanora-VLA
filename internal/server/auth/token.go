package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Token errors.
var (
	ErrTokenInvalid = errors.New("auth: invalid token")
	ErrTokenExpired = errors.New("auth: token expired")
)

// Keys are the purpose-specific secrets derived from the server's master
// secret. Deriving one key per purpose means a token minted for one purpose
// can never be replayed as another kind of token.
type Keys struct {
	session []byte
	nonce   []byte
	relay   []byte
}

// DeriveKeys expands the master secret. relayOverride, when non-empty,
// replaces the derived relay secret: it is the value shared with stand-alone
// relay nodes.
func DeriveKeys(master, relayOverride []byte) *Keys {
	k := &Keys{
		session: derive(master, "lanora session token v1"),
		nonce:   derive(master, "lanora join nonce v1"),
		relay:   derive(master, "lanora relay secret v1"),
	}
	if len(relayOverride) > 0 {
		k.relay = relayOverride
	}
	return k
}

func derive(master []byte, label string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte(label))
	return m.Sum(nil)
}

// RelaySecret returns the secret relay tickets are keyed with.
func (k *Keys) RelaySecret() []byte { return k.relay }

// SessionClaims is the content of a room session token. The token is
// self-contained, so a client can resume its session after a server restart
// without the server keeping any per-session state; membership, bans and the
// room password version are still re-checked against the database each time
// it is presented.
//
// Device names the device the token was issued to (its identity key, in
// base64url). Room and Member are database ids, and a token must not start
// to mean someone else if a membership row is ever replaced, so the server
// also checks that the membership still belongs to this device.
type SessionClaims struct {
	Room            int64  `json:"r"`
	Member          int64  `json:"m"`
	Device          string `json:"d"`
	PasswordVersion int    `json:"pv"`
	Expiry          int64  `json:"exp"`
}

// DeviceClaim returns the form in which a device identity key is carried in
// SessionClaims.Device.
func DeviceClaim(identity [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(identity[:])
}

// IssueSession returns a signed session token.
func (k *Keys) IssueSession(c SessionClaims) string {
	payload, _ := json.Marshal(c)
	return sign(k.session, payload)
}

// ParseSession verifies a session token and returns its claims.
func (k *Keys) ParseSession(token string, now time.Time) (SessionClaims, error) {
	var c SessionClaims
	payload, err := verify(k.session, token)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, ErrTokenInvalid
	}
	if now.Unix() >= c.Expiry {
		return c, ErrTokenExpired
	}
	return c, nil
}

// NonceTTL is how long a join nonce stays valid. The nonce carries its own
// issue time, so validity never depends on the client's clock.
const NonceTTL = 5 * time.Minute

// IssueNonce returns a fresh join nonce.
func (k *Keys) IssueNonce(now time.Time) string {
	payload := make([]byte, 8, 24)
	binary.BigEndian.PutUint64(payload, uint64(now.Unix()))
	payload = append(payload, randomBytes(16)...)
	return sign(k.nonce, payload)
}

// CheckNonce verifies that a nonce was issued by this server recently.
func (k *Keys) CheckNonce(nonce string, now time.Time) error {
	payload, err := verify(k.nonce, nonce)
	if err != nil || len(payload) != 24 {
		return ErrTokenInvalid
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(payload[:8])), 0)
	if now.Sub(issued) > NonceTTL || issued.Sub(now) > time.Minute {
		return ErrTokenExpired
	}
	return nil
}

// sign returns "<payload>.<mac>", both base64url without padding.
func sign(key, payload []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(payload)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(m.Sum(nil))
}

func verify(key []byte, token string) ([]byte, error) {
	if len(token) > 1024 {
		return nil, ErrTokenInvalid
	}
	p, s, ok := strings.Cut(token, ".")
	if !ok {
		return nil, ErrTokenInvalid
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(p)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	sig, err := enc.DecodeString(s)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	m := hmac.New(sha256.New, key)
	m.Write(payload)
	if !hmac.Equal(sig, m.Sum(nil)) {
		return nil, ErrTokenInvalid
	}
	return payload, nil
}

// NewOpaqueToken returns a random bearer token and the hash under which it
// is stored. Only the hash is persisted, so a leaked database does not leak
// usable sessions.
func NewOpaqueToken() (token string, hash []byte) {
	token = base64.RawURLEncoding.EncodeToString(randomBytes(32))
	return token, HashOpaqueToken(token)
}

// HashOpaqueToken returns the storage hash of a bearer token.
func HashOpaqueToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
