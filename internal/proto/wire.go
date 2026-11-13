package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/crypto/nacl/box"
)

// UDP wire format
//
// A client uses one UDP socket for everything: WireGuard packets sent
// straight to peers, discovery probes, and all traffic to the relay. Frames
// defined here start with Magic so they can never be mistaken for a WireGuard
// message, whose first byte is always 1-4.
//
//	byte 0   Magic (0x4C)
//	byte 1   frame type
//	...      type-specific body
//
// Relay binding is a four-step exchange that proves two things before the
// relay will forward anything for a client: that the client really receives
// packets at the address it sends from (the cookie), and that the control
// server authorised it for this room (the MAC keyed by the session key).
//
//	client → relay  BindRequest    txid, claims
//	relay → client  BindChallenge  txid, cookie            (stateless)
//	client → relay  BindConfirm    txid, claims, cookie, mac
//	relay → client  BindAck        txid, observed address, mac
//
// Because the cookie is bound to the sender's address, a captured BindConfirm
// replayed from elsewhere is rejected, so a relay session cannot be hijacked
// by replay. The observed address in the ack is the client's public address
// as seen by the relay, which is what peers need for UDP hole punching.
const Magic byte = 0x4C

// Frame types.
const (
	FrameBindRequest   byte = 0x01
	FrameBindChallenge byte = 0x02
	FrameBindConfirm   byte = 0x03
	FrameBindAck       byte = 0x04
	FrameBindReject    byte = 0x05

	FrameRelaySend    byte = 0x10 // client → relay: forward payload to a peer
	FrameRelayRecv    byte = 0x11 // relay → client: payload from a peer
	FrameRelayUnbound byte = 0x12 // relay → client: no session for your address

	FrameDisco byte = 0x20 // peer ↔ peer path probe (direct or inside a relay frame)

	FrameProbe      byte = 0x30 // unauthenticated address probe (NAT detection, health)
	FrameProbeReply byte = 0x31
)

// Field and frame sizes in bytes.
const (
	HeaderLen = 2
	TxIDLen   = 8
	ClaimsLen = 20
	CookieLen = 16
	MACLen    = 16
	AddrLen   = 18
	PeerIDLen = 4

	BindRequestLen   = HeaderLen + TxIDLen + ClaimsLen
	BindChallengeLen = HeaderLen + TxIDLen + CookieLen
	BindConfirmLen   = HeaderLen + TxIDLen + ClaimsLen + CookieLen + MACLen
	BindAckLen       = HeaderLen + TxIDLen + AddrLen + MACLen
	BindRejectLen    = HeaderLen + TxIDLen + 1

	// RelayHeaderLen is the overhead of a relayed packet: header plus the
	// 4-byte peer (destination when sending, source when receiving).
	RelayHeaderLen = HeaderLen + PeerIDLen

	// ProbeLen is the size of both a probe and its reply. Requests are padded
	// to the reply size so the relay never sends more bytes than it received
	// and cannot be used to amplify traffic towards a spoofed address.
	ProbeLen = HeaderLen + TxIDLen + AddrLen

	DiscoNonceLen  = 24
	DiscoHeaderLen = HeaderLen + PeerIDLen + DiscoNonceLen
	DiscoTxIDLen   = 12
	DiscoPingLen   = 1 + DiscoTxIDLen
	DiscoPongLen   = 1 + DiscoTxIDLen + AddrLen
)

// Bind reject reasons.
const (
	RejectExpired byte = 1 // ticket expired: ask the control server for a new one
	RejectInvalid byte = 2 // ticket or MAC invalid
	RejectBusy    byte = 3 // relay is at capacity
)

// Discovery message types (first byte of the sealed payload).
const (
	DiscoPing byte = 1
	DiscoPong byte = 2
)

// PeerID is a member's identifier inside a room on the wire: its IPv4 virtual
// address.
type PeerID [PeerIDLen]byte

// PeerIDOf converts a virtual IPv4 address to a PeerID.
func PeerIDOf(ip netip.Addr) PeerID { return ip.As4() }

// Addr converts a PeerID back to the virtual address.
func (p PeerID) Addr() netip.Addr { return netip.AddrFrom4(p) }

// IsFrame reports whether b is a Lanora frame rather than a WireGuard packet.
func IsFrame(b []byte) bool { return len(b) >= HeaderLen && b[0] == Magic }

// PutAddrPort encodes ap into b[:AddrLen] as a 16-byte address (IPv4 is
// stored IPv4-mapped) followed by a big-endian port.
func PutAddrPort(b []byte, ap netip.AddrPort) {
	a16 := ap.Addr().As16()
	copy(b[:16], a16[:])
	binary.BigEndian.PutUint16(b[16:18], ap.Port())
}

// GetAddrPort decodes an address written by PutAddrPort.
func GetAddrPort(b []byte) netip.AddrPort {
	var a16 [16]byte
	copy(a16[:], b[:16])
	return netip.AddrPortFrom(netip.AddrFrom16(a16).Unmap(), binary.BigEndian.Uint16(b[16:18]))
}

// Claims is the body of a relay ticket: which room and which member the
// bearer may act as, and until when. The control server hands a client its
// claims together with the session key derived from them.
type Claims struct {
	Room   uint64
	Peer   PeerID
	Expiry int64 // Unix seconds
}

// Bytes encodes the claims.
func (c Claims) Bytes() []byte {
	b := make([]byte, ClaimsLen)
	binary.BigEndian.PutUint64(b[0:8], c.Room)
	copy(b[8:12], c.Peer[:])
	binary.BigEndian.PutUint64(b[12:20], uint64(c.Expiry))
	return b
}

// ErrShortFrame is returned when a frame is too short for its type.
var ErrShortFrame = errors.New("proto: short frame")

// ParseClaims decodes claims written by Claims.Bytes.
func ParseClaims(b []byte) (Claims, error) {
	if len(b) < ClaimsLen {
		return Claims{}, ErrShortFrame
	}
	var c Claims
	c.Room = binary.BigEndian.Uint64(b[0:8])
	copy(c.Peer[:], b[8:12])
	c.Expiry = int64(binary.BigEndian.Uint64(b[12:20]))
	return c, nil
}

// RelaySessionKey derives the per-ticket MAC key from the secret shared by
// the control server and its relays. A relay recomputes it from the claims,
// so relays keep no per-client state until a client has proven itself.
func RelaySessionKey(secret, claims []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("lanora relay session v1"))
	m.Write(claims)
	return m.Sum(nil)
}

// frameMAC returns the truncated HMAC-SHA256 of data.
func frameMAC(key, data []byte) [MACLen]byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	var out [MACLen]byte
	copy(out[:], m.Sum(nil))
	return out
}

// TxID identifies one bind or probe exchange.
type TxID [TxIDLen]byte

// NewTxID returns a random transaction ID.
func NewTxID() TxID {
	var t TxID
	copy(t[:], RandomBytes(TxIDLen))
	return t
}

func header(b []byte, typ byte) []byte { return append(b, Magic, typ) }

// AppendBindRequest appends a BindRequest frame to b.
func AppendBindRequest(b []byte, tx TxID, claims []byte) []byte {
	b = header(b, FrameBindRequest)
	b = append(b, tx[:]...)
	return append(b, claims[:ClaimsLen]...)
}

// AppendBindChallenge appends a BindChallenge frame to b.
func AppendBindChallenge(b []byte, tx TxID, cookie [CookieLen]byte) []byte {
	b = header(b, FrameBindChallenge)
	b = append(b, tx[:]...)
	return append(b, cookie[:]...)
}

// AppendBindConfirm appends a BindConfirm frame, authenticated with key.
func AppendBindConfirm(b []byte, tx TxID, claims []byte, cookie [CookieLen]byte, key []byte) []byte {
	start := len(b)
	b = header(b, FrameBindConfirm)
	b = append(b, tx[:]...)
	b = append(b, claims[:ClaimsLen]...)
	b = append(b, cookie[:]...)
	mac := frameMAC(key, b[start:])
	return append(b, mac[:]...)
}

// AppendBindAck appends a BindAck frame, authenticated with key.
func AppendBindAck(b []byte, tx TxID, observed netip.AddrPort, key []byte) []byte {
	start := len(b)
	b = header(b, FrameBindAck)
	b = append(b, tx[:]...)
	var addr [AddrLen]byte
	PutAddrPort(addr[:], observed)
	b = append(b, addr[:]...)
	mac := frameMAC(key, b[start:])
	return append(b, mac[:]...)
}

// AppendBindReject appends a BindReject frame to b.
func AppendBindReject(b []byte, tx TxID, reason byte) []byte {
	b = header(b, FrameBindReject)
	b = append(b, tx[:]...)
	return append(b, reason)
}

// VerifyMAC checks the trailing MAC of a BindConfirm or BindAck frame.
func VerifyMAC(frame, key []byte) bool {
	if len(frame) < HeaderLen+MACLen {
		return false
	}
	body, got := frame[:len(frame)-MACLen], frame[len(frame)-MACLen:]
	want := frameMAC(key, body)
	return hmac.Equal(got, want[:])
}

// FrameTxID extracts the transaction ID that follows the header of bind and
// probe frames. The caller must have checked the frame length.
func FrameTxID(frame []byte) TxID {
	var t TxID
	copy(t[:], frame[HeaderLen:HeaderLen+TxIDLen])
	return t
}

// AppendProbe appends an address probe, padded to the size of its reply.
func AppendProbe(b []byte, tx TxID) []byte {
	b = header(b, FrameProbe)
	b = append(b, tx[:]...)
	return append(b, make([]byte, AddrLen)...)
}

// AppendProbeReply appends a probe reply carrying the observed address.
func AppendProbeReply(b []byte, tx TxID, observed netip.AddrPort) []byte {
	b = header(b, FrameProbeReply)
	b = append(b, tx[:]...)
	var addr [AddrLen]byte
	PutAddrPort(addr[:], observed)
	return append(b, addr[:]...)
}

// AppendRelaySend appends the header of a client → relay data frame. The
// payload follows it directly.
func AppendRelaySend(b []byte, dst PeerID) []byte {
	b = header(b, FrameRelaySend)
	return append(b, dst[:]...)
}

// RelayPeer returns the peer field of a relay data frame. The caller must
// have checked that the frame is at least RelayHeaderLen long.
func RelayPeer(frame []byte) PeerID {
	var p PeerID
	copy(p[:], frame[HeaderLen:RelayHeaderLen])
	return p
}

// StreamAuthorization returns the Authorization header value a client sends
// to bind to the relay over its TCP fallback. The session key is presented
// as a bearer credential; unlike the UDP exchange this always travels inside
// TLS.
func StreamAuthorization(claims, key []byte) string {
	enc := base64.RawURLEncoding
	return "Bearer " + enc.EncodeToString(claims) + "." + enc.EncodeToString(key)
}

// SealDisco appends a discovery frame to b. The payload is encrypted and
// authenticated with NaCl box using the precomputed shared key of the two
// peers' discovery keys, so only the addressed peer can read it and nobody
// else can forge it.
func SealDisco(b []byte, sender PeerID, shared *[32]byte, payload []byte) []byte {
	b = header(b, FrameDisco)
	b = append(b, sender[:]...)
	var nonce [DiscoNonceLen]byte
	copy(nonce[:], RandomBytes(DiscoNonceLen))
	b = append(b, nonce[:]...)
	return box.SealAfterPrecomputation(b, payload, &nonce, shared)
}

// DiscoSender returns the claimed sender of a discovery frame, or false if
// the frame is not a well-formed discovery frame. The claim is only trusted
// once OpenDisco succeeds with that sender's key.
func DiscoSender(frame []byte) (PeerID, bool) {
	if len(frame) < DiscoHeaderLen+box.Overhead+1 || frame[0] != Magic || frame[1] != FrameDisco {
		return PeerID{}, false
	}
	return RelayPeer(frame), true
}

// OpenDisco authenticates and decrypts a discovery frame, appending the
// payload to out.
func OpenDisco(out, frame []byte, shared *[32]byte) ([]byte, bool) {
	if len(frame) < DiscoHeaderLen+box.Overhead+1 {
		return nil, false
	}
	var nonce [DiscoNonceLen]byte
	copy(nonce[:], frame[RelayHeaderLen:DiscoHeaderLen])
	return box.OpenAfterPrecomputation(out, frame[DiscoHeaderLen:], &nonce, shared)
}

// DiscoTxID identifies one ping/pong exchange.
type DiscoTxID [DiscoTxIDLen]byte

// NewDiscoTxID returns a random discovery transaction ID.
func NewDiscoTxID() DiscoTxID {
	var t DiscoTxID
	copy(t[:], RandomBytes(DiscoTxIDLen))
	return t
}

// AppendDiscoPing appends the plaintext of a ping.
func AppendDiscoPing(b []byte, tx DiscoTxID) []byte {
	b = append(b, DiscoPing)
	return append(b, tx[:]...)
}

// AppendDiscoPong appends the plaintext of a pong. observed is the address
// the ping arrived from, which tells the pinger its own public mapping.
func AppendDiscoPong(b []byte, tx DiscoTxID, observed netip.AddrPort) []byte {
	b = append(b, DiscoPong)
	b = append(b, tx[:]...)
	var addr [AddrLen]byte
	PutAddrPort(addr[:], observed)
	return append(b, addr[:]...)
}

// ParseDisco decodes a decrypted discovery payload.
func ParseDisco(payload []byte) (typ byte, tx DiscoTxID, observed netip.AddrPort, ok bool) {
	if len(payload) < DiscoPingLen {
		return 0, tx, observed, false
	}
	typ = payload[0]
	copy(tx[:], payload[1:1+DiscoTxIDLen])
	switch typ {
	case DiscoPing:
		return typ, tx, observed, true
	case DiscoPong:
		if len(payload) < DiscoPongLen {
			return 0, tx, observed, false
		}
		return typ, tx, GetAddrPort(payload[1+DiscoTxIDLen:]), true
	}
	return 0, tx, observed, false
}
