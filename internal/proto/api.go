package proto

import (
	"fmt"
	"net/netip"
)

// HTTP API paths used by clients.
const (
	PathHello   = "/api/v1/hello"
	PathJoin    = "/api/v1/join"
	PathSession = "/api/v1/session"
	PathRelay   = "/api/v1/relay"
)

// HelloResponse is returned by GET /api/v1/hello. It lets a client check
// compatibility before it sends any credentials and carries the single-use
// nonce that the join request must sign.
type HelloResponse struct {
	Server    string `json:"server"`
	Version   string `json:"version"`
	Protocol  int    `json:"protocol"`
	MinClient string `json:"min_client"`
	Nonce     string `json:"nonce"`
	Time      int64  `json:"time"`
}

// JoinRequest is the body of POST /api/v1/join.
//
// Identity is the device's long-lived Ed25519 public key. Signature is made
// with the matching private key over JoinTranscript, which proves possession
// of the key so that one room member cannot claim another member's device
// identity (and with it that member's virtual IP address).
type JoinRequest struct {
	RoomID        string `json:"room_id"`
	Password      string `json:"password"`
	Nickname      string `json:"nickname"`
	Identity      Key32  `json:"identity"`
	Nonce         string `json:"nonce"`
	Signature     []byte `json:"signature"`
	ClientVersion string `json:"client_version"`
	Protocol      int    `json:"protocol"`
	Platform      string `json:"platform"`
}

// JoinTranscript returns the byte string a client signs to join a room.
func JoinTranscript(nonce, roomID string, identity Key32) []byte {
	return fmt.Appendf(nil, "lanora-join-v1\n%s\n%s\n%s\n", nonce, roomID, identity.String())
}

// RoomInfo describes the virtual network of a room.
type RoomInfo struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Subnet      netip.Prefix `json:"subnet"`
	MTU         int          `json:"mtu"`
	Capacity    int          `json:"capacity"`
}

// JoinResponse is returned by a successful join. Token authenticates the
// session WebSocket and can be reused to reconnect until it expires.
type JoinResponse struct {
	Token     string     `json:"token"`
	ExpiresAt int64      `json:"expires_at"`
	Room      RoomInfo   `json:"room"`
	IP        netip.Addr `json:"ip"`
	Nickname  string     `json:"nickname"`
}

// ErrorCode is a stable, machine-readable failure reason.
type ErrorCode string

const (
	CodeBadRequest         ErrorCode = "bad_request"
	CodeInvalidCredentials ErrorCode = "invalid_credentials"
	CodeRoomFull           ErrorCode = "room_full"
	CodeRoomDisabled       ErrorCode = "room_disabled"
	CodeBanned             ErrorCode = "banned"
	CodeKicked             ErrorCode = "kicked"
	CodeRateLimited        ErrorCode = "rate_limited"
	CodeClientTooOld       ErrorCode = "client_too_old"
	CodeUnauthorized       ErrorCode = "unauthorized"
	CodeForbidden          ErrorCode = "forbidden"
	CodeNotFound           ErrorCode = "not_found"
	CodeConflict           ErrorCode = "conflict"
	CodeReplaced           ErrorCode = "replaced"
	CodeRoomClosed         ErrorCode = "room_closed"
	CodeServerError        ErrorCode = "server_error"
	CodeUnavailable        ErrorCode = "unavailable"
)

// ErrorResponse is the JSON body of every non-2xx API response.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody carries the failure reason. RetryAfter is in seconds and is only
// set for rate-limit responses.
type ErrorBody struct {
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	RetryAfter int       `json:"retry_after,omitempty"`
}

// APIError is the Go error form of an ErrorBody.
type APIError struct {
	Status int
	ErrorBody
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return string(e.Code)
}

// Fatal reports whether retrying with the same credentials cannot succeed, so
// an automatic reconnect loop must stop and tell the user.
func (c ErrorCode) Fatal() bool {
	switch c {
	case CodeInvalidCredentials, CodeBanned, CodeKicked, CodeRoomDisabled,
		CodeClientTooOld, CodeReplaced, CodeRoomClosed, CodeBadRequest, CodeForbidden:
		return true
	}
	return false
}
