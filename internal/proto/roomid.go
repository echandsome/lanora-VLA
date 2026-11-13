package proto

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"unicode"
)

// Room IDs are nine characters from Crockford's base32 alphabet, which leaves
// out I, L, O and U so that an ID read aloud or copied by hand cannot be
// mistyped into another valid ID. They are shown grouped as "7KQ-2MX-9DW".
const (
	roomIDAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	RoomIDLen      = 9
)

// Generated passwords avoid look-alike characters (0/o, 1/l/i).
const passwordAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// Limits applied to user-supplied text.
const (
	MinPasswordLen = 8
	MaxPasswordLen = 128
	MaxNicknameLen = 32
	MaxRoomNameLen = 64
	MaxRoomDescLen = 280
)

// ErrBadRoomID is returned for a room ID that cannot be normalised.
var ErrBadRoomID = errors.New("proto: room ID must be 9 letters or digits")

// NormalizeRoomID converts user input ("7kq-2mx 9dw") to the canonical form
// ("7KQ2MX9DW"), mapping the letters people substitute by mistake.
func NormalizeRoomID(s string) (string, error) {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '-' || r == '_' || unicode.IsSpace(r):
			continue
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		}
		switch r {
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if r > unicode.MaxASCII || !strings.ContainsRune(roomIDAlphabet, r) {
			return "", ErrBadRoomID
		}
		b.WriteRune(r)
		if b.Len() > RoomIDLen {
			return "", ErrBadRoomID
		}
	}
	if b.Len() != RoomIDLen {
		return "", ErrBadRoomID
	}
	return b.String(), nil
}

// FormatRoomID groups a canonical room ID for display.
func FormatRoomID(id string) string {
	if len(id) != RoomIDLen {
		return id
	}
	return id[0:3] + "-" + id[3:6] + "-" + id[6:9]
}

// NewRoomID returns a random canonical room ID (45 bits of entropy).
func NewRoomID() string { return randomString(roomIDAlphabet, RoomIDLen) }

// NewRoomPassword returns a random password in four dash-separated groups,
// about 79 bits of entropy. The dashes are part of the password.
func NewRoomPassword() string {
	raw := randomString(passwordAlphabet, 16)
	return raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:16]
}

func randomString(alphabet string, n int) string {
	max := big.NewInt(int64(len(alphabet)))
	out := make([]byte, n)
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic("proto: system random source failed: " + err.Error())
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out)
}

// CleanNickname trims a nickname, removes control characters and collapses
// runs of whitespace. It returns "" when nothing printable is left.
func CleanNickname(s string) string {
	return cleanText(s, MaxNicknameLen)
}

// CleanText applies the nickname rules with a caller-chosen length limit; it
// is used for room names and descriptions.
func CleanText(s string, maxRunes int) string { return cleanText(s, maxRunes) }

func cleanText(s string, maxRunes int) string {
	var b strings.Builder
	space := false
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if !unicode.IsPrint(r) {
			continue
		}
		if space && n > 0 {
			if n+1 >= maxRunes {
				break
			}
			b.WriteByte(' ')
			n++
		}
		space = false
		if n >= maxRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
