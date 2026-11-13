package proto

import "net/netip"

// Signalling message types. Every message on the session WebSocket is one
// JSON-encoded Msg whose T field is one of these.
const (
	// Client → server.
	MsgHello     = "hello"     // first message: session keys
	MsgEndpoints = "endpoints" // the client's current UDP candidates
	MsgPunch     = "punch"     // ask a peer to probe our candidates now
	MsgStatus    = "status"    // periodic path report for the dashboard

	// Server → client.
	MsgWelcome    = "welcome"     // full room state after hello
	MsgPeerJoined = "peer_joined" // a peer came online (or changed keys)
	MsgPeerLeft   = "peer_left"   // a peer went offline
	MsgPeerUpdate = "peer_update" // a peer's candidates changed
	MsgRelay      = "relay"       // refreshed relay ticket / relay moved
	MsgBye        = "bye"         // the server is ending the session (see Code)
)

// MaxSignalMessage bounds a signalling message sent by a client, in bytes.
const MaxSignalMessage = 64 << 10

// MaxServerMessage bounds a signalling message sent by the server. It is
// much larger because the welcome message lists every member of the room.
const MaxServerMessage = 4 << 20

// MaxEndpoints bounds how many UDP candidates a peer may advertise.
const MaxEndpoints = 12

// Msg is the envelope for all signalling messages. Only the fields relevant
// to the message type are set.
type Msg struct {
	T string `json:"t"`

	// hello
	WGPub    *Key32 `json:"wg_pub,omitempty"`
	DiscoPub *Key32 `json:"disco_pub,omitempty"`

	// hello, endpoints, punch (forwarded: the sender's candidates)
	Endpoints []netip.AddrPort `json:"endpoints,omitempty"`

	// punch
	To   *netip.Addr `json:"to,omitempty"`
	From *netip.Addr `json:"from,omitempty"`

	// welcome
	Epoch string     `json:"epoch,omitempty"`
	Self  *Peer      `json:"self,omitempty"`
	Room  *RoomInfo  `json:"room,omitempty"`
	Peers []Peer     `json:"peers,omitempty"`
	Relay *RelayInfo `json:"relay,omitempty"`

	// peer_joined, peer_update
	Peer *Peer `json:"peer,omitempty"`

	// peer_left
	IP *netip.Addr `json:"ip,omitempty"`

	// bye
	Code    ErrorCode `json:"code,omitempty"`
	Message string    `json:"message,omitempty"`

	// status
	Status *StatusReport `json:"status,omitempty"`
}

// A welcome's Epoch identifies one run of the server. When it differs from
// the previous welcome's, the server restarted in between and its member
// list is still filling up as clients reconnect; see the engine for why
// that matters.

// Peer is one online member of a room as seen by the other members. A peer is
// identified inside its room by its virtual IP address.
type Peer struct {
	IP        netip.Addr       `json:"ip"`
	Nickname  string           `json:"nickname"`
	WGPub     Key32            `json:"wg_pub"`
	DiscoPub  Key32            `json:"disco_pub"`
	Endpoints []netip.AddrPort `json:"endpoints,omitempty"`
}

// RelayInfo tells a client how to reach the relay assigned to its room and
// gives it the credentials to bind there.
//
// UDP entries are "host:port". An empty host (":8443") means "the host the
// control connection was made to". WS is the URL of the TCP fallback relay;
// a relative path is resolved against the control server URL.
type RelayInfo struct {
	UDP       []string `json:"udp"`
	WS        string   `json:"ws,omitempty"`
	Claims    []byte   `json:"claims"`
	Key       []byte   `json:"key"`
	ExpiresAt int64    `json:"expires_at"`
}

// How a client currently reaches a peer, as reported in a StatusReport.
const (
	ViaDirect = "direct" // straight UDP between the two peers
	ViaRelay  = "relay"  // through the relay
	ViaNone   = "none"   // no working path yet
)

// StatusReport is a client's summary of how it currently reaches each peer.
type StatusReport struct {
	Peers []PeerStatus `json:"peers"`
	Rx    uint64       `json:"rx"`
	Tx    uint64       `json:"tx"`
}

// PeerStatus is one row of a StatusReport. Via is one of the Via* constants.
// RTT is in milliseconds; -1 means not measured yet.
type PeerStatus struct {
	IP  netip.Addr `json:"ip"`
	Via string     `json:"via"`
	RTT int        `json:"rtt"`
}
