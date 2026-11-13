// Package ipc is the local channel between the Lanora window and the Lanora
// service.
//
// On Windows the network engine runs in a service and the window is an
// ordinary unprivileged program; they talk over a named pipe. Keeping every
// socket in the service is deliberate: socket-layer hooks installed by other
// software (Astrill VPN's among them) are loaded into ordinary programs but
// not into services, so the engine's traffic is never intercepted or
// crashed by one. On other systems the same protocol runs over a Unix
// socket.
//
// The protocol is one JSON object per line. The window sends requests; the
// service answers each one and, unprompted, sends a status event whenever
// anything changes.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"lanora/internal/client/settings"
)

// Operations.
const (
	OpStatus      = "status"
	OpConnect     = "connect"
	OpDisconnect  = "disconnect"
	OpSettings    = "settings"
	OpDiagnostics = "diagnostics"
)

// EventStatus is the name of the status event.
const EventStatus = "status"

// maxLine bounds one protocol line (the diagnostics report is the longest).
const maxLine = 1 << 20

// Request is sent by the window.
type Request struct {
	ID   uint64          `json:"id"`
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Response is sent by the service: the answer to the request with the same
// ID, or (ID zero, Event set) an event.
type Response struct {
	ID     uint64          `json:"id,omitempty"`
	Event  string          `json:"event,omitempty"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Status is everything the window shows.
type Status struct {
	Version     string            `json:"version"`
	Hostname    string            `json:"hostname"`
	Connection  Connection        `json:"connection"`
	Settings    settings.Settings `json:"settings"`
	HasPassword bool              `json:"has_password"` // a password is remembered for Settings.RoomID
}

// Connection phases, as in package engine.
const (
	PhaseIdle         = "idle"
	PhaseConnecting   = "connecting"
	PhaseConnected    = "connected"
	PhaseReconnecting = "reconnecting"
	PhaseStopped      = "stopped"
)

// Connection describes the room connection.
type Connection struct {
	Phase     string `json:"phase"`
	Detail    string `json:"detail,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`

	RoomID   string    `json:"room_id,omitempty"`
	RoomName string    `json:"room_name,omitempty"`
	Subnet   string    `json:"subnet,omitempty"`
	IP       string    `json:"ip,omitempty"`
	Nickname string    `json:"nickname,omitempty"`
	Since    time.Time `json:"since,omitzero"`

	Peers      []Peer `json:"peers"`
	Relay      string `json:"relay,omitempty"` // "udp", "tcp" or "" when unreachable
	PublicAddr string `json:"public_addr,omitempty"`
	Rx         uint64 `json:"rx"`
	Tx         uint64 `json:"tx"`
}

// Active reports whether a connection exists or is being made.
func (c Connection) Active() bool {
	return c.Phase == PhaseConnecting || c.Phase == PhaseConnected || c.Phase == PhaseReconnecting
}

// Peer is another member of the room.
type Peer struct {
	IP       string `json:"ip"`
	Nickname string `json:"nickname"`
	Via      string `json:"via"` // "direct", "relay" or "none"
	Addr     string `json:"addr,omitempty"`
	RTTms    int    `json:"rtt_ms"` // -1 when not measured yet
}

// ConnectArgs are the arguments of OpConnect. An empty Password means "use
// the remembered one".
type ConnectArgs struct {
	Server   string `json:"server"`
	RoomID   string `json:"room_id"`
	Password string `json:"password"`
	Nickname string `json:"nickname"`
	Remember bool   `json:"remember"`
}

// SettingsArgs are the arguments of OpSettings; nil fields are unchanged.
type SettingsArgs struct {
	Server         *string `json:"server,omitempty"`
	AutoConnect    *bool   `json:"auto_connect,omitempty"`
	LANPriority    *bool   `json:"lan_priority,omitempty"`
	PrivateNetwork *bool   `json:"private_network,omitempty"`
	RelayOnly      *bool   `json:"relay_only,omitempty"`
}

// ErrClosed is returned by calls on a client whose connection has ended.
var ErrClosed = errors.New("the connection to the Lanora service was lost")

// Client is the window's end of the channel.
type Client struct {
	conn net.Conn
	enc  *json.Encoder

	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]chan Response

	events chan Status
	done   chan struct{}
}

// Dial connects to the service.
func Dial(ctx context.Context) (*Client, error) {
	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	return NewClient(conn), nil
}

// NewClient wraps an established connection.
func NewClient(conn net.Conn) *Client {
	c := &Client{
		conn:    conn,
		enc:     json.NewEncoder(conn),
		pending: make(map[uint64]chan Response),
		events:  make(chan Status, 1),
		done:    make(chan struct{}),
	}
	go c.read()
	return c
}

func (c *Client) read() {
	defer func() {
		close(c.done)
		c.conn.Close()
		c.mu.Lock()
		for id, ch := range c.pending {
			close(ch)
			delete(c.pending, id)
		}
		c.mu.Unlock()
	}()
	sc := bufio.NewScanner(c.conn)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		var r Response
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		if r.Event == EventStatus {
			var st Status
			if json.Unmarshal(r.Result, &st) != nil {
				continue
			}
			// Only the newest status matters: replace one that has not
			// been picked up yet.
			select {
			case c.events <- st:
			default:
				select {
				case <-c.events:
				default:
				}
				select {
				case c.events <- st:
				default:
				}
			}
			continue
		}
		c.mu.Lock()
		ch := c.pending[r.ID]
		delete(c.pending, r.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- r
		}
	}
}

// Events delivers status updates pushed by the service. Only the most recent
// undelivered update is kept.
func (c *Client) Events() <-chan Status { return c.events }

// Done is closed when the connection to the service ends.
func (c *Client) Done() <-chan struct{} { return c.done }

// Close ends the connection.
func (c *Client) Close() { c.conn.Close() }

// call performs one request. A failure reported by the service comes back
// as an error whose text is meant for the user.
func (c *Client) call(ctx context.Context, op string, args, result any) error {
	var raw json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return err
		}
		raw = b
	}
	ch := make(chan Response, 1)
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.pending[id] = ch
	err := c.enc.Encode(Request{ID: id, Op: op, Args: raw})
	c.mu.Unlock()
	if err != nil {
		return ErrClosed
	}
	select {
	case r, ok := <-ch:
		if !ok {
			return ErrClosed
		}
		if r.Error != "" {
			return errors.New(r.Error)
		}
		if result != nil {
			return json.Unmarshal(r.Result, result)
		}
		return nil
	case <-c.done:
		return ErrClosed
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	}
}

// Status returns the current status.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	err := c.call(ctx, OpStatus, nil, &st)
	return st, err
}

// Connect asks the service to join a room. It returns once the attempt has
// started; progress and the outcome arrive as status events.
func (c *Client) Connect(ctx context.Context, args ConnectArgs) error {
	return c.call(ctx, OpConnect, args, nil)
}

// Disconnect leaves the room.
func (c *Client) Disconnect(ctx context.Context) error {
	return c.call(ctx, OpDisconnect, nil, nil)
}

// UpdateSettings changes preferences and returns the resulting status.
func (c *Client) UpdateSettings(ctx context.Context, args SettingsArgs) (Status, error) {
	var st Status
	err := c.call(ctx, OpSettings, args, &st)
	return st, err
}

// Diagnostics returns a plain-text report about the service's view of the
// machine's network, for troubleshooting.
func (c *Client) Diagnostics(ctx context.Context) (string, error) {
	var text string
	err := c.call(ctx, OpDiagnostics, nil, &text)
	return text, err
}
