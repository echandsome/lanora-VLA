// Package hub keeps the live state of every room: who is connected, how each
// member can be reached, and the signalling channel to each of them.
//
// Nothing here touches the database. Presence and endpoints change far more
// often than durable data and are worthless after a restart (clients simply
// reconnect and repopulate them), so they live in memory, partitioned by
// room: activity in one room never contends with another.
package hub

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"lanora/internal/proto"
)

// Errors returned by Join.
var (
	ErrRoomFull = errors.New("hub: room is full")
	ErrClosed   = errors.New("hub: shutting down")
)

const (
	// sendQueue is how many signalling messages may be waiting for one
	// client. A client that falls this far behind is disconnected; it will
	// reconnect and receive the complete room state again.
	sendQueue = 256

	// Relay tickets are short-lived and renewed while the session lasts.
	ticketRenewBefore = 10 * time.Minute

	// Limits on what one member can make the server send to the others.
	// Without them a single member could fill its peers' queues and get them
	// disconnected. A punch is advisory, so each sender may ask each target
	// only once per interval; endpoint updates are state, so a sender gets a
	// small burst (network changes come in clusters) and a slow refill.
	punchInterval      = time.Second
	endpointBurst      = 8
	endpointsPerSecond = 0.5
)

// Relays hands out relay credentials. It is implemented by relay.Directory.
type Relays interface {
	Ticket(room int64, peer netip.Addr) proto.RelayInfo
	Revoke(room int64, peer netip.Addr)
	RevokeRoom(room int64)
}

// EventFunc records an entry in the server's event log.
type EventFunc func(level, kind string, roomID, memberID int64, actor, addr, message string)

// Options configures a Hub.
type Options struct {
	Relays Relays
	Events EventFunc
	// OnLeave is called (outside any lock) after a member disconnects.
	OnLeave func(memberID int64)
	Logger  *slog.Logger
}

// Hub is the registry of live rooms.
type Hub struct {
	opts  Options
	log   *slog.Logger
	epoch string // identifies this run of the server to clients

	mu     sync.RWMutex
	rooms  map[int64]*room
	closed bool

	online atomic.Int64

	subMu sync.Mutex
	subs  map[chan struct{}]struct{}
}

type room struct {
	id       int64
	mu       sync.Mutex
	info     proto.RoomInfo
	sessions map[netip.Addr]*Session
	dead     bool // removed from the hub; a concurrent Join must retry
}

// MemberInfo identifies the device behind a session.
type MemberInfo struct {
	ID            int64
	IP            netip.Addr
	Nickname      string
	Identity      proto.Key32
	Platform      string
	ClientVersion string
}

// JoinParams holds the inputs for Join.
type JoinParams struct {
	RoomID     int64
	Room       proto.RoomInfo
	Member     MemberInfo
	WGPub      proto.Key32
	DiscoPub   proto.Key32
	Endpoints  []netip.AddrPort
	RemoteAddr string
}

// Session is one connected member.
type Session struct {
	hub  *Hub
	room *room

	Member      MemberInfo
	RemoteAddr  string
	ConnectedAt time.Time

	wgPub    proto.Key32
	discoPub proto.Key32

	// Guarded by room.mu.
	endpoints    []netip.AddrPort
	ticketExpiry int64

	out  chan []byte
	done chan struct{}
	once sync.Once
	bye  atomic.Pointer[proto.Msg]

	status atomic.Pointer[proto.StatusReport]

	limitMu        sync.Mutex
	punched        map[netip.Addr]time.Time // last punch sent to each peer
	endpointTokens float64
	endpointLast   time.Time
}

// New returns an empty hub.
func New(opts Options) *Hub {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Events == nil {
		opts.Events = func(string, string, int64, int64, string, string, string) {}
	}
	return &Hub{
		opts:  opts,
		log:   opts.Logger.With("component", "hub"),
		epoch: hex.EncodeToString(proto.RandomBytes(8)),
		rooms: make(map[int64]*room),
		subs:  make(map[chan struct{}]struct{}),
	}
}

// Join registers a member's session and queues its welcome message. If the
// same member already has a session (it reconnected before the old
// connection was noticed dead, or the device started twice), the old one is
// replaced.
func (h *Hub) Join(p JoinParams) (*Session, error) {
	s := &Session{
		hub:            h,
		Member:         p.Member,
		RemoteAddr:     p.RemoteAddr,
		ConnectedAt:    time.Now(),
		wgPub:          p.WGPub,
		discoPub:       p.DiscoPub,
		endpoints:      sanitizeEndpoints(p.Endpoints, p.Room.Subnet),
		out:            make(chan []byte, sendQueue),
		done:           make(chan struct{}),
		endpointTokens: endpointBurst,
		endpointLast:   time.Now(),
	}

	for {
		r, err := h.roomFor(p.RoomID, p.Room)
		if err != nil {
			return nil, err
		}
		r.mu.Lock()
		if r.dead {
			r.mu.Unlock()
			continue
		}
		old := r.sessions[p.Member.IP]
		if old == nil && len(r.sessions) >= p.Room.Capacity {
			r.mu.Unlock()
			return nil, ErrRoomFull
		}
		r.info = p.Room
		s.room = r

		peers := make([]proto.Peer, 0, len(r.sessions))
		for ip, other := range r.sessions {
			if ip != p.Member.IP {
				peers = append(peers, other.peerLocked())
			}
		}
		sort.Slice(peers, func(i, j int) bool { return peers[i].IP.Less(peers[j].IP) })

		relay := h.opts.Relays.Ticket(r.id, p.Member.IP)
		s.ticketExpiry = relay.ExpiresAt
		self := s.peerLocked()
		s.queue(encode(proto.Msg{T: proto.MsgWelcome, Epoch: h.epoch, Self: &self, Room: &r.info, Peers: peers, Relay: &relay}))

		r.sessions[p.Member.IP] = s
		joined := encode(proto.Msg{T: proto.MsgPeerJoined, Peer: &self})
		for ip, other := range r.sessions {
			if ip != p.Member.IP {
				other.queue(joined)
			}
		}
		r.mu.Unlock()

		if old != nil {
			old.end(proto.CodeReplaced, "This device connected to the room again from another session.")
		} else {
			h.online.Add(1)
		}
		h.opts.Events("info", "room.join", r.id, p.Member.ID, p.Member.Nickname, p.RemoteAddr,
			p.Member.Nickname+" joined as "+p.Member.IP.String())
		h.notify()
		return s, nil
	}
}

func (h *Hub) roomFor(id int64, info proto.RoomInfo) (*room, error) {
	h.mu.RLock()
	r, closed := h.rooms[id], h.closed
	h.mu.RUnlock()
	if closed {
		return nil, ErrClosed
	}
	if r != nil {
		return r, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, ErrClosed
	}
	if r = h.rooms[id]; r == nil {
		r = &room{id: id, info: info, sessions: make(map[netip.Addr]*Session)}
		h.rooms[id] = r
	}
	return r, nil
}

// dropIfEmpty removes a room that has no sessions left.
func (h *Hub) dropIfEmpty(r *room) {
	h.mu.Lock()
	r.mu.Lock()
	if len(r.sessions) == 0 && !r.dead {
		r.dead = true
		delete(h.rooms, r.id)
	}
	r.mu.Unlock()
	h.mu.Unlock()
}

// Leave removes a session after its connection ended. It is safe to call
// more than once.
func (h *Hub) Leave(s *Session) {
	s.close()
	r := s.room
	r.mu.Lock()
	current := r.sessions[s.Member.IP] == s
	if current {
		delete(r.sessions, s.Member.IP)
		ip := s.Member.IP
		left := encode(proto.Msg{T: proto.MsgPeerLeft, IP: &ip})
		for _, other := range r.sessions {
			other.queue(left)
		}
	}
	empty := len(r.sessions) == 0
	r.mu.Unlock()

	if !current {
		return // replaced by a newer session, which now owns the member's slot
	}
	h.online.Add(-1)
	if empty {
		h.dropIfEmpty(r)
	}
	// The member's relay session is left alone. If the member is really
	// gone it expires by itself within a minute; if only the signalling
	// connection dropped, the member keeps relaying to its peers while it
	// reconnects. Removal by an administrator revokes it explicitly (see
	// Session.remove).
	h.opts.Events("info", "room.leave", r.id, s.Member.ID, s.Member.Nickname, s.RemoteAddr,
		s.Member.Nickname+" left after "+time.Since(s.ConnectedAt).Round(time.Second).String())
	if h.opts.OnLeave != nil {
		h.opts.OnLeave(s.Member.ID)
	}
	h.notify()
}

// peerLocked returns the session's public description. room.mu must be held
// (or the session not yet shared).
func (s *Session) peerLocked() proto.Peer {
	return proto.Peer{
		IP:        s.Member.IP,
		Nickname:  s.Member.Nickname,
		WGPub:     s.wgPub,
		DiscoPub:  s.discoPub,
		Endpoints: append([]netip.AddrPort(nil), s.endpoints...),
	}
}

// Outbound returns the channel of encoded messages to write to the client.
func (s *Session) Outbound() <-chan []byte { return s.out }

// Done is closed when the session must end. Bye then returns the final
// message to send, if the server is ending the session on purpose.
func (s *Session) Done() <-chan struct{} { return s.done }

// Bye returns the farewell message for a session the server is ending, or
// nil when it simply dropped.
func (s *Session) Bye() *proto.Msg { return s.bye.Load() }

func (s *Session) close() { s.once.Do(func() { close(s.done) }) }

// end terminates the session with a reason the client will be shown.
func (s *Session) end(code proto.ErrorCode, message string) {
	s.bye.CompareAndSwap(nil, &proto.Msg{T: proto.MsgBye, Code: code, Message: message})
	s.close()
}

// remove ends the session because the member is no longer allowed in the
// room, and cuts off its relay access at once rather than when its ticket
// expires.
func (s *Session) remove(code proto.ErrorCode, message string) {
	s.end(code, message)
	s.hub.opts.Relays.Revoke(s.room.id, s.Member.IP)
}

// queue hands a message to the session's writer. A client too slow to keep
// up is dropped rather than allowed to block the room.
func (s *Session) queue(msg []byte) {
	select {
	case s.out <- msg:
	default:
		s.close()
	}
}

// queueAdvisory queues a message the client can do without. It is skipped
// when the client's queue is filling up, keeping room for the messages that
// carry room state, and never causes a disconnect.
func (s *Session) queueAdvisory(msg []byte) {
	if len(s.out) >= sendQueue/2 {
		return
	}
	select {
	case s.out <- msg:
	default:
	}
}

func encode(m proto.Msg) []byte {
	b, err := json.Marshal(m)
	if err != nil {
		panic("hub: cannot encode signalling message: " + err.Error())
	}
	return b
}

// sanitizeEndpoints drops candidates no peer should ever dial: malformed or
// non-unicast addresses, and anything inside the room's own virtual subnet,
// which would route tunnel packets back into the tunnel.
func sanitizeEndpoints(in []netip.AddrPort, subnet netip.Prefix) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, min(len(in), proto.MaxEndpoints))
	seen := make(map[netip.AddrPort]bool, len(in))
	for _, ep := range in {
		a := ep.Addr().Unmap()
		ep = netip.AddrPortFrom(a, ep.Port())
		if !a.IsValid() || ep.Port() == 0 || a.IsUnspecified() || a.IsLoopback() ||
			a.IsMulticast() || a.IsLinkLocalUnicast() || a.Zone() != "" || subnet.Contains(a) || seen[ep] {
			continue
		}
		seen[ep] = true
		out = append(out, ep)
		if len(out) == proto.MaxEndpoints {
			break
		}
	}
	return out
}

// Handle processes a signalling message received from a session's client.
func (h *Hub) Handle(s *Session, m *proto.Msg) {
	switch m.T {
	case proto.MsgEndpoints:
		h.setEndpoints(s, m.Endpoints)
	case proto.MsgPunch:
		if m.To != nil {
			h.punch(s, *m.To)
		}
	case proto.MsgStatus:
		if m.Status != nil && len(m.Status.Peers) <= 1024 {
			s.status.Store(m.Status)
		}
	}
}

func (h *Hub) setEndpoints(s *Session, eps []netip.AddrPort) {
	if !s.allowEndpoints() {
		return
	}
	r := s.room
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[s.Member.IP] != s {
		return
	}
	s.endpoints = sanitizeEndpoints(eps, r.info.Subnet)
	peer := s.peerLocked()
	update := encode(proto.Msg{T: proto.MsgPeerUpdate, Peer: &peer})
	for ip, other := range r.sessions {
		if ip != s.Member.IP {
			other.queue(update)
		}
	}
}

// punch asks another member to start probing the sender's endpoints now, so
// that both sides open their NAT mappings at the same moment.
func (h *Hub) punch(s *Session, to netip.Addr) {
	if !s.allowPunch(to) {
		return
	}
	r := s.room
	r.mu.Lock()
	defer r.mu.Unlock()
	target := r.sessions[to]
	if target == nil || target == s || r.sessions[s.Member.IP] != s {
		return
	}
	from := s.Member.IP
	target.queueAdvisory(encode(proto.Msg{T: proto.MsgPunch, From: &from, Endpoints: append([]netip.AddrPort(nil), s.endpoints...)}))
}

// allowPunch reports whether the session may punch towards a peer now.
func (s *Session) allowPunch(to netip.Addr) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	now := time.Now()
	if last, ok := s.punched[to]; ok && now.Sub(last) < punchInterval {
		return false
	}
	if s.punched == nil {
		s.punched = make(map[netip.Addr]time.Time)
	} else if len(s.punched) > 1024 {
		// Addresses that are not (or no longer) members would otherwise
		// accumulate; starting over only forgets the one-second holds.
		clear(s.punched)
	}
	s.punched[to] = now
	return true
}

// allowEndpoints reports whether the session may publish new endpoints now.
func (s *Session) allowEndpoints() bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	now := time.Now()
	s.endpointTokens = min(endpointBurst, s.endpointTokens+now.Sub(s.endpointLast).Seconds()*endpointsPerSecond)
	s.endpointLast = now
	if s.endpointTokens < 1 {
		return false
	}
	s.endpointTokens--
	return true
}

// RenewTickets sends a fresh relay ticket to every session whose current
// one is close to expiring. The server calls it periodically.
func (h *Hub) RenewTickets(now time.Time) {
	deadline := now.Add(ticketRenewBefore).Unix()
	for _, r := range h.snapshotRooms() {
		r.mu.Lock()
		for ip, s := range r.sessions {
			if s.ticketExpiry > deadline {
				continue
			}
			relay := h.opts.Relays.Ticket(r.id, ip)
			s.ticketExpiry = relay.ExpiresAt
			s.queue(encode(proto.Msg{T: proto.MsgRelay, Relay: &relay}))
		}
		r.mu.Unlock()
	}
}

// RefreshRelays re-issues relay tickets to every session immediately. It is
// used when the set of relay nodes changes and rooms may have moved.
func (h *Hub) RefreshRelays() {
	for _, r := range h.snapshotRooms() {
		r.mu.Lock()
		for ip, s := range r.sessions {
			relay := h.opts.Relays.Ticket(r.id, ip)
			s.ticketExpiry = relay.ExpiresAt
			s.queue(encode(proto.Msg{T: proto.MsgRelay, Relay: &relay}))
		}
		r.mu.Unlock()
	}
}

func (h *Hub) snapshotRooms() []*room {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*room, 0, len(h.rooms))
	for _, r := range h.rooms {
		out = append(out, r)
	}
	return out
}

func (h *Hub) room(id int64) *room {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.rooms[id]
}

// Kick ends one member's session. It reports whether the member was online.
func (h *Hub) Kick(roomID int64, memberID int64, code proto.ErrorCode, message string) bool {
	r := h.room(roomID)
	if r == nil {
		return false
	}
	r.mu.Lock()
	var target *Session
	for _, s := range r.sessions {
		if s.Member.ID == memberID {
			target = s
			break
		}
	}
	r.mu.Unlock()
	if target == nil {
		return false
	}
	target.remove(code, message)
	return true
}

// CloseRoom ends every session of a room (it was deleted, disabled, or its
// password changed). It returns the number of sessions ended.
func (h *Hub) CloseRoom(roomID int64, code proto.ErrorCode, message string) int {
	r := h.room(roomID)
	if r == nil {
		return 0
	}
	r.mu.Lock()
	targets := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		targets = append(targets, s)
	}
	r.mu.Unlock()
	for _, s := range targets {
		s.end(code, message)
	}
	h.opts.Relays.RevokeRoom(roomID)
	return len(targets)
}

// DisconnectWhere ends every session matching pred, across all rooms. It is
// used to enforce server-wide bans on connected members.
func (h *Hub) DisconnectWhere(pred func(*Session) bool, code proto.ErrorCode, message string) int {
	n := 0
	for _, r := range h.snapshotRooms() {
		r.mu.Lock()
		var targets []*Session
		for _, s := range r.sessions {
			if pred(s) {
				targets = append(targets, s)
			}
		}
		r.mu.Unlock()
		for _, s := range targets {
			s.remove(code, message)
			n++
		}
	}
	return n
}

// UpdateRoom refreshes the cached description of a live room after an
// administrator edited it.
func (h *Hub) UpdateRoom(roomID int64, info proto.RoomInfo) {
	if r := h.room(roomID); r != nil {
		r.mu.Lock()
		r.info = info
		r.mu.Unlock()
	}
}

// Shutdown ends every session and refuses new ones.
func (h *Hub) Shutdown(message string) {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	for _, r := range h.snapshotRooms() {
		r.mu.Lock()
		for _, s := range r.sessions {
			s.end(proto.CodeUnavailable, message)
		}
		r.mu.Unlock()
	}
}

// Online returns the number of connected members across all rooms.
func (h *Hub) Online() int { return int(h.online.Load()) }

// ActiveRooms returns the number of rooms with at least one member online.
func (h *Hub) ActiveRooms() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.rooms)
}

// OnlineCounts returns the number of connected members per live room.
func (h *Hub) OnlineCounts() map[int64]int {
	out := make(map[int64]int)
	for _, r := range h.snapshotRooms() {
		r.mu.Lock()
		if n := len(r.sessions); n > 0 {
			out[r.id] = n
		}
		r.mu.Unlock()
	}
	return out
}

// OnlineIn returns the number of connected members of one room.
func (h *Hub) OnlineIn(roomID int64) int {
	r := h.room(roomID)
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// IsOnline reports whether a virtual address in a room is held by a
// connected member.
func (h *Hub) IsOnline(roomID int64, ip netip.Addr) bool {
	r := h.room(roomID)
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[ip] != nil
}

// SessionInfo is a read-only view of a session for the dashboard.
type SessionInfo struct {
	RoomID        int64
	MemberID      int64
	IP            netip.Addr
	Nickname      string
	Identity      proto.Key32
	RemoteAddr    string
	Platform      string
	ClientVersion string
	ConnectedAt   time.Time
	Endpoints     []netip.AddrPort
	Status        *proto.StatusReport
}

// Sessions returns the connected members of one room ordered by address.
func (h *Hub) Sessions(roomID int64) []SessionInfo {
	r := h.room(roomID)
	if r == nil {
		return nil
	}
	return r.infos()
}

// AllSessions returns every connected member, ordered by room then address.
func (h *Hub) AllSessions() []SessionInfo {
	rooms := h.snapshotRooms()
	sort.Slice(rooms, func(i, j int) bool { return rooms[i].id < rooms[j].id })
	var out []SessionInfo
	for _, r := range rooms {
		out = append(out, r.infos()...)
	}
	return out
}

func (r *room) infos() []SessionInfo {
	r.mu.Lock()
	out := make([]SessionInfo, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, SessionInfo{
			RoomID:        r.id,
			MemberID:      s.Member.ID,
			IP:            s.Member.IP,
			Nickname:      s.Member.Nickname,
			Identity:      s.Member.Identity,
			RemoteAddr:    s.RemoteAddr,
			Platform:      s.Member.Platform,
			ClientVersion: s.Member.ClientVersion,
			ConnectedAt:   s.ConnectedAt,
			Endpoints:     append([]netip.AddrPort(nil), s.endpoints...),
			Status:        s.status.Load(),
		})
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}

// Subscribe returns a channel that receives a value whenever presence
// changes (coalesced: a burst of changes produces one wake-up), and a
// function to stop the subscription.
func (h *Hub) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.subMu.Lock()
	h.subs[ch] = struct{}{}
	h.subMu.Unlock()
	return ch, func() {
		h.subMu.Lock()
		delete(h.subs, ch)
		h.subMu.Unlock()
	}
}

func (h *Hub) notify() {
	h.subMu.Lock()
	for ch := range h.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	h.subMu.Unlock()
}

// Notify wakes subscribers after a change made outside the hub (for
// example an administrator editing a room).
func (h *Hub) Notify() { h.notify() }
