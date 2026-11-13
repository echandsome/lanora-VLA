package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"lanora/internal/proto"
	"lanora/internal/server/hub"
	"lanora/internal/server/store"
)

type roomDTO struct {
	ID          int64     `json:"id"`
	PublicID    string    `json:"public_id"`
	DisplayID   string    `json:"display_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Subnet      string    `json:"subnet"`
	Capacity    int       `json:"capacity"`
	Enabled     bool      `json:"enabled"`
	Online      int       `json:"online"`
	Members     int       `json:"members"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func toRoomDTO(r store.Room, online, members int) roomDTO {
	return roomDTO{
		ID: r.ID, PublicID: r.PublicID, DisplayID: proto.FormatRoomID(r.PublicID),
		Name: r.Name, Description: r.Description, Subnet: r.Subnet.String(),
		Capacity: r.Capacity, Enabled: r.Enabled, Online: online, Members: members,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

type peerPathDTO struct {
	IP  string `json:"ip"`
	Via string `json:"via"`
	RTT int    `json:"rtt_ms"`
}

// sessionDTO describes one live connection.
type sessionDTO struct {
	RoomID        int64         `json:"room_id"`
	RoomName      string        `json:"room_name,omitempty"`
	RoomDisplayID string        `json:"room_display_id,omitempty"`
	MemberID      int64         `json:"member_id"`
	Nickname      string        `json:"nickname"`
	IP            string        `json:"ip"`
	Identity      string        `json:"identity"`
	RemoteAddr    string        `json:"remote_addr"`
	Platform      string        `json:"platform"`
	ClientVersion string        `json:"client_version"`
	ConnectedAt   time.Time     `json:"connected_at"`
	Endpoints     []string      `json:"endpoints"`
	Reported      bool          `json:"reported"` // the client has sent a path report
	Direct        int           `json:"direct"`
	Relayed       int           `json:"relayed"`
	Unreachable   int           `json:"unreachable"`
	AvgRTT        int           `json:"avg_rtt_ms"` // -1 when unknown
	Peers         []peerPathDTO `json:"peers,omitempty"`
	RelayBound    bool          `json:"relay_bound"`
	RelayRx       uint64        `json:"relay_rx_bytes"`
	RelayTx       uint64        `json:"relay_tx_bytes"`
}

// toSessionDTO summarises a live session. withPeers includes the per-peer
// path table, which is only wanted when looking at a single room.
func (s *Server) toSessionDTO(info hub.SessionInfo, withPeers bool) sessionDTO {
	d := sessionDTO{
		RoomID: info.RoomID, MemberID: info.MemberID, Nickname: info.Nickname,
		IP: info.IP.String(), Identity: info.Identity.Hex(), RemoteAddr: info.RemoteAddr,
		Platform: info.Platform, ClientVersion: info.ClientVersion,
		ConnectedAt: info.ConnectedAt.UTC().Truncate(time.Millisecond), // like every stored timestamp
		Endpoints:   make([]string, 0, len(info.Endpoints)), AvgRTT: -1,
	}
	for _, ep := range info.Endpoints {
		d.Endpoints = append(d.Endpoints, ep.String())
	}
	if st := info.Status; st != nil {
		d.Reported = true
		sum, n := 0, 0
		for _, p := range st.Peers {
			switch p.Via {
			case proto.ViaDirect:
				d.Direct++
			case proto.ViaRelay:
				d.Relayed++
			default:
				d.Unreachable++
			}
			if p.RTT >= 0 {
				sum, n = sum+p.RTT, n+1
			}
			if withPeers {
				d.Peers = append(d.Peers, peerPathDTO{IP: p.IP.String(), Via: p.Via, RTT: p.RTT})
			}
		}
		if n > 0 {
			d.AvgRTT = sum / n
		}
	}
	if s.Relay != nil {
		d.RelayRx, d.RelayTx, d.RelayBound = s.Relay.Traffic(uint64(info.RoomID), proto.PeerIDOf(info.IP))
	}
	return d
}

type memberDTO struct {
	ID            int64       `json:"id"`
	Nickname      string      `json:"nickname"`
	IP            string      `json:"ip"`
	Identity      string      `json:"identity"`
	Banned        bool        `json:"banned"`
	BanReason     string      `json:"ban_reason"`
	Online        bool        `json:"online"`
	FirstSeenAt   time.Time   `json:"first_seen_at"`
	LastSeenAt    time.Time   `json:"last_seen_at"`
	LastAddr      string      `json:"last_addr"`
	Platform      string      `json:"platform"`
	ClientVersion string      `json:"client_version"`
	Session       *sessionDTO `json:"session"`
}

func toMemberDTO(m store.Member) memberDTO {
	return memberDTO{
		ID: m.ID, Nickname: m.Nickname, IP: m.IP.String(), Identity: m.Identity.Hex(),
		Banned: m.Banned, BanReason: m.BanReason, FirstSeenAt: m.FirstSeenAt, LastSeenAt: m.LastSeenAt,
		LastAddr: m.LastAddr, Platform: m.Platform, ClientVersion: m.ClientVersion,
	}
}

func (s *Server) handleListRooms(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rooms, total, err := s.Store.ListRooms(ctx, store.RoomFilter{
		Search: r.URL.Query().Get("q"),
		Limit:  queryInt(r, "limit", 200),
		Offset: queryInt(r, "offset", 0),
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	members, err := s.Store.MemberCounts(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	online := s.Hub.OnlineCounts()
	out := make([]roomDTO, 0, len(rooms))
	for _, room := range rooms {
		out = append(out, toRoomDTO(room, online[room.ID], members[room.ID]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"rooms": out, "total": total})
}

// validRoomPassword returns a message when pw is not acceptable.
func validRoomPassword(pw string) string {
	if len(pw) < proto.MinPasswordLen {
		return fmt.Sprintf("A room password must be at least %d characters long.", proto.MinPasswordLen)
	}
	if len(pw) > proto.MaxPasswordLen {
		return "That password is too long."
	}
	return ""
}

func (s *Server) handleCreateRoom(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Capacity    int    `json:"capacity"`
		Password    string `json:"password"`
		Subnet      string `json:"subnet"`
	}
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	set := s.Settings()
	name := proto.CleanText(req.Name, proto.MaxRoomNameLen)
	if name == "" {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "Give the room a name.")
		return
	}
	capacity := req.Capacity
	if capacity == 0 {
		capacity = set.DefaultCapacity
	}
	if capacity < 2 || capacity > store.MaxRoomCapacity {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, fmt.Sprintf("Capacity must be between 2 and %d.", store.MaxRoomCapacity))
		return
	}
	password := req.Password
	if password == "" {
		password = proto.NewRoomPassword()
	} else if msg := validRoomPassword(password); msg != "" {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, msg)
		return
	}
	in := store.NewRoom{
		Name:        name,
		Description: proto.CleanText(req.Description, proto.MaxRoomDescLen),
		Capacity:    capacity,
		CreatedBy:   currentAdmin(r).ID,
		Pool:        set.Pool(),
	}
	if sub := strings.TrimSpace(req.Subnet); sub != "" {
		p, err := netip.ParsePrefix(sub)
		if err == nil {
			err = store.ValidateRoomSubnet(p)
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "The subnet must be an IPv4 /24 such as 10.214.7.0/24.")
			return
		}
		in.Subnet = p
	}

	ctx := r.Context()
	if set.MaxRooms > 0 {
		if n, err := s.Store.CountRooms(ctx); err != nil {
			s.serverError(w, r, err)
			return
		} else if n >= set.MaxRooms {
			writeError(w, http.StatusConflict, proto.CodeConflict, fmt.Sprintf("The server is limited to %d rooms. Delete one or raise the limit in Settings.", set.MaxRooms))
			return
		}
	}
	var err error
	if in.PasswordHash, err = s.Hasher.Hash(ctx, password); err != nil {
		s.serverError(w, r, err)
		return
	}
	room, err := s.Store.CreateRoom(ctx, in)
	switch {
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, proto.CodeConflict, "That subnet overlaps another room.")
		return
	case errors.Is(err, store.ErrNoSpace):
		writeError(w, http.StatusConflict, proto.CodeConflict, "The address pool has no free subnet left. Enlarge it in Settings.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "admin.room.create", room.ID, "created room \""+room.Name+"\" ("+proto.FormatRoomID(room.PublicID)+", "+room.Subnet.String()+")")
	// The plain password is returned exactly once; only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]any{"room": toRoomDTO(room, 0, 0), "password": password})
}

// loadRoom fetches the room named by the {id} path parameter, writing the
// error response when it does not exist.
func (s *Server) loadRoom(w http.ResponseWriter, r *http.Request) (store.Room, bool) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return store.Room{}, false
	}
	room, err := s.Store.Room(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, proto.CodeNotFound, "No such room.")
		return store.Room{}, false
	} else if err != nil {
		s.serverError(w, r, err)
		return store.Room{}, false
	}
	return room, true
}

func (s *Server) handleGetRoom(w http.ResponseWriter, r *http.Request) {
	room, ok := s.loadRoom(w, r)
	if !ok {
		return
	}
	members, err := s.Store.ListMembers(r.Context(), room.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	live := make(map[int64]hub.SessionInfo)
	for _, info := range s.Hub.Sessions(room.ID) {
		live[info.MemberID] = info
	}
	out := make([]memberDTO, 0, len(members))
	for _, m := range members {
		d := toMemberDTO(m)
		if info, ok := live[m.ID]; ok {
			sess := s.toSessionDTO(info, true)
			d.Online, d.Session = true, &sess
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"room": toRoomDTO(room, len(live), len(members)), "members": out})
}

func (s *Server) handleUpdateRoom(w http.ResponseWriter, r *http.Request) {
	room, ok := s.loadRoom(w, r)
	if !ok {
		return
	}
	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Capacity    *int    `json:"capacity"`
		Enabled     *bool   `json:"enabled"`
	}
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	patch := store.RoomPatch{Enabled: req.Enabled}
	if req.Name != nil {
		name := proto.CleanText(*req.Name, proto.MaxRoomNameLen)
		if name == "" {
			writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "Give the room a name.")
			return
		}
		patch.Name = &name
	}
	if req.Description != nil {
		desc := proto.CleanText(*req.Description, proto.MaxRoomDescLen)
		patch.Description = &desc
	}
	if req.Capacity != nil {
		if *req.Capacity < 2 || *req.Capacity > store.MaxRoomCapacity {
			writeError(w, http.StatusBadRequest, proto.CodeBadRequest, fmt.Sprintf("Capacity must be between 2 and %d.", store.MaxRoomCapacity))
			return
		}
		patch.Capacity = req.Capacity
	}
	updated, err := s.Store.UpdateRoom(r.Context(), room.ID, patch)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if room.Enabled && !updated.Enabled {
		n := s.Hub.CloseRoom(room.ID, proto.CodeRoomDisabled, "This room was disabled by an administrator.")
		s.audit(r, "admin.room.disable", room.ID, fmt.Sprintf("disabled room \"%s\" (%d members disconnected)", updated.Name, n))
	} else {
		s.Hub.UpdateRoom(room.ID, s.roomInfo(updated))
		s.audit(r, "admin.room.update", room.ID, "updated room \""+updated.Name+"\"")
	}
	members, _ := s.Store.MemberCounts(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"room": toRoomDTO(updated, s.Hub.OnlineIn(room.ID), members[room.ID])})
}

func (s *Server) handleRoomPassword(w http.ResponseWriter, r *http.Request) {
	room, ok := s.loadRoom(w, r)
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	password := req.Password
	if password == "" {
		password = proto.NewRoomPassword()
	} else if msg := validRoomPassword(password); msg != "" {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, msg)
		return
	}
	hash, err := s.Hasher.Hash(r.Context(), password)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if _, err := s.Store.SetRoomPassword(r.Context(), room.ID, hash); err != nil {
		s.serverError(w, r, err)
		return
	}
	// Everyone connected joined with the old password: they must re-enter.
	n := s.Hub.CloseRoom(room.ID, proto.CodeInvalidCredentials, "The room password was changed. Ask the room administrator for the new one.")
	s.audit(r, "admin.room.password", room.ID, fmt.Sprintf("changed the password of room \"%s\" (%d members disconnected)", room.Name, n))
	writeJSON(w, http.StatusOK, map[string]any{"password": password})
}

func (s *Server) handleDeleteRoom(w http.ResponseWriter, r *http.Request) {
	room, ok := s.loadRoom(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteRoom(r.Context(), room.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	n := s.Hub.CloseRoom(room.ID, proto.CodeRoomClosed, "This room was deleted by an administrator.")
	s.audit(r, "admin.room.delete", room.ID, fmt.Sprintf("deleted room \"%s\" (%d members disconnected)", room.Name, n))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// loadMember fetches the member named by {mid}, which must belong to the
// room named by {id}.
func (s *Server) loadMember(w http.ResponseWriter, r *http.Request) (store.Member, bool) {
	roomID, ok := pathID(w, r, "id")
	if !ok {
		return store.Member{}, false
	}
	memberID, ok := pathID(w, r, "mid")
	if !ok {
		return store.Member{}, false
	}
	m, err := s.Store.Member(r.Context(), memberID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && m.RoomID != roomID) {
		writeError(w, http.StatusNotFound, proto.CodeNotFound, "No such member in this room.")
		return store.Member{}, false
	} else if err != nil {
		s.serverError(w, r, err)
		return store.Member{}, false
	}
	return m, true
}

func (s *Server) handleKickMember(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMember(w, r)
	if !ok {
		return
	}
	online := s.Hub.Kick(m.RoomID, m.ID, proto.CodeKicked, "You were removed from the room by an administrator.")
	if !online {
		writeError(w, http.StatusConflict, proto.CodeConflict, "That member is not connected.")
		return
	}
	s.audit(r, "admin.member.kick", m.RoomID, "disconnected "+m.Nickname+" ("+m.IP.String()+")")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleBanMember(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMember(w, r)
	if !ok {
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	reason := proto.CleanText(req.Reason, 200)
	updated, err := s.Store.SetMemberBan(r.Context(), m.ID, true, reason)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	msg := "You were banned from this room."
	if reason != "" {
		msg += " Reason: " + reason
	}
	s.Hub.Kick(m.RoomID, m.ID, proto.CodeBanned, msg)
	s.audit(r, "admin.member.ban", m.RoomID, "banned "+m.Nickname+" ("+m.IP.String()+") from the room")
	writeJSON(w, http.StatusOK, map[string]any{"member": toMemberDTO(updated)})
}

func (s *Server) handleUnbanMember(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMember(w, r)
	if !ok {
		return
	}
	updated, err := s.Store.SetMemberBan(r.Context(), m.ID, false, "")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "admin.member.unban", m.RoomID, "lifted the ban on "+m.Nickname+" ("+m.IP.String()+")")
	writeJSON(w, http.StatusOK, map[string]any{"member": toMemberDTO(updated)})
}

func (s *Server) handleDeleteMember(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMember(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteMember(r.Context(), m.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	// Its session token now refers to a membership that no longer exists;
	// end the live session too. Rejoining with the password is allowed.
	s.Hub.Kick(m.RoomID, m.ID, proto.CodeKicked, "You were removed from the room by an administrator.")
	s.audit(r, "admin.member.remove", m.RoomID, "removed "+m.Nickname+" and released "+m.IP.String())
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
