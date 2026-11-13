package api

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"lanora/internal/proto"
	"lanora/internal/server/hub"
	"lanora/internal/server/relay"
	"lanora/internal/server/store"
	"lanora/internal/server/sysmon"
	"lanora/internal/version"
)

// liveStats is the part of the overview that changes continuously. It is
// pushed over the event stream every couple of seconds.
type liveStats struct {
	Time        time.Time     `json:"time"`
	Online      int           `json:"online"`
	ActiveRooms int           `json:"active_rooms"`
	Relay       *relay.Stats  `json:"relay"` // nil when the built-in relay is not used
	System      sysmon.Sample `json:"system"`
}

func (s *Server) liveStats() liveStats {
	st := liveStats{
		Time:        time.Now().UTC(),
		Online:      s.Hub.Online(),
		ActiveRooms: s.Hub.ActiveRooms(),
		System:      s.Monitor.Latest(),
	}
	if s.Relay != nil {
		rs := s.Relay.Stats()
		st.Relay = &rs
	}
	return st
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rooms, err := s.Store.CountRooms(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	members, err := s.Store.CountMembers(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	devices, err := s.Store.CountDevices(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	nodes, healthy := s.Directory.Nodes()
	relayNodes := make([]string, 0, len(nodes))
	for _, n := range nodes {
		relayNodes = append(relayNodes, n.UDP)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"live":       s.liveStats(),
		"history":    s.Monitor.History(),
		"rooms":      rooms,
		"registered": members, // memberships: one device in two rooms counts twice
		"devices":    devices,
		"server": map[string]any{
			"name":           s.Settings().ServerName,
			"version":        version.Version,
			"commit":         version.Commit,
			"protocol":       version.Protocol,
			"go":             runtime.Version(),
			"started_at":     s.started.UTC(),
			"uptime_seconds": int(time.Since(s.started).Seconds()),
			"tls":            s.Config.TLSMode,
			"tls_pin":        s.TLSPin,
			"relay_builtin":  s.Relay != nil,
			"relay_nodes":    relayNodes,
			"relay_healthy":  healthy,
			"events_dropped": s.Events.Dropped(),
		},
	})
}

// handleStream is a Server-Sent Events feed for the dashboard: a "stats"
// event every two seconds and a "presence" event whenever rooms or members
// change, on which the dashboard refreshes whatever list it is showing.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	// The stream is long-lived: lift the server's write deadline for it.
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		writeError(w, http.StatusNotImplemented, proto.CodeServerError, "Streaming is not supported on this connection.")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // ask reverse proxies not to buffer
	w.WriteHeader(http.StatusOK)

	send := func(event string, v any) bool {
		data, err := json.Marshal(v)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send("stats", s.liveStats()) {
		return
	}

	changes, cancel := s.Hub.Subscribe()
	defer cancel()
	stats := time.NewTicker(2 * time.Second)
	defer stats.Stop()

	// Presence changes come in bursts (a room filling up); coalesce them so
	// the dashboard refreshes at most once a second.
	var pending <-chan time.Time
	for {
		select {
		case <-r.Context().Done():
			return
		case <-stats.C:
			if !send("stats", s.liveStats()) {
				return
			}
		case <-changes:
			if pending == nil {
				pending = time.After(time.Second)
			}
		case <-pending:
			pending = nil
			if !send("presence", struct{}{}) {
				return
			}
		}
	}
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	infos := s.Hub.AllSessions()
	rooms := make(map[int64]store.Room)
	out := make([]sessionDTO, 0, len(infos))
	for _, info := range infos {
		room, ok := rooms[info.RoomID]
		if !ok {
			var err error
			if room, err = s.Store.Room(r.Context(), info.RoomID); err != nil && !errors.Is(err, store.ErrNotFound) {
				s.serverError(w, r, err)
				return
			}
			rooms[info.RoomID] = room
		}
		d := s.toSessionDTO(info, false)
		d.RoomName, d.RoomDisplayID = room.Name, proto.FormatRoomID(room.PublicID)
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": out})
}

type deviceDTO struct {
	Identity      string    `json:"identity"`
	Nickname      string    `json:"nickname"`
	Rooms         int       `json:"rooms"`
	BannedRooms   int       `json:"banned_rooms"`
	Banned        bool      `json:"banned"` // banned server-wide
	Online        int       `json:"online"` // rooms it is connected to right now
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	LastAddr      string    `json:"last_addr"`
	Platform      string    `json:"platform"`
	ClientVersion string    `json:"client_version"`
}

// onlineByIdentity counts live sessions per device.
func onlineByIdentity(sessions []hub.SessionInfo) map[proto.Key32]int {
	out := make(map[proto.Key32]int)
	for _, info := range sessions {
		out[info.Identity]++
	}
	return out
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, total, err := s.Store.ListDevices(r.Context(), store.DeviceFilter{
		Search: strings.TrimSpace(r.URL.Query().Get("q")),
		Limit:  queryInt(r, "limit", 100),
		Offset: queryInt(r, "offset", 0),
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	online := onlineByIdentity(s.Hub.AllSessions())
	bans := s.bans.Load()
	out := make([]deviceDTO, 0, len(devices))
	for _, d := range devices {
		out = append(out, deviceDTO{
			Identity: d.Identity.Hex(), Nickname: d.Nickname, Rooms: d.Rooms, BannedRooms: d.BannedRooms,
			Banned: bans.identity(d.Identity), Online: online[d.Identity],
			FirstSeenAt: d.FirstSeenAt, LastSeenAt: d.LastSeenAt, LastAddr: d.LastAddr,
			Platform: d.Platform, ClientVersion: d.ClientVersion,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out, "total": total})
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	hexID, err := store.NormalizeBan(store.BanIdentity, r.PathValue("identity"))
	if err != nil {
		writeError(w, http.StatusNotFound, proto.CodeNotFound, "No such device.")
		return
	}
	var identity proto.Key32
	if raw, err := hex.DecodeString(hexID); err == nil {
		copy(identity[:], raw)
	}
	memberships, err := s.Store.DeviceMemberships(r.Context(), identity)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(memberships) == 0 {
		writeError(w, http.StatusNotFound, proto.CodeNotFound, "No such device.")
		return
	}
	type membershipDTO struct {
		memberDTO
		RoomID        int64  `json:"room_id"`
		RoomName      string `json:"room_name"`
		RoomDisplayID string `json:"room_display_id"`
	}
	out := make([]membershipDTO, 0, len(memberships))
	for _, m := range memberships {
		d := membershipDTO{memberDTO: toMemberDTO(m.Member), RoomID: m.RoomID, RoomName: m.RoomName, RoomDisplayID: proto.FormatRoomID(m.RoomPublicID)}
		d.Online = s.Hub.IsOnline(m.RoomID, m.IP)
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"identity":    hexID,
		"banned":      s.bans.Load().identity(identity),
		"memberships": out,
	})
}

type banDTO struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.Store.ListBans(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	out := make([]banDTO, 0, len(bans))
	for _, b := range bans {
		out = append(out, banDTO{ID: b.ID, Kind: b.Kind, Value: b.Value, Reason: b.Reason, CreatedAt: b.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"bans": out})
}

func (s *Server) handleAddBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind   string `json:"kind"`
		Value  string `json:"value"`
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	value, err := store.NormalizeBan(req.Kind, strings.TrimSpace(req.Value))
	if err != nil {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "Invalid ban: "+err.Error()+".")
		return
	}
	if req.Kind == store.BanIP {
		// Refuse a ban that would lock the administrator making it out of
		// the dashboard's own network path by accident.
		if p, _ := netip.ParsePrefix(value); p.Contains(s.clientIP(r)) {
			writeError(w, http.StatusConflict, proto.CodeConflict, "That range includes your own address.")
			return
		}
	}
	ban, err := s.Store.AddBan(r.Context(), req.Kind, value, proto.CleanText(req.Reason, 200), currentAdmin(r).ID)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, proto.CodeConflict, "That ban already exists.")
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.reloadBans(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	// Enforce it on anyone connected right now.
	bans := s.bans.Load()
	n := s.Hub.DisconnectWhere(func(sess *hub.Session) bool {
		addr, _ := netip.ParseAddr(sess.RemoteAddr)
		return bans.identity(sess.Member.Identity) || bans.addr(addr)
	}, proto.CodeBanned, "You are banned from this server.")
	s.audit(r, "admin.ban.add", 0, fmt.Sprintf("banned %s %s server-wide (%d sessions disconnected)", req.Kind, value, n))
	writeJSON(w, http.StatusCreated, map[string]any{"ban": banDTO{ID: ban.ID, Kind: ban.Kind, Value: ban.Value, Reason: ban.Reason, CreatedAt: ban.CreatedAt}})
}

func (s *Server) handleRemoveBan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := s.Store.RemoveBan(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, proto.CodeNotFound, "No such ban.")
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.reloadBans(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "admin.ban.remove", 0, "lifted a server-wide ban")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type eventDTO struct {
	ID      int64     `json:"id"`
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Kind    string    `json:"kind"`
	RoomID  int64     `json:"room_id,omitempty"`
	Actor   string    `json:"actor"`
	Addr    string    `json:"addr"`
	Message string    `json:"message"`
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.EventFilter{
		Kind:     q.Get("kind"),
		Search:   q.Get("q"),
		RoomID:   int64(queryInt(r, "room", 0)),
		BeforeID: int64(queryInt(r, "before", 0)),
		Limit:    min(max(queryInt(r, "limit", 100), 1), 500),
	}
	switch level := q.Get("level"); level {
	case "", store.LevelInfo, store.LevelWarn, store.LevelError:
		filter.Level = level
	default:
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "Level must be info, warn or error.")
		return
	}
	events, err := s.Store.ListEvents(r.Context(), filter)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	out := make([]eventDTO, 0, len(events))
	for _, e := range events {
		out = append(out, eventDTO{ID: e.ID, Time: e.Time, Level: e.Level, Kind: e.Kind, RoomID: e.RoomID, Actor: e.Actor, Addr: e.Addr, Message: e.Message})
	}
	// more tells the dashboard whether an older page exists.
	writeJSON(w, http.StatusOK, map[string]any{"events": out, "more": len(events) == filter.Limit})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"settings": s.Settings()})
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	next := s.Settings()
	if !decodeJSON(w, r, &next, 8<<10) {
		return
	}
	if err := next.Validate(); err != nil {
		msg := err.Error()
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, strings.ToUpper(msg[:1])+msg[1:]+".")
		return
	}
	if err := saveSettings(r.Context(), s.Store, next); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.applySettings(next)
	s.audit(r, "admin.settings", 0, "changed the server settings")
	writeJSON(w, http.StatusOK, map[string]any{"settings": next})
}

// handleMetrics exposes counters in the Prometheus text format. It is
// disabled unless a token is configured, and then requires it.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	token := s.Config.MetricsToken
	if token == "" {
		http.NotFound(w, r)
		return
	}
	got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	live := s.liveStats()
	var b strings.Builder
	metric := func(name, help, typ string, value any, labels string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s%s %v\n", name, help, name, typ, name, labels, value)
	}
	metric("lanora_build_info", "Build information.", "gauge", 1, fmt.Sprintf(`{version=%q}`, version.Version))
	metric("lanora_uptime_seconds", "Seconds since the server started.", "gauge", int(time.Since(s.started).Seconds()), "")
	metric("lanora_members_online", "Members connected right now.", "gauge", live.Online, "")
	metric("lanora_rooms_active", "Rooms with at least one member online.", "gauge", live.ActiveRooms, "")
	metric("lanora_events_dropped_total", "Log events dropped because the queue was full.", "counter", s.Events.Dropped(), "")
	if rs := live.Relay; rs != nil {
		metric("lanora_relay_sessions", "Clients bound to the built-in relay.", "gauge", rs.Sessions, "")
		metric("lanora_relay_packets_total", "Packets forwarded by the relay.", "counter", rs.Packets, "")
		metric("lanora_relay_bytes_total", "Bytes forwarded by the relay.", "counter", rs.Bytes, "")
		fmt.Fprintf(&b, "# HELP lanora_relay_dropped_total Packets the relay did not forward, by reason.\n# TYPE lanora_relay_dropped_total counter\n")
		for _, d := range []struct {
			reason string
			n      uint64
		}{
			{"no_peer", rs.DroppedNoPeer}, {"unbound", rs.DroppedUnbound},
			{"rate_limited", rs.DroppedLimited}, {"queue_full", rs.DroppedQueue},
		} {
			fmt.Fprintf(&b, "lanora_relay_dropped_total{reason=%q} %d\n", d.reason, d.n)
		}
	}
	metric("process_cpu_percent", "CPU use of the server process, percent of one core.", "gauge", fmt.Sprintf("%.2f", live.System.CPUPercent), "")
	metric("process_resident_memory_bytes", "Resident memory of the server process.", "gauge", live.System.RSSBytes, "")
	metric("process_open_fds", "Open file descriptors.", "gauge", live.System.OpenFDs, "")
	metric("go_goroutines", "Number of goroutines.", "gauge", live.System.Goroutines, "")
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(b.String()))
}
