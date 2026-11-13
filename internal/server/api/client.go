package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"lanora/internal/proto"
	"lanora/internal/server/auth"
	"lanora/internal/server/hub"
	"lanora/internal/server/store"
	"lanora/internal/version"
)

const (
	sessionHelloTimeout = 10 * time.Second
	sessionWriteTimeout = 10 * time.Second
	// Clients ping every 25 seconds. The server does not ping back: it only
	// notices when a client has been silent for too long. One keepalive
	// direction halves the idle traffic of every connection.
	sessionIdleTimeout = 70 * time.Second
	// A client may send signalling messages in bursts (it publishes
	// endpoints and asks every peer to punch when it joins), but not
	// continuously.
	sessionMsgBurst     = 600
	sessionMsgPerSecond = 30
)

// invalidCredentials is deliberately the same for an unknown room and a
// wrong password, so the API does not reveal which room IDs exist.
const invalidCredentials = "The room ID or password is incorrect."

func (s *Server) handleHello(w http.ResponseWriter, r *http.Request) {
	if ok, retry := s.helloLimiter.Allow(s.clientIP(r).String()); !ok {
		writeRateLimited(w, retry)
		return
	}
	now := time.Now()
	set := s.Settings()
	writeJSON(w, http.StatusOK, proto.HelloResponse{
		Server:    set.ServerName,
		Version:   version.Version,
		Protocol:  version.Protocol,
		MinClient: set.MinClientVersion,
		Nonce:     s.Keys.IssueNonce(now),
		Time:      now.Unix(),
	})
}

func (s *Server) roomInfo(room store.Room) proto.RoomInfo {
	return proto.RoomInfo{
		ID:          room.PublicID,
		Name:        room.Name,
		Description: room.Description,
		Subnet:      room.Subnet,
		MTU:         s.Settings().MTU,
		Capacity:    room.Capacity,
	}
}

// checkClientVersion returns a non-empty message when the client cannot
// talk to this server.
func (s *Server) checkClientVersion(protocol int, clientVersion string) string {
	if protocol != version.Protocol {
		if protocol < version.Protocol {
			return "This version of Lanora is too old for this server. Please update the app."
		}
		return "This server is older than your Lanora app and does not support it yet."
	}
	if version.Compare(clientVersion, s.Settings().MinClientVersion) < 0 {
		return "This version of Lanora is too old for this server. Please update the app."
	}
	return ""
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	source := ip.String()
	if ok, retry := s.joinLimiter.Allow(source); !ok {
		writeRateLimited(w, retry)
		return
	}

	var req proto.JoinRequest
	if !decodeJSON(w, r, &req, 16<<10) {
		return
	}
	if msg := s.checkClientVersion(req.Protocol, req.ClientVersion); msg != "" {
		writeError(w, http.StatusUpgradeRequired, proto.CodeClientTooOld, msg)
		return
	}
	roomID, err := proto.NormalizeRoomID(req.RoomID)
	if err != nil {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "A room ID is 9 letters and digits, for example 7KQ-2MX-9DW.")
		return
	}
	// Wrong passwords are counted per source address and room, not per
	// address alone. Many people can share one public address (a household,
	// a campus, the exit of a commercial VPN), and one of them mistyping a
	// password must not lock the others out of their own rooms. Trying many
	// rooms from one address is held back by the request rate limit above.
	guessKey := source + "|" + roomID
	if locked := s.joinLockout.Locked(guessKey); locked > 0 {
		writeRateLimited(w, locked)
		return
	}
	nickname := proto.CleanNickname(req.Nickname)
	if nickname == "" {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "Please choose a nickname.")
		return
	}
	if err := s.Keys.CheckNonce(req.Nonce, time.Now()); err != nil {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "The join request expired. Please try again.")
		return
	}
	if req.Identity.IsZero() || len(req.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(req.Identity[:], proto.JoinTranscript(req.Nonce, roomID, req.Identity), req.Signature) {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "The join request is not signed correctly.")
		return
	}

	bans := s.bans.Load()
	if bans.identity(req.Identity) || bans.addr(ip) {
		s.Events.Record(store.LevelWarn, "auth.banned", 0, 0, nickname, source, "join refused: banned from this server")
		writeError(w, http.StatusForbidden, proto.CodeBanned, "You are banned from this server.")
		return
	}

	ctx := r.Context()
	room, err := s.Store.RoomByPublicID(ctx, roomID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Spend the same effort as a real password check so that an unknown
		// room cannot be told apart from a wrong password by timing.
		s.Hasher.Burn(ctx, req.Password)
		s.joinFailed(w, guessKey, source, 0, nickname, "unknown room "+proto.FormatRoomID(roomID))
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	ok := false
	if len(req.Password) <= proto.MaxPasswordLen {
		if ok, _, err = s.Hasher.Verify(ctx, room.PasswordHash, req.Password); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if !ok {
		s.joinFailed(w, guessKey, source, room.ID, nickname, "wrong password for room "+room.Name)
		return
	}
	s.joinLockout.Success(guessKey)

	if !room.Enabled {
		writeError(w, http.StatusForbidden, proto.CodeRoomDisabled, "This room is currently disabled.")
		return
	}

	member, created, err := s.Store.AdmitMember(ctx, store.Admission{
		RoomID:        room.ID,
		Subnet:        room.Subnet,
		Identity:      req.Identity,
		Nickname:      nickname,
		Addr:          source,
		Platform:      proto.CleanText(req.Platform, 32),
		ClientVersion: proto.CleanText(req.ClientVersion, 32),
		Online:        func(a netip.Addr) bool { return s.Hub.IsOnline(room.ID, a) },
	})
	switch {
	case errors.Is(err, store.ErrNoSpace):
		writeError(w, http.StatusConflict, proto.CodeRoomFull, "This room is full.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	if member.Banned {
		msg := "You are banned from this room."
		if member.BanReason != "" {
			msg += " Reason: " + member.BanReason
		}
		s.Events.Record(store.LevelWarn, "auth.banned", room.ID, member.ID, nickname, source, "join refused: banned from the room")
		writeError(w, http.StatusForbidden, proto.CodeBanned, msg)
		return
	}
	if !s.Hub.IsOnline(room.ID, member.IP) && s.Hub.OnlineIn(room.ID) >= room.Capacity {
		writeError(w, http.StatusConflict, proto.CodeRoomFull, "This room is full.")
		return
	}
	if created {
		s.Events.Record(store.LevelInfo, "room.member", room.ID, member.ID, nickname, source,
			"new device registered with address "+member.IP.String())
	}

	expires := time.Now().Add(s.Settings().SessionTTL())
	writeJSON(w, http.StatusOK, proto.JoinResponse{
		Token: s.Keys.IssueSession(auth.SessionClaims{
			Room: room.ID, Member: member.ID, Device: auth.DeviceClaim(member.Identity),
			PasswordVersion: room.PasswordVersion, Expiry: expires.Unix(),
		}),
		ExpiresAt: expires.Unix(),
		Room:      s.roomInfo(room),
		IP:        member.IP,
		Nickname:  member.Nickname,
	})
}

// joinFailed records a failed join, applies the lockout policy and answers
// with the generic credentials error.
func (s *Server) joinFailed(w http.ResponseWriter, guessKey, source string, roomID int64, nickname, detail string) {
	if lock := s.joinLockout.Fail(guessKey); lock > 0 {
		s.Events.Record(store.LevelWarn, "auth.lockout", roomID, 0, nickname, source,
			"too many failed join attempts; source locked out for "+humanDuration(lock))
	} else {
		s.Events.Record(store.LevelWarn, "auth.fail", roomID, 0, nickname, source, "join failed: "+detail)
	}
	writeError(w, http.StatusUnauthorized, proto.CodeInvalidCredentials, invalidCredentials)
}

// authorizeSession validates a session token against the current state of
// the database: the membership must still exist, still belong to the device
// the token was issued to and not be banned; the room must be enabled, and
// its password must not have changed since the token was issued.
func (s *Server) authorizeSession(ctx context.Context, token string) (store.Room, store.Member, *proto.APIError) {
	deny := func(status int, code proto.ErrorCode, msg string) (store.Room, store.Member, *proto.APIError) {
		return store.Room{}, store.Member{}, &proto.APIError{Status: status, ErrorBody: proto.ErrorBody{Code: code, Message: msg}}
	}
	claims, err := s.Keys.ParseSession(token, time.Now())
	if err != nil {
		return deny(http.StatusUnauthorized, proto.CodeUnauthorized, "The session has expired. Joining again.")
	}
	room, err := s.Store.Room(ctx, claims.Room)
	if errors.Is(err, store.ErrNotFound) {
		return deny(http.StatusForbidden, proto.CodeRoomClosed, "This room no longer exists.")
	} else if err != nil {
		return deny(http.StatusInternalServerError, proto.CodeServerError, "Internal server error.")
	}
	if !room.Enabled {
		return deny(http.StatusForbidden, proto.CodeRoomDisabled, "This room is currently disabled.")
	}
	if room.PasswordVersion != claims.PasswordVersion {
		return deny(http.StatusUnauthorized, proto.CodeUnauthorized, "The room password was changed.")
	}
	member, err := s.Store.Member(ctx, claims.Member)
	if errors.Is(err, store.ErrNotFound) ||
		(err == nil && (member.RoomID != room.ID || auth.DeviceClaim(member.Identity) != claims.Device)) {
		// The membership was removed; joining again creates a new one.
		return deny(http.StatusUnauthorized, proto.CodeUnauthorized, "Your membership of this room was removed.")
	} else if err != nil {
		return deny(http.StatusInternalServerError, proto.CodeServerError, "Internal server error.")
	}
	if member.Banned {
		return deny(http.StatusForbidden, proto.CodeBanned, "You are banned from this room.")
	}
	return room, member, nil
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if ok, retry := s.connLimiter.Allow(ip.String()); !ok {
		writeRateLimited(w, retry)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, proto.CodeUnauthorized, "Missing session token.")
		return
	}
	room, member, apiErr := s.authorizeSession(r.Context(), token)
	if apiErr != nil {
		writeError(w, apiErr.Status, apiErr.Code, apiErr.Message)
		return
	}
	bans := s.bans.Load()
	if bans.identity(member.Identity) || bans.addr(ip) {
		writeError(w, http.StatusForbidden, proto.CodeBanned, "You are banned from this server.")
		return
	}

	// alive is called for every sign of life from the client, including the
	// pings the WebSocket library answers by itself.
	var idle atomic.Pointer[time.Timer]
	alive := func() {
		if t := idle.Load(); t != nil {
			t.Reset(sessionIdleTimeout)
		}
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
		OnPingReceived:  func(context.Context, []byte) bool { alive(); return true },
	})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(proto.MaxSignalMessage)

	// The first message carries the keys for this session.
	hctx, cancel := context.WithTimeout(r.Context(), sessionHelloTimeout)
	hello, err := readMsg(hctx, conn)
	cancel()
	if err != nil || hello.T != proto.MsgHello || hello.WGPub == nil || hello.DiscoPub == nil ||
		hello.WGPub.IsZero() || hello.DiscoPub.IsZero() {
		conn.Close(websocket.StatusPolicyViolation, "expected hello")
		return
	}

	sess, err := s.Hub.Join(hub.JoinParams{
		RoomID: room.ID,
		Room:   s.roomInfo(room),
		Member: hub.MemberInfo{
			ID: member.ID, IP: member.IP, Nickname: member.Nickname, Identity: member.Identity,
			Platform: member.Platform, ClientVersion: member.ClientVersion,
		},
		WGPub:      *hello.WGPub,
		DiscoPub:   *hello.DiscoPub,
		Endpoints:  hello.Endpoints,
		RemoteAddr: ip.String(),
	})
	if err != nil {
		bye := proto.Msg{T: proto.MsgBye, Code: proto.CodeUnavailable, Message: "The server is restarting."}
		if errors.Is(err, hub.ErrRoomFull) {
			bye.Code, bye.Message = proto.CodeRoomFull, "This room is full."
		}
		writeMsg(r.Context(), conn, bye)
		conn.Close(websocket.StatusNormalClosure, string(bye.Code))
		return
	}
	defer s.Hub.Leave(sess)

	ctx, stop := context.WithCancel(r.Context())
	defer stop()
	timer := time.AfterFunc(sessionIdleTimeout, stop)
	defer timer.Stop()
	idle.Store(timer)
	go s.sessionWriter(ctx, stop, conn, sess)

	// Reader: runs until the connection drops or the session is ended.
	tokens, last := float64(sessionMsgBurst), time.Now()
	for {
		msg, err := readMsg(ctx, conn)
		if err != nil {
			return
		}
		alive()
		now := time.Now()
		tokens = min(sessionMsgBurst, tokens+now.Sub(last).Seconds()*sessionMsgPerSecond)
		last = now
		if tokens < 1 {
			conn.Close(websocket.StatusPolicyViolation, "too many messages")
			return
		}
		tokens--
		s.Hub.Handle(sess, msg)
	}
}

// sessionWriter is the only goroutine that writes to the connection. It
// forwards queued signalling messages and says goodbye when the hub ends
// the session.
func (s *Server) sessionWriter(ctx context.Context, stop context.CancelFunc, conn *websocket.Conn, sess *hub.Session) {
	defer stop()
	write := func(data []byte) error {
		wctx, cancel := context.WithTimeout(ctx, sessionWriteTimeout)
		defer cancel()
		return conn.Write(wctx, websocket.MessageText, data)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-sess.Outbound():
			if write(data) != nil {
				return
			}
		case <-sess.Done():
			// Deliver anything already queued (it may include the welcome),
			// then the reason for ending the session.
			for {
				select {
				case data := <-sess.Outbound():
					if write(data) != nil {
						return
					}
					continue
				default:
				}
				break
			}
			if bye := sess.Bye(); bye != nil {
				if data, err := json.Marshal(bye); err == nil {
					write(data)
				}
				conn.Close(websocket.StatusNormalClosure, string(bye.Code))
			}
			return
		}
	}
}

func readMsg(ctx context.Context, conn *websocket.Conn) (*proto.Msg, error) {
	typ, data, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageText {
		return nil, errors.New("unexpected binary message")
	}
	var m proto.Msg
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func writeMsg(ctx context.Context, conn *websocket.Conn, m proto.Msg) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, sessionWriteTimeout)
	defer cancel()
	return conn.Write(wctx, websocket.MessageText, data)
}
