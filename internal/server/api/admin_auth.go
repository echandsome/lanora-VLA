package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"lanora/internal/proto"
	"lanora/internal/server/auth"
	"lanora/internal/server/store"
)

const (
	adminCookie         = "lanora_admin"
	minAdminPasswordLen = 10
	maxAdminUsernameLen = 32
)

type ctxKey int

const (
	ctxAdmin ctxKey = iota
	ctxTokenHash
)

// currentAdmin returns the signed-in administrator of a request that passed
// requireRole.
func currentAdmin(r *http.Request) store.Admin {
	a, _ := r.Context().Value(ctxAdmin).(store.Admin)
	return a
}

func roleRank(role string) int {
	switch role {
	case store.RoleOwner:
		return 3
	case store.RoleAdmin:
		return 2
	case store.RoleViewer:
		return 1
	}
	return 0
}

// requireRole wraps a handler so it only runs for a signed-in administrator
// whose role is at least min.
func (s *Server) requireRole(min string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(adminCookie)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, proto.CodeUnauthorized, "Sign in to continue.")
			return
		}
		hash := auth.HashOpaqueToken(cookie.Value)
		sess, err := s.Store.AdminSession(r.Context(), hash)
		if errors.Is(err, store.ErrNotFound) || (err == nil && sess.Admin.Disabled) {
			s.clearAdminCookie(w, r)
			writeError(w, http.StatusUnauthorized, proto.CodeUnauthorized, "Your session has ended. Sign in again.")
			return
		} else if err != nil {
			s.serverError(w, r, err)
			return
		}
		if roleRank(sess.Admin.Role) < roleRank(min) {
			writeError(w, http.StatusForbidden, proto.CodeForbidden, "Your account is not allowed to do this.")
			return
		}
		// Sliding expiry: a session in use is extended once it is half used
		// up, so an active administrator is not signed out mid-task and the
		// database is written to at most a few times per session.
		ttl := s.Settings().AdminSessionTTL()
		if time.Until(sess.ExpiresAt) < ttl/2 {
			if err := s.Store.ExtendAdminSession(r.Context(), hash, ttl); err == nil {
				s.setAdminCookie(w, r, cookie.Value, ttl)
			}
		}
		ctx := context.WithValue(r.Context(), ctxAdmin, sess.Admin)
		ctx = context.WithValue(ctx, ctxTokenHash, hash)
		next(w, r.WithContext(ctx))
	})
}

func (s *Server) setAdminCookie(w http.ResponseWriter, r *http.Request, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookie,
		Value:    token,
		Path:     "/api/admin",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   s.isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearAdminCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookie,
		Path:     "/api/admin",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

type adminDTO struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

func toAdminDTO(a store.Admin) adminDTO {
	d := adminDTO{ID: a.ID, Username: a.Username, Role: a.Role, Disabled: a.Disabled, CreatedAt: a.CreatedAt}
	if !a.LastLoginAt.IsZero() {
		d.LastLoginAt = &a.LastLoginAt
	}
	return d
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	source := s.clientIP(r).String()
	if ok, retry := s.loginLimiter.Allow(source); !ok {
		writeRateLimited(w, retry)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	username := strings.TrimSpace(req.Username)
	// Lock out both the source address and the account name, so neither one
	// address trying many accounts nor many addresses trying one account
	// gets unlimited guesses.
	userKey := "user:" + strings.ToLower(username)
	for _, key := range []string{source, userKey} {
		if locked := s.loginLockout.Locked(key); locked > 0 {
			writeRateLimited(w, locked)
			return
		}
	}

	ctx := r.Context()
	fail := func() {
		lock := max(s.loginLockout.Fail(source), s.loginLockout.Fail(userKey))
		msg := "sign-in failed for \"" + proto.CleanText(username, maxAdminUsernameLen) + "\""
		if lock > 0 {
			msg += "; locked out for " + humanDuration(lock)
		}
		s.Events.Record(store.LevelWarn, "admin.login.fail", 0, 0, "", source, msg)
		writeError(w, http.StatusUnauthorized, proto.CodeInvalidCredentials, "The user name or password is incorrect.")
	}

	admin, err := s.Store.AdminByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) || len(req.Password) > proto.MaxPasswordLen {
		s.Hasher.Burn(ctx, req.Password)
		fail()
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	ok, _, err := s.Hasher.Verify(ctx, admin.PasswordHash, req.Password)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok || admin.Disabled {
		fail()
		return
	}
	s.loginLockout.Success(source)
	s.loginLockout.Success(userKey)

	token, hash := auth.NewOpaqueToken()
	ttl := s.Settings().AdminSessionTTL()
	if err := s.Store.CreateAdminSession(ctx, hash, admin.ID, ttl, source, proto.CleanText(r.UserAgent(), 200)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setAdminCookie(w, r, token, ttl)
	s.Events.Add(store.Event{Level: store.LevelInfo, Kind: "admin.login", AdminID: admin.ID, Actor: admin.Username, Addr: source, Message: "signed in to the dashboard"})
	writeJSON(w, http.StatusOK, map[string]any{"admin": toAdminDTO(admin)})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(adminCookie); err == nil && cookie.Value != "" {
		if err := s.Store.DeleteAdminSession(r.Context(), auth.HashOpaqueToken(cookie.Value)); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.clearAdminCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"admin": toAdminDTO(currentAdmin(r))})
}

func validAdminPassword(pw string) string {
	if len(pw) < minAdminPasswordLen {
		return "An administrator password must be at least 10 characters long."
	}
	if len(pw) > proto.MaxPasswordLen {
		return "That password is too long."
	}
	return ""
}

func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	admin := currentAdmin(r)
	ctx := r.Context()
	ok, _, err := s.Hasher.Verify(ctx, admin.PasswordHash, req.Current)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, proto.CodeInvalidCredentials, "Your current password is incorrect.")
		return
	}
	if msg := validAdminPassword(req.New); msg != "" {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, msg)
		return
	}
	hash, err := s.Hasher.Hash(ctx, req.New)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// UpdateAdmin ends every session of the account, including this one, so
	// a fresh session is issued for the browser that made the change.
	if _, err := s.Store.UpdateAdmin(ctx, admin.ID, store.AdminPatch{PasswordHash: &hash}); err != nil {
		s.serverError(w, r, err)
		return
	}
	token, tokenHash := auth.NewOpaqueToken()
	ttl := s.Settings().AdminSessionTTL()
	if err := s.Store.CreateAdminSession(ctx, tokenHash, admin.ID, ttl, s.clientIP(r).String(), proto.CleanText(r.UserAgent(), 200)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setAdminCookie(w, r, token, ttl)
	s.audit(r, "admin.password", 0, "changed their own password")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// audit records an action taken by the signed-in administrator, and tells
// every open dashboard that something changed so that a second administrator
// is not left looking at a stale page.
func (s *Server) audit(r *http.Request, kind string, roomID int64, message string) {
	a := currentAdmin(r)
	s.Events.Add(store.Event{Level: store.LevelInfo, Kind: kind, RoomID: roomID, AdminID: a.ID, Actor: a.Username, Addr: s.clientIP(r).String(), Message: message})
	s.Hub.Notify()
}

func (s *Server) handleListAdmins(w http.ResponseWriter, r *http.Request) {
	admins, err := s.Store.ListAdmins(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	out := make([]adminDTO, 0, len(admins))
	for _, a := range admins {
		out = append(out, toAdminDTO(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"admins": out})
}

func validUsername(u string) bool {
	if len(u) < 2 || len(u) > maxAdminUsernameLen {
		return false
	}
	for _, c := range u {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func (s *Server) handleCreateAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !validUsername(req.Username) {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "A user name is 2 to 32 letters, digits, dots, dashes or underscores.")
		return
	}
	if !store.ValidRole(req.Role) {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "Role must be owner, admin or viewer.")
		return
	}
	if msg := validAdminPassword(req.Password); msg != "" {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, msg)
		return
	}
	hash, err := s.Hasher.Hash(r.Context(), req.Password)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	admin, err := s.Store.CreateAdmin(r.Context(), req.Username, hash, req.Role)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, proto.CodeConflict, "That user name is already taken.")
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "admin.account.create", 0, "created "+req.Role+" account \""+admin.Username+"\"")
	writeJSON(w, http.StatusCreated, map[string]any{"admin": toAdminDTO(admin)})
}

func (s *Server) handleUpdateAdmin(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
	}
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	ctx := r.Context()
	target, err := s.Store.Admin(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, proto.CodeNotFound, "No such account.")
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}

	patch := store.AdminPatch{Disabled: req.Disabled}
	if req.Role != nil {
		if !store.ValidRole(*req.Role) {
			writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "Role must be owner, admin or viewer.")
			return
		}
		patch.Role = req.Role
	}
	// The server must always keep at least one owner who can sign in.
	losesOwner := target.Role == store.RoleOwner && !target.Disabled &&
		((patch.Role != nil && *patch.Role != store.RoleOwner) || (patch.Disabled != nil && *patch.Disabled))
	if losesOwner {
		if n, err := s.Store.CountActiveOwners(ctx); err != nil {
			s.serverError(w, r, err)
			return
		} else if n <= 1 {
			writeError(w, http.StatusConflict, proto.CodeConflict, "This is the only active owner account. Make another account an owner first.")
			return
		}
	}
	if req.Password != nil {
		if msg := validAdminPassword(*req.Password); msg != "" {
			writeError(w, http.StatusBadRequest, proto.CodeBadRequest, msg)
			return
		}
		hash, err := s.Hasher.Hash(ctx, *req.Password)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		patch.PasswordHash = &hash
	}
	updated, err := s.Store.UpdateAdmin(ctx, id, patch)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "admin.account.update", 0, "updated account \""+updated.Username+"\"")
	writeJSON(w, http.StatusOK, map[string]any{"admin": toAdminDTO(updated)})
}

func (s *Server) handleDeleteAdmin(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	ctx := r.Context()
	target, err := s.Store.Admin(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, proto.CodeNotFound, "No such account.")
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	if target.Role == store.RoleOwner && !target.Disabled {
		if n, err := s.Store.CountActiveOwners(ctx); err != nil {
			s.serverError(w, r, err)
			return
		} else if n <= 1 {
			writeError(w, http.StatusConflict, proto.CodeConflict, "This is the only active owner account and cannot be deleted.")
			return
		}
	}
	if err := s.Store.DeleteAdmin(ctx, id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "admin.account.delete", 0, "deleted account \""+target.Username+"\"")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
