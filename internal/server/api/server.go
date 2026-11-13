// Package api implements the server's HTTP surface: the client API (hello,
// join, the signalling WebSocket), the administrator API behind the
// dashboard, and the dashboard's static files.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"lanora/internal/proto"
	"lanora/internal/server/auth"
	"lanora/internal/server/config"
	"lanora/internal/server/hub"
	"lanora/internal/server/relay"
	"lanora/internal/server/store"
	"lanora/internal/server/sysmon"
)

// Options carries the Server's dependencies.
type Options struct {
	Config    *config.Config
	Store     *store.Store
	Hub       *hub.Hub
	Relay     *relay.Relay // built-in relay; nil when only stand-alone nodes are used
	Directory *relay.Directory
	Keys      *auth.Keys
	Hasher    *auth.Hasher
	Events    *EventLog
	Monitor   *sysmon.Monitor
	Logger    *slog.Logger
	Dashboard fs.FS
	// TLSPin is the certificate pin clients need for a self-signed server,
	// shown in the dashboard; empty otherwise.
	TLSPin string
}

// Server is the HTTP API.
type Server struct {
	Options
	log      *slog.Logger
	settings settingsCache
	bans     atomic.Pointer[banSet]
	started  time.Time
	static   *staticFiles
	csrf     *http.CrossOriginProtection

	helloLimiter *auth.Limiter
	joinLimiter  *auth.Limiter
	loginLimiter *auth.Limiter
	connLimiter  *auth.Limiter
	joinLockout  *auth.Lockout
	loginLockout *auth.Lockout
}

// New prepares the API server: it loads the stored settings and bans.
func New(ctx context.Context, opts Options) (*Server, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Server{
		Options: opts,
		log:     opts.Logger.With("component", "api"),
		started: time.Now(),
		csrf:    http.NewCrossOriginProtection(),

		// Per source address. Generous enough for a household behind one
		// NAT, tight enough to make guessing impractical.
		helloLimiter: auth.NewLimiter(120, 60),
		joinLimiter:  auth.NewLimiter(30, 20),
		loginLimiter: auth.NewLimiter(20, 10),
		connLimiter:  auth.NewLimiter(120, 60),
		// Five wrong passwords (for one room from one address, or for one
		// dashboard account or address) cause a 30-second lockout, doubling
		// up to 15 minutes while the failures continue.
		joinLockout:  auth.NewLockout(5, 30*time.Second, 15*time.Minute),
		loginLockout: auth.NewLockout(5, 30*time.Second, 15*time.Minute),
	}
	settings, err := loadSettings(ctx, opts.Store)
	if err != nil {
		return nil, err
	}
	s.applySettings(settings)
	if err := s.reloadBans(ctx); err != nil {
		return nil, err
	}
	if opts.Dashboard != nil {
		if s.static, err = newStaticFiles(opts.Dashboard); err != nil {
			return nil, fmt.Errorf("loading dashboard files: %w", err)
		}
	}
	return s, nil
}

// Settings returns the current runtime settings.
func (s *Server) Settings() Settings { return s.settings.get() }

func (s *Server) applySettings(v Settings) {
	s.settings.v.Store(&v)
	if s.Relay != nil {
		s.Relay.SetRateLimit(v.RelayLimitBytes())
	}
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	// Client API.
	mux.HandleFunc("GET "+proto.PathHello, s.handleHello)
	mux.HandleFunc("POST "+proto.PathJoin, s.handleJoin)
	mux.HandleFunc("GET "+proto.PathSession, s.handleSession)
	if s.Relay != nil {
		mux.Handle("GET "+proto.PathRelay, s.Relay)
	}

	// Administrator API. Every route is behind the cross-origin check; all
	// but login require a dashboard session with at least the given role.
	admin := http.NewServeMux()
	admin.HandleFunc("POST /api/admin/login", s.handleLogin)
	admin.HandleFunc("POST /api/admin/logout", s.handleLogout)
	route := func(pattern, role string, h http.HandlerFunc) {
		admin.Handle(pattern, s.requireRole(role, h))
	}
	route("GET /api/admin/me", store.RoleViewer, s.handleMe)
	route("PUT /api/admin/me/password", store.RoleViewer, s.handleChangeOwnPassword)
	route("GET /api/admin/overview", store.RoleViewer, s.handleOverview)
	route("GET /api/admin/stream", store.RoleViewer, s.handleStream)

	route("GET /api/admin/rooms", store.RoleViewer, s.handleListRooms)
	route("POST /api/admin/rooms", store.RoleAdmin, s.handleCreateRoom)
	route("GET /api/admin/rooms/{id}", store.RoleViewer, s.handleGetRoom)
	route("PATCH /api/admin/rooms/{id}", store.RoleAdmin, s.handleUpdateRoom)
	route("DELETE /api/admin/rooms/{id}", store.RoleAdmin, s.handleDeleteRoom)
	route("POST /api/admin/rooms/{id}/password", store.RoleAdmin, s.handleRoomPassword)
	route("POST /api/admin/rooms/{id}/members/{mid}/kick", store.RoleAdmin, s.handleKickMember)
	route("POST /api/admin/rooms/{id}/members/{mid}/ban", store.RoleAdmin, s.handleBanMember)
	route("POST /api/admin/rooms/{id}/members/{mid}/unban", store.RoleAdmin, s.handleUnbanMember)
	route("DELETE /api/admin/rooms/{id}/members/{mid}", store.RoleAdmin, s.handleDeleteMember)

	route("GET /api/admin/connections", store.RoleViewer, s.handleConnections)
	route("GET /api/admin/devices", store.RoleViewer, s.handleDevices)
	route("GET /api/admin/devices/{identity}", store.RoleViewer, s.handleDevice)
	route("GET /api/admin/bans", store.RoleViewer, s.handleListBans)
	route("POST /api/admin/bans", store.RoleAdmin, s.handleAddBan)
	route("DELETE /api/admin/bans/{id}", store.RoleAdmin, s.handleRemoveBan)
	route("GET /api/admin/events", store.RoleViewer, s.handleEvents)
	route("GET /api/admin/settings", store.RoleViewer, s.handleGetSettings)
	route("PUT /api/admin/settings", store.RoleAdmin, s.handlePutSettings)

	route("GET /api/admin/admins", store.RoleOwner, s.handleListAdmins)
	route("POST /api/admin/admins", store.RoleOwner, s.handleCreateAdmin)
	route("PATCH /api/admin/admins/{id}", store.RoleOwner, s.handleUpdateAdmin)
	route("DELETE /api/admin/admins/{id}", store.RoleOwner, s.handleDeleteAdmin)
	// Anything else under /api is a mistake, not a dashboard page: answer in
	// the API's own error format rather than with the dashboard's HTML.
	notFound := func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, proto.CodeNotFound, "No such API endpoint.")
	}
	admin.HandleFunc("/api/admin/", notFound)
	mux.Handle("/api/admin/", s.csrf.Handler(admin))
	mux.HandleFunc("/api/", notFound)
	if s.static != nil {
		mux.Handle("/", s.static)
	}

	return s.recoverer(s.securityHeaders(mux))
}

// recoverer turns a panic in a handler into a 500 response and a log entry
// instead of a dropped connection.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic in HTTP handler", "path", r.URL.Path, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, proto.CodeServerError, "Internal server error.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
		"connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", csp)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if s.isHTTPS(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// isHTTPS reports whether the client reached the server over TLS, either
// directly or through a trusted reverse proxy.
func (s *Server) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return s.fromTrustedProxy(r) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) remoteAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.Config.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s *Server) fromTrustedProxy(r *http.Request) bool {
	a := s.remoteAddr(r)
	return a.IsValid() && s.trusted(a)
}

// clientIP returns the address of the client that made the request. The
// X-Forwarded-For header is honoured only when the connection comes from a
// configured reverse proxy, and then the right-most address that is not
// itself a trusted proxy is used; anything further left is client-supplied
// and cannot be relied on.
func (s *Server) clientIP(r *http.Request) netip.Addr {
	remote := s.remoteAddr(r)
	if !remote.IsValid() || !s.trusted(remote) {
		return remote
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if a = a.Unmap(); !s.trusted(a) {
			return a
		}
	}
	return remote
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code proto.ErrorCode, message string) {
	writeJSON(w, status, proto.ErrorResponse{Error: proto.ErrorBody{Code: code, Message: message}})
}

func writeRateLimited(w http.ResponseWriter, retry time.Duration) {
	secs := max(int(retry.Round(time.Second).Seconds()), 1)
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeJSON(w, http.StatusTooManyRequests, proto.ErrorResponse{Error: proto.ErrorBody{
		Code:       proto.CodeRateLimited,
		Message:    fmt.Sprintf("Too many attempts. Try again in %s.", humanDuration(time.Duration(secs)*time.Second)),
		RetryAfter: secs,
	}})
}

func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	m := int(d.Round(time.Minute).Minutes())
	if m == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", m)
}

// decodeJSON reads a JSON request body of at most limit bytes into v. On
// failure it writes the error response and returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, proto.CodeBadRequest, "Request body is too large.")
		} else {
			writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "Could not read the request body.")
		}
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeError(w, http.StatusBadRequest, proto.CodeBadRequest, "Request body is not valid JSON for this endpoint.")
		return false
	}
	return true
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, auth.ErrBusy) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		// Overload is answered quickly and plainly so clients back off
		// instead of piling up.
		w.Header().Set("Retry-After", "3")
		writeError(w, http.StatusServiceUnavailable, proto.CodeUnavailable, "The server is busy. Try again in a moment.")
		return
	}
	s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, proto.CodeServerError, "Internal server error.")
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "database unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// banSet is the in-memory copy of the server-wide bans, consulted on every
// join and session attempt.
type banSet struct {
	identities map[string]bool
	prefixes   []netip.Prefix
}

func (s *Server) reloadBans(ctx context.Context) error {
	list, err := s.Store.ListBans(ctx)
	if err != nil {
		return err
	}
	set := &banSet{identities: make(map[string]bool)}
	for _, b := range list {
		switch b.Kind {
		case store.BanIdentity:
			set.identities[b.Value] = true
		case store.BanIP:
			if p, err := netip.ParsePrefix(b.Value); err == nil {
				set.prefixes = append(set.prefixes, p)
			}
		}
	}
	s.bans.Store(set)
	return nil
}

func (b *banSet) identity(k proto.Key32) bool { return b.identities[k.Hex()] }

func (b *banSet) addr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range b.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// pathID parses a numeric path parameter, writing a 404 when it is not one.
func pathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, proto.CodeNotFound, "Not found.")
		return 0, false
	}
	return id, true
}

func queryInt(r *http.Request, name string, def int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || v < 0 {
		return def
	}
	return v
}
