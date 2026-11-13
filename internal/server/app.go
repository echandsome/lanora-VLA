// Package server assembles the Lanora server from its parts and runs it.
package server

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"lanora/internal/proto"
	"lanora/internal/server/api"
	"lanora/internal/server/auth"
	"lanora/internal/server/config"
	"lanora/internal/server/hub"
	"lanora/internal/server/relay"
	"lanora/internal/server/store"
	"lanora/internal/server/sysmon"
	"lanora/internal/version"
	"lanora/web"
)

const (
	shutdownGrace   = 10 * time.Second
	maxEventRows    = 500_000
	monitorInterval = 2 * time.Second
	monitorWindow   = 150 // five minutes of history
)

// Run starts the server described by cfg and blocks until ctx is cancelled
// or a component fails. Informational output for the operator (such as a
// generated first password) goes to out.
func Run(ctx context.Context, cfg *config.Config, out io.Writer) error {
	if cfg.Mode == config.ModeRelay {
		return runRelayNode(ctx, cfg, slog.New(newLogHandler(cfg)))
	}
	app, err := New(ctx, cfg, out)
	if err != nil {
		return err
	}
	return app.Run(ctx)
}

// App is a fully assembled control server. New opens the database and
// binds the network ports; Run serves until told to stop.
type App struct {
	cfg *config.Config
	log *slog.Logger

	Store     *store.Store
	Hub       *hub.Hub
	Relay     *relay.Relay // nil when stand-alone relay nodes are configured
	Directory *relay.Directory
	API       *api.Server

	events   *api.EventLog
	monitor  *sysmon.Monitor
	tls      tlsSetup
	listener net.Listener
	http     *http.Server
}

// New builds the server: it opens the database, prepares TLS, binds the
// TCP and UDP ports and, on an empty database, creates the first
// administrator.
func New(ctx context.Context, cfg *config.Config, out io.Writer) (app *App, err error) {
	base := newLogHandler(cfg)
	st, err := store.Open(ctx, cfg.DatabasePath())
	if err != nil {
		return nil, err
	}
	a := &App{cfg: cfg, Store: st}
	defer func() {
		if err != nil {
			a.Close()
		}
	}()

	// Warnings and errors are mirrored into the event log so they show up
	// in the dashboard. The event log itself reports through the plain
	// logger so a database failure cannot feed back into itself.
	a.events = api.NewEventLog(st, slog.New(base))
	a.log = slog.New(api.NewLogHandler(base, a.events))

	master, err := masterSecret(ctx, cfg, st)
	if err != nil {
		return nil, err
	}
	keys := auth.DeriveKeys(master, []byte(cfg.RelaySecret))
	// Each password hash in flight holds 19 MiB; one per core keeps sign-in
	// bursts from monopolising the machine.
	hasher := auth.NewHasher(max(2, runtime.NumCPU()))

	var nodes []relay.Node
	if len(cfg.Relays) == 0 {
		a.Relay = relay.New(relay.Options{Secret: keys.RelaySecret(), Logger: a.log})
		if err := a.Relay.Listen(cfg.RelayListen); err != nil {
			return nil, err
		}
		advertise := cfg.RelayPublic
		if advertise == "" {
			// No host: clients use the one they reached the API at.
			advertise = fmt.Sprintf(":%d", a.Relay.Addr().Port())
		}
		nodes = []relay.Node{{UDP: advertise, WS: proto.PathRelay}}
	} else {
		for _, hostPort := range cfg.Relays {
			nodes = append(nodes, relay.Node{UDP: hostPort, WS: "wss://" + hostPort + proto.PathRelay})
		}
	}
	a.Directory = relay.NewDirectory(keys.RelaySecret(), nodes, a.Relay)

	a.Hub = hub.New(hub.Options{
		Relays: a.Directory,
		Events: a.events.Record,
		Logger: a.log,
		OnLeave: func(memberID int64) {
			tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := st.TouchMember(tctx, memberID); err != nil {
				a.log.Warn("recording last-seen time", "err", err)
			}
		},
	})

	if a.tls, err = prepareTLS(cfg); err != nil {
		return nil, err
	}
	a.monitor = sysmon.New(monitorInterval, monitorWindow)

	dashboard := web.Admin()
	if cfg.AdminDir != "" {
		dashboard = os.DirFS(cfg.AdminDir)
	}
	a.API, err = api.New(ctx, api.Options{
		Config: cfg, Store: st, Hub: a.Hub, Relay: a.Relay, Directory: a.Directory,
		Keys: keys, Hasher: hasher, Events: a.events, Monitor: a.monitor,
		Logger: a.log, Dashboard: dashboard, TLSPin: a.tls.pin,
	})
	if err != nil {
		return nil, err
	}
	if err := bootstrapAdmin(ctx, cfg, st, hasher, out); err != nil {
		return nil, err
	}

	if a.listener, err = net.Listen("tcp", cfg.Listen); err != nil {
		return nil, fmt.Errorf("listen tcp %s: %w", cfg.Listen, err)
	}
	a.http = newHTTPServer(a.API.Handler(), a.tls.config, a.log)
	return a, nil
}

// Addr returns the TCP address the API is listening on.
func (a *App) Addr() net.Addr { return a.listener.Addr() }

// TLSPin returns the certificate pin clients need when the server uses a
// self-signed certificate, or "".
func (a *App) TLSPin() string { return a.tls.pin }

// Close releases everything New acquired. It is only needed when Run is
// not called; Run closes the server itself.
func (a *App) Close() {
	if a.listener != nil {
		a.listener.Close()
	}
	if a.Relay != nil {
		a.Relay.Close()
	}
	a.Store.Close()
}

// Run serves until ctx is cancelled or a component fails, then shuts down.
func (a *App) Run(ctx context.Context) error {
	defer a.Store.Close()
	cfg, log := a.cfg, a.log

	log.Info("Lanora server starting",
		"version", version.Version, "listen", a.listener.Addr().String(), "tls", cfg.TLSMode,
		"relay_builtin", a.Relay != nil, "database", a.Store.Path())
	if a.tls.pin != "" {
		log.Info("self-signed certificate in use: clients must add this pin to the server address",
			"example", "https://<this-host>"+portSuffix(a.listener.Addr().String())+"/#pin="+a.tls.pin)
	}

	// Background work stops when runCtx is cancelled. The event log has its
	// own context because it must outlive everything else to record the
	// shutdown itself.
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	eventsCtx, stopEvents := context.WithCancel(context.Background())
	defer stopEvents()
	a.events.Start(eventsCtx)

	g, gctx := errgroup.WithContext(runCtx)
	g.Go(func() error {
		if err := serveHTTP(a.http, a.listener); err != nil {
			return fmt.Errorf("HTTP server: %w", err)
		}
		return nil
	})
	if a.tls.acme != nil {
		acmeServer := &http.Server{Addr: cfg.ACMEListen, Handler: a.tls.acme, ReadHeaderTimeout: 10 * time.Second}
		g.Go(func() error {
			if err := acmeServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("ACME listener on %s: %w", cfg.ACMEListen, err)
			}
			return nil
		})
		g.Go(func() error {
			<-gctx.Done()
			return acmeServer.Close()
		})
	}
	if a.Relay != nil {
		g.Go(func() error { return a.Relay.Serve(gctx) })
	} else {
		g.Go(func() error {
			a.Directory.Watch(gctx, log, a.Hub.RefreshRelays)
			return nil
		})
	}
	g.Go(func() error { a.monitor.Run(gctx); return nil })
	g.Go(func() error { janitor(gctx, a.Store, a.Hub, a.API, log); return nil })
	if cfg.DebugListen != "" {
		debugServer := &http.Server{Addr: cfg.DebugListen, Handler: profilingHandler(), ReadHeaderTimeout: 10 * time.Second}
		log.Warn("profiling endpoints enabled; they are unauthenticated", "listen", cfg.DebugListen)
		g.Go(func() error {
			if err := debugServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("debug listener on %s: %w", cfg.DebugListen, err)
			}
			return nil
		})
		g.Go(func() error { <-gctx.Done(); return debugServer.Close() })
	}

	// Shut down in order once asked to (or once a component fails).
	g.Go(func() error {
		<-gctx.Done()
		log.Info("shutting down")
		a.Hub.Shutdown("The server is restarting.")
		time.Sleep(300 * time.Millisecond) // let sessions deliver their goodbye
		sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := a.http.Shutdown(sctx); err != nil {
			a.http.Close()
		}
		return nil
	})

	err := g.Wait()
	stopEvents()
	a.events.Wait()
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

// profilingHandler serves Go's runtime profiles. It is mounted on its own
// listener, never on the public one.
func profilingHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

func newLogHandler(cfg *config.Config) slog.Handler {
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "json" {
		return slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.NewTextHandler(os.Stderr, opts)
}

func portSuffix(listen string) string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil || port == "443" {
		return ""
	}
	return ":" + port
}

func newHTTPServer(h http.Handler, tlsCfg *tls.Config, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// TLS handshake noise from port scanners is not worth a log line
		// each; real problems surface through the handlers' own logging.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
}

func serveHTTP(srv *http.Server, ln net.Listener) error {
	var err error
	if srv.TLSConfig != nil {
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// masterSecret returns the secret all tokens are derived from: the
// configured one, or one generated on first start and kept in the database.
func masterSecret(ctx context.Context, cfg *config.Config, st *store.Store) ([]byte, error) {
	if cfg.Secret != "" {
		return []byte(cfg.Secret), nil
	}
	v, err := st.SettingOrInit(ctx, "secret.master", func() string { return hex.EncodeToString(proto.RandomBytes(32)) })
	if err != nil {
		return nil, fmt.Errorf("loading the server secret: %w", err)
	}
	secret, err := hex.DecodeString(v)
	if err != nil || len(secret) < 16 {
		return nil, errors.New("the stored server secret is corrupt")
	}
	return secret, nil
}

// bootstrapAdmin creates the first administrator on an empty database.
func bootstrapAdmin(ctx context.Context, cfg *config.Config, st *store.Store, hasher *auth.Hasher, out io.Writer) error {
	n, err := st.CountAdmins(ctx)
	if err != nil || n > 0 {
		return err
	}
	password, generated := cfg.AdminPassword, false
	if password == "" {
		password, generated = proto.NewRoomPassword(), true
	} else if len(password) < 10 {
		return errors.New("LANORA_ADMIN_PASSWORD must be at least 10 characters long")
	}
	hash, err := hasher.Hash(ctx, password)
	if err != nil {
		return err
	}
	if _, err := st.CreateAdmin(ctx, cfg.AdminUser, hash, store.RoleOwner); err != nil {
		return fmt.Errorf("creating the first administrator: %w", err)
	}
	if generated {
		// Printed directly rather than logged, so the password never
		// reaches the event log or a log aggregator's structured fields.
		line := strings.Repeat("=", 66)
		fmt.Fprintf(out, "\n%s\n  Lanora created the first administrator account:\n\n      user name:  %s\n      password:   %s\n\n  Sign in to the dashboard and change this password.\n  It will not be shown again.\n%s\n\n",
			line, cfg.AdminUser, password, line)
	}
	return nil
}

// janitor does the server's periodic housekeeping.
func janitor(ctx context.Context, st *store.Store, h *hub.Hub, apiServer *api.Server, log *slog.Logger) {
	minute := time.NewTicker(time.Minute)
	defer minute.Stop()
	hourly := time.NewTicker(time.Hour)
	defer hourly.Stop()
	purge := func() {
		pctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if err := st.PurgeAdminSessions(pctx); err != nil {
			log.Warn("purging expired dashboard sessions", "err", err)
		}
		retention := time.Duration(apiServer.Settings().LogRetentionDays) * 24 * time.Hour
		if _, err := st.PurgeEvents(pctx, time.Now().Add(-retention), maxEventRows); err != nil {
			log.Warn("purging old log entries", "err", err)
		}
	}
	purge()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-minute.C:
			h.RenewTickets(now)
		case <-hourly.C:
			purge()
		}
	}
}

// runRelayNode runs a stand-alone relay: the UDP relay plus an HTTP listener
// for the TCP-fallback relay and health checks. It needs no database.
func runRelayNode(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	r := relay.New(relay.Options{Secret: []byte(cfg.RelaySecret), Logger: log})
	if err := r.Listen(cfg.RelayListen); err != nil {
		return err
	}
	defer r.Close()

	tlsCfg, err := prepareTLS(cfg)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("GET "+proto.PathRelay, r)
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", cfg.Listen, err)
	}
	httpServer := newHTTPServer(mux, tlsCfg.config, log)
	log.Info("Lanora relay node starting", "version", version.Version, "listen", listener.Addr().String(), "tls", cfg.TLSMode)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return r.Serve(gctx) })
	g.Go(func() error { return serveHTTP(httpServer, listener) })
	if tlsCfg.acme != nil {
		acmeServer := &http.Server{Addr: cfg.ACMEListen, Handler: tlsCfg.acme, ReadHeaderTimeout: 10 * time.Second}
		g.Go(func() error {
			if err := acmeServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		})
		g.Go(func() error { <-gctx.Done(); return acmeServer.Close() })
	}
	g.Go(func() error {
		<-gctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		return httpServer.Shutdown(sctx)
	})
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
