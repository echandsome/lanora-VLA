// Package e2e runs the real server and real client engines together in one
// process. Each client gets a userspace TCP/IP stack in place of an
// operating-system adapter, so the tests exercise the whole path (join,
// signalling, WireGuard, path discovery, relay) without privileges.
package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"lanora/internal/client/control"
	"lanora/internal/client/engine"
	"lanora/internal/client/netcfg"
	"lanora/internal/proto"
	"lanora/internal/server"
	"lanora/internal/server/auth"
	"lanora/internal/server/config"
	"lanora/internal/server/store"
)

func testLogger() *slog.Logger {
	level := slog.LevelWarn
	if os.Getenv("LANORA_TEST_DEBUG") != "" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

type testServer struct {
	t      *testing.T
	app    *server.App
	addr   control.Address
	hasher *auth.Hasher
	stop   context.CancelFunc
	done   chan error
}

// startServer runs a complete server on loopback with a fresh database.
func startServer(t *testing.T, env map[string]string) *testServer {
	t.Helper()
	vars := map[string]string{
		"LANORA_DATA_DIR":       t.TempDir(),
		"LANORA_LISTEN":         "127.0.0.1:0",
		"LANORA_RELAY_LISTEN":   "127.0.0.1:0",
		"LANORA_TLS":            "off",
		"LANORA_ADMIN_PASSWORD": "test-admin-password",
		"LANORA_LOG_LEVEL":      "error",
	}
	for k, v := range env {
		vars[k] = v
	}
	cfg, err := config.FromEnv(func(k string) string { return vars[k] })
	if err != nil {
		t.Fatal(err)
	}
	app, err := server.New(context.Background(), cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &testServer{t: t, app: app, hasher: auth.NewHasher(4), stop: cancel, done: make(chan error, 1)}
	go func() { s.done <- app.Run(ctx) }()
	scheme := "http"
	if cfg.TLSMode != config.TLSOff {
		scheme = "https"
	}
	raw := scheme + "://" + app.Addr().String()
	if pin := app.TLSPin(); pin != "" {
		raw += "/#pin=" + pin
	}
	if s.addr, err = control.ParseAddress(raw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.shutdown)
	return s
}

func (s *testServer) shutdown() {
	s.stop()
	select {
	case err := <-s.done:
		if err != nil {
			s.t.Errorf("server exited with: %v", err)
		}
		s.done <- nil
	case <-time.After(20 * time.Second):
		s.t.Errorf("server did not shut down")
	}
}

// room creates a room directly in the database.
func (s *testServer) room(name, password string, capacity int) store.Room {
	s.t.Helper()
	ctx := context.Background()
	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		s.t.Fatal(err)
	}
	r, err := s.app.Store.CreateRoom(ctx, store.NewRoom{
		Name: name, PasswordHash: hash, Capacity: capacity, Pool: s.app.API.Settings().Pool(),
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return r
}

// stackAdapter is a virtual adapter backed by a userspace network stack.
type stackAdapter struct {
	dev tun.Device
	net *netstack.Net
}

func (a *stackAdapter) Device() tun.Device { return a.dev }
func (a *stackAdapter) Name() string       { return "netstack" }
func (a *stackAdapter) Close() error       { return nil }

type testClient struct {
	t    *testing.T
	name string
	eng  *engine.Engine
	stop context.CancelFunc
	done chan error

	mu      sync.Mutex
	cond    *sync.Cond
	state   engine.State
	adapter *stackAdapter
	raw     *chanTUN
}

type clientOpt func(*engine.Options)

// client starts an engine joining the room and returns once it has started;
// use waitConnected to wait for it to enter the room.
func (s *testServer) client(name, roomID, password string, opts ...clientOpt) *testClient {
	s.t.Helper()
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.t.Fatal(err)
	}
	c := &testClient{t: s.t, name: name, done: make(chan error, 1)}
	c.cond = sync.NewCond(&c.mu)
	o := engine.Options{
		Server:        s.addr,
		RoomID:        roomID,
		Password:      password,
		Nickname:      name,
		Identity:      identity,
		AllowLoopback: true,
		Logger:        testLogger().With("client", name),
		OpenAdapter: func(cfg netcfg.Config) (netcfg.Adapter, error) {
			dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.IP}, nil, cfg.MTU)
			if err != nil {
				return nil, err
			}
			a := &stackAdapter{dev: dev, net: tnet}
			c.mu.Lock()
			c.adapter = a
			c.mu.Unlock()
			return a, nil
		},
		OnState: func(st engine.State) {
			c.mu.Lock()
			c.state = st
			c.cond.Broadcast()
			c.mu.Unlock()
		},
	}
	for _, opt := range opts {
		opt(&o)
	}
	c.eng = engine.New(o)
	ctx, cancel := context.WithCancel(context.Background())
	c.stop = cancel
	go func() {
		err := c.eng.Run(ctx)
		c.done <- err
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	}()
	s.t.Cleanup(c.close)
	return c
}

func (c *testClient) close() {
	c.stop()
	select {
	case <-c.done:
		c.done <- nil
	case <-time.After(15 * time.Second):
		c.t.Errorf("%s: engine did not stop", c.name)
	}
}

// wait blocks until pred holds for the client's state, or fails the test.
func (c *testClient) wait(what string, timeout time.Duration, pred func(engine.State) bool) engine.State {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	timer := time.AfterFunc(timeout, func() {
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	})
	defer timer.Stop()
	c.mu.Lock()
	defer c.mu.Unlock()
	for !pred(c.state) {
		if time.Now().After(deadline) {
			c.t.Fatalf("%s: timed out waiting for %s; state: phase=%s detail=%q error=%q peers=%+v relay=%q",
				c.name, what, c.state.Phase, c.state.Detail, c.state.Error, c.state.Peers, c.state.Relay)
		}
		c.cond.Wait()
	}
	return c.state
}

func (c *testClient) waitConnected() engine.State {
	c.t.Helper()
	return c.wait("connected", 20*time.Second, func(s engine.State) bool {
		return s.Phase == engine.PhaseConnected || s.Phase == engine.PhaseStopped
	})
}

// waitPeer waits until the client reaches peer ip over the given kind of
// path ("" accepts direct or relay).
func (c *testClient) waitPeer(ip netip.Addr, via string, timeout time.Duration) engine.Peer {
	c.t.Helper()
	var found engine.Peer
	c.wait(fmt.Sprintf("peer %s via %q", ip, via), timeout, func(s engine.State) bool {
		for _, p := range s.Peers {
			if p.IP == ip && ((via == "" && p.Via != proto.ViaNone) || (via != "" && p.Via == via)) {
				found = p
				return true
			}
		}
		return false
	})
	return found
}

// waitStopped waits for the engine to give up and returns its error.
func (c *testClient) waitStopped(timeout time.Duration) engine.State {
	c.t.Helper()
	return c.wait("stopped", timeout, func(s engine.State) bool { return s.Phase == engine.PhaseStopped })
}

func (c *testClient) ip() netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.IP
}

func (c *testClient) stack() *netstack.Net {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.adapter.net
}

// echoServer accepts TCP connections on the client's virtual address and
// echoes what it receives.
func (c *testClient) echoServer(port uint16) {
	c.t.Helper()
	ln, err := c.stack().ListenTCPAddrPort(netip.AddrPortFrom(c.ip(), port))
	if err != nil {
		c.t.Fatalf("%s: listen: %v", c.name, err)
	}
	c.t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(conn)
		}
	}()
}

// exchange opens a TCP connection to a peer's echo server across the
// overlay, sends size bytes and checks they come back intact.
func (c *testClient) exchange(to netip.Addr, port uint16, size int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := c.stack().DialContextTCPAddrPort(ctx, netip.AddrPortFrom(to, port))
	if err != nil {
		return fmt.Errorf("dial %s: %w", to, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	sent := make([]byte, size)
	rand.Read(sent)
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(sent)
		errc <- err
	}()
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read echo from %s: %w", to, err)
	}
	if err := <-errc; err != nil {
		return fmt.Errorf("write to %s: %w", to, err)
	}
	for i := range sent {
		if sent[i] != got[i] {
			return fmt.Errorf("echo from %s differs at byte %d", to, i)
		}
	}
	return nil
}

// chanTUN is a raw adapter for tests that need to inject and observe exact
// IP packets (broadcasts), which a TCP/IP stack would not let them do.
type chanTUN struct {
	fromOS chan []byte // packets the "operating system" sends
	toOS   chan []byte // packets delivered to the "operating system"
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func newChanTUN() *chanTUN {
	return &chanTUN{
		fromOS: make(chan []byte, 256), toOS: make(chan []byte, 256),
		events: make(chan tun.Event, 4), closed: make(chan struct{}),
	}
}

func (c *chanTUN) File() *os.File           { return nil }
func (c *chanTUN) MTU() (int, error)        { return 1280, nil }
func (c *chanTUN) Name() (string, error)    { return "chan", nil }
func (c *chanTUN) Events() <-chan tun.Event { return c.events }
func (c *chanTUN) BatchSize() int           { return 1 }
func (c *chanTUN) Close() error             { c.once.Do(func() { close(c.closed) }); return nil }

func (c *chanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-c.closed:
		return 0, os.ErrClosed
	case pkt := <-c.fromOS:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	}
}

func (c *chanTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := append([]byte(nil), b[offset:]...)
		select {
		case c.toOS <- pkt:
		default: // the test is not reading; drop like a full socket buffer
		}
	}
	return len(bufs), nil
}

type rawAdapter struct{ dev *chanTUN }

func (a *rawAdapter) Device() tun.Device { return a.dev }
func (a *rawAdapter) Name() string       { return "chan" }
func (a *rawAdapter) Close() error       { return nil }

// withRawAdapter gives the client a raw packet adapter instead of a stack.
func withRawAdapter(c **chanTUN) clientOpt {
	return func(o *engine.Options) {
		dev := newChanTUN()
		*c = dev
		o.OpenAdapter = func(netcfg.Config) (netcfg.Adapter, error) { return &rawAdapter{dev: dev}, nil }
	}
}

func relayOnly(o *engine.Options) { o.RelayOnly = true }
