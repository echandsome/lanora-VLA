// Command lanora-bench is the load generator for a Lanora server.
//
// It signs in as an administrator, creates rooms, and fills them with
// simulated clients. Two kinds of client are available:
//
//	-mode signal   lightweight: joins, holds a signalling session and sends
//	               the periodic messages a real client sends. Thousands fit
//	               in one process; use it to size the control plane.
//	-mode full     the real client engine with a null network adapter:
//	               WireGuard, path discovery and relay binding all run. Use
//	               it to exercise peer-to-peer set-up and the relay, and to
//	               give the dashboard something real to show.
//
// Simulated clients all come from one address, so the server's per-address
// rate limits would throttle them. Start the server with
// LANORA_TRUSTED_PROXIES=<the generator's address> and each client will
// present its own forwarded address instead.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"lanora/internal/client/control"
	"lanora/internal/client/engine"
	"lanora/internal/client/netcfg"
	"lanora/internal/proto"
	"lanora/internal/tlspin"
)

func main() {
	var (
		server   = flag.String("server", "https://127.0.0.1:8443", "server address (with #pin=... for a self-signed server)")
		user     = flag.String("admin-user", "admin", "administrator user name")
		adminPW  = flag.String("admin-password", os.Getenv("LANORA_ADMIN_PASSWORD"), "administrator password (env LANORA_ADMIN_PASSWORD)")
		rooms    = flag.Int("rooms", 10, "rooms to create")
		perRoom  = flag.Int("clients", 10, "clients per room")
		mode     = flag.String("mode", "signal", "signal or full (see the package documentation)")
		ramp     = flag.Int("ramp", 100, "clients started per second")
		duration = flag.Duration("duration", 30*time.Second, "how long to hold the load once every client is started")
		keep     = flag.Bool("keep", false, "leave the rooms in place on exit")
		joinRoom = flag.String("room", "", "join this existing room instead of creating rooms (with -room-password)")
		roomPW   = flag.String("room-password", "", "password of the room given with -room")
		names    = flag.String("names", "", "comma-separated nicknames for the clients (default bench-00001, ...)")
		relayed  = flag.Bool("relay-only", false, "with -mode full: clients never connect directly, so all their traffic uses the relay")
		spoof    = flag.Bool("forwarded", true, "give every client its own X-Forwarded-For address")
	)
	flag.Parse()
	if (*adminPW == "" && *joinRoom == "") || (*mode != "signal" && *mode != "full") || *rooms < 1 || *perRoom < 1 || *perRoom > 253 {
		fmt.Fprintln(os.Stderr, "lanora-bench: need -admin-password (or -room), -mode signal|full, -rooms >= 1, -clients 1..253")
		os.Exit(2)
	}
	addr, err := control.ParseAddress(*server)
	if err != nil {
		fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *names != "" {
		nicknames = strings.Split(*names, ",")
	}
	relayOnly = *relayed

	if *joinRoom != "" {
		// Fill one existing room and stay there until interrupted.
		st := &stats{}
		var wg sync.WaitGroup
		for i := 0; i < *perRoom; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if *mode == "full" {
					runFull(ctx, addr, *joinRoom, *roomPW, i, nil, st)
				} else {
					runSignal(ctx, addr, *joinRoom, *roomPW, i, nil, st)
				}
			}(i)
		}
		select {
		case <-ctx.Done():
		case <-time.After(*duration):
			stop()
		}
		wg.Wait()
		st.report(*perRoom)
		return
	}

	admin, err := newAdmin(addr, *user, *adminPW)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("creating %d rooms for %d clients each (%d clients, mode %s)\n", *rooms, *perRoom, *rooms**perRoom, *mode)
	const password = "bench-room-password"
	var created []benchRoom
	for i := 0; i < *rooms; i++ {
		r, err := admin.createRoom(fmt.Sprintf("bench %03d", i+1), password, max(*perRoom, 2))
		if err != nil {
			fatal(fmt.Errorf("creating room: %w", err))
		}
		created = append(created, r)
	}
	if !*keep {
		defer func() {
			for _, r := range created {
				admin.do("DELETE", fmt.Sprintf("/api/admin/rooms/%d", r.ID), nil, nil)
			}
			fmt.Println("rooms removed")
		}()
	}

	before, _ := admin.overview()
	st := &stats{}
	var wg sync.WaitGroup
	total := *rooms * *perRoom
	interval := time.Second / time.Duration(max(*ramp, 1))
	start := time.Now()
launch:
	for i := 0; i < total; i++ {
		select {
		case <-ctx.Done():
			break launch
		case <-time.After(interval):
		}
		room := created[i%len(created)]
		var hdr http.Header
		if *spoof {
			// A distinct documentation-range address per client.
			hdr = http.Header{"X-Forwarded-For": {fmt.Sprintf("198.51.%d.%d", 100+i/250%100, 1+i%250)}}
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if *mode == "full" {
				runFull(ctx, addr, room.PublicID, password, i, hdr, st)
			} else {
				runSignal(ctx, addr, room.PublicID, password, i, hdr, st)
			}
		}(i)
	}
	fmt.Printf("all clients started in %s; holding for %s\n", time.Since(start).Round(time.Millisecond), *duration)

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	deadline := time.After(*duration)
hold:
	for {
		select {
		case <-ctx.Done():
			break hold
		case <-deadline:
			break hold
		case <-tick.C:
			ov, err := admin.overview()
			if err != nil {
				fmt.Println("  overview:", err)
				continue
			}
			fmt.Printf("  server: %d online in %d rooms | cpu %.0f%% rss %s heap %s goroutines %d files %d | relay %d sessions, %s forwarded | client side: %d connected, %d failed\n",
				ov.Live.Online, ov.Live.ActiveRooms, ov.Live.System.CPUPercent, mb(ov.Live.System.RSSBytes), mb(ov.Live.System.HeapBytes),
				ov.Live.System.Goroutines, ov.Live.System.OpenFDs, relaySessions(ov), mb(relayBytes(ov)), st.connected.Load(), st.failed.Load())
		}
	}

	after, _ := admin.overview()
	st.report(total)
	if before != nil && after != nil {
		// Heap in use is the figure that scales with clients. Resident
		// memory also holds what the runtime has freed but not yet returned
		// to the operating system, such as the password-hashing buffers of
		// a burst of joins.
		online := after.Live.Online - before.Live.Online
		grew := int64(after.Live.System.HeapBytes) - int64(before.Live.System.HeapBytes)
		fmt.Printf("server heap: %s → %s", mb(before.Live.System.HeapBytes), mb(after.Live.System.HeapBytes))
		// Only meaningful with enough clients to dwarf the fixed costs and
		// the garbage left by password hashing.
		if online >= 500 && grew > 0 {
			fmt.Printf("  (%.1f KiB per connected client, including uncollected garbage)", float64(grew)/float64(online)/1024)
		}
		fmt.Printf("\nserver resident memory: %s → %s", mb(before.Live.System.RSSBytes), mb(after.Live.System.RSSBytes))
		fmt.Printf("\nserver goroutines: %d → %d, open files: %d → %d\n",
			before.Live.System.Goroutines, after.Live.System.Goroutines, before.Live.System.OpenFDs, after.Live.System.OpenFDs)
	}
	stop()
	wg.Wait()
}

// nicknames, when set, names the first clients; the rest are numbered.
var nicknames []string

// relayOnly makes full-mode clients avoid direct connections.
var relayOnly bool

func nickname(n int) string {
	if n < len(nicknames) && strings.TrimSpace(nicknames[n]) != "" {
		return strings.TrimSpace(nicknames[n])
	}
	return fmt.Sprintf("bench-%05d", n+1)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "lanora-bench:", err)
	os.Exit(1)
}

func mb(b uint64) string { return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20)) }

// stats collects client-side results.
type stats struct {
	connected atomic.Int64
	failed    atomic.Int64
	mu        sync.Mutex
	joins     []time.Duration
	errors    map[string]int
}

func (s *stats) joined(d time.Duration) {
	s.connected.Add(1)
	s.mu.Lock()
	s.joins = append(s.joins, d)
	s.mu.Unlock()
}

func (s *stats) fail(err error) {
	s.failed.Add(1)
	s.mu.Lock()
	if s.errors == nil {
		s.errors = map[string]int{}
	}
	msg := err.Error()
	if len(msg) > 90 {
		msg = msg[:90] + "…"
	}
	s.errors[msg]++
	s.mu.Unlock()
}

func (s *stats) report(total int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sort.Slice(s.joins, func(i, j int) bool { return s.joins[i] < s.joins[j] })
	fmt.Printf("\nclients: %d started, %d entered their room, %d failed\n", total, len(s.joins), s.failed.Load())
	if n := len(s.joins); n > 0 {
		pct := func(p float64) time.Duration { return s.joins[min(n-1, int(float64(n)*p))].Round(time.Millisecond) }
		fmt.Printf("time to enter a room (join + session): median %s, 95%% %s, 99%% %s, slowest %s\n",
			pct(0.50), pct(0.95), pct(0.99), s.joins[n-1].Round(time.Millisecond))
	}
	for msg, n := range s.errors {
		fmt.Printf("  %5d × %s\n", n, msg)
	}
}

// runSignal is a lightweight client: it keeps a signalling session open and
// behaves on it the way a real client does.
func runSignal(ctx context.Context, addr control.Address, room, password string, n int, hdr http.Header, st *stats) {
	_, identity, _ := ed25519.GenerateKey(rand.Reader)
	cl := control.New(addr, identity)
	cl.Header = hdr
	defer cl.Close()

	begin := time.Now()
	join, err := cl.Join(ctx, room, password, nickname(n))
	if err != nil {
		if ctx.Err() == nil {
			st.fail(err)
		}
		return
	}
	var wg, disco proto.Key32
	rand.Read(wg[:])
	rand.Read(disco[:])
	endpoints := []netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(1 + n%250)}), uint16(20000+n%40000))}
	sess, err := cl.OpenSession(ctx, join.Token, proto.Msg{WGPub: &wg, DiscoPub: &disco, Endpoints: endpoints})
	if err != nil {
		if ctx.Err() == nil {
			st.fail(err)
		}
		return
	}
	defer sess.Close()
	first, err := sess.Read(ctx)
	if err != nil || first.T != proto.MsgWelcome {
		if ctx.Err() == nil {
			st.fail(fmt.Errorf("no welcome: %v", err))
		}
		return
	}
	st.joined(time.Since(begin))
	cl.Close() // the connection used to join is no longer needed

	// What a real client sends while idle: a keepalive ping every 25
	// seconds and a path report every minute.
	go func() {
		status := time.NewTicker(time.Minute)
		defer status.Stop()
		ping := time.NewTicker(25 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-status.C:
				if sess.Write(ctx, proto.Msg{T: proto.MsgStatus, Status: &proto.StatusReport{}}) != nil {
					return
				}
			case <-ping.C:
				if sess.Ping(ctx) != nil {
					return
				}
			}
		}
	}()
	for {
		if _, err := sess.Read(ctx); err != nil {
			if ctx.Err() == nil {
				st.connected.Add(-1)
				st.fail(fmt.Errorf("session lost: %w", err))
			}
			return
		}
	}
}

// runFull runs the real client engine without an operating-system adapter.
func runFull(ctx context.Context, addr control.Address, room, password string, n int, hdr http.Header, st *stats) {
	_, identity, _ := ed25519.GenerateKey(rand.Reader)
	begin := time.Now()
	var once sync.Once
	eng := engine.New(engine.Options{
		Server:        addr,
		RoomID:        room,
		Password:      password,
		Nickname:      nickname(n),
		Identity:      identity,
		AllowLoopback: true,
		RelayOnly:     relayOnly,
		Header:        hdr,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		OpenAdapter:   func(netcfg.Config) (netcfg.Adapter, error) { return newNullAdapter(), nil },
		OnState: func(s engine.State) {
			if s.Phase == engine.PhaseConnected {
				once.Do(func() { st.joined(time.Since(begin)) })
			}
		},
	})
	if err := eng.Run(ctx); err != nil && ctx.Err() == nil {
		st.fail(err)
	}
}

// nullAdapter is a network adapter that never produces a packet and
// discards what it is given.
type nullAdapter struct {
	closed chan struct{}
	once   sync.Once
	events chan tun.Event
}

func newNullAdapter() *nullAdapter {
	return &nullAdapter{closed: make(chan struct{}), events: make(chan tun.Event)}
}

func (a *nullAdapter) Device() tun.Device       { return nullDevice{a} }
func (a *nullAdapter) File() *os.File           { return nil }
func (a *nullAdapter) MTU() (int, error)        { return 1280, nil }
func (a *nullAdapter) Name() string             { return "null" }
func (a *nullAdapter) Events() <-chan tun.Event { return a.events }
func (a *nullAdapter) BatchSize() int           { return 1 }
func (a *nullAdapter) Close() error             { a.once.Do(func() { close(a.closed) }); return nil }

func (a *nullAdapter) Read([][]byte, []int, int) (int, error) {
	<-a.closed
	return 0, os.ErrClosed
}

func (a *nullAdapter) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

// nullDevice adapts nullAdapter to tun.Device, whose Name has another
// signature than netcfg.Adapter's.
type nullDevice struct{ *nullAdapter }

func (d nullDevice) Name() (string, error) { return "null", nil }

// admin is a minimal client for the administrator API.
type admin struct {
	base string
	http *http.Client
}

type benchRoom struct {
	ID       int64  `json:"id"`
	PublicID string `json:"public_id"`
}

type overview struct {
	Live struct {
		Online      int `json:"online"`
		ActiveRooms int `json:"active_rooms"`
		Relay       *struct {
			Sessions int    `json:"sessions"`
			Bytes    uint64 `json:"bytes"`
		} `json:"relay"`
		System struct {
			CPUPercent float64 `json:"cpu_percent"`
			RSSBytes   uint64  `json:"rss_bytes"`
			HeapBytes  uint64  `json:"heap_bytes"`
			Goroutines int     `json:"goroutines"`
			OpenFDs    int     `json:"open_fds"`
		} `json:"system"`
	} `json:"live"`
}

func relaySessions(o *overview) int {
	if o.Live.Relay == nil {
		return 0
	}
	return o.Live.Relay.Sessions
}

func relayBytes(o *overview) uint64 {
	if o.Live.Relay == nil {
		return 0
	}
	return o.Live.Relay.Bytes
}

func newAdmin(addr control.Address, user, password string) (*admin, error) {
	jar, _ := cookiejar.New(nil)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if addr.Pin != "" {
		tlsCfg = tlspin.Config(addr.Pin)
	}
	a := &admin{base: addr.Base.String(), http: &http.Client{
		Jar: jar, Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}}
	err := a.do("POST", "/api/admin/login", map[string]string{"username": user, "password": password}, nil)
	if err != nil {
		return nil, fmt.Errorf("administrator sign-in: %w", err)
	}
	return a, nil
}

func (a *admin) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, _ := json.Marshal(in)
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, a.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var er proto.ErrorResponse
		if json.Unmarshal(raw, &er) == nil && er.Error.Message != "" {
			return fmt.Errorf("%s (HTTP %d)", er.Error.Message, resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (a *admin) createRoom(name, password string, capacity int) (benchRoom, error) {
	var out struct {
		Room benchRoom `json:"room"`
	}
	err := a.do("POST", "/api/admin/rooms", map[string]any{"name": name, "password": password, "capacity": capacity}, &out)
	return out.Room, err
}

func (a *admin) overview() (*overview, error) {
	var o overview
	if err := a.do("GET", "/api/admin/overview", nil, &o); err != nil {
		return nil, err
	}
	return &o, nil
}
