// Command lanora-cli joins a Lanora room from a terminal and stays in it
// until interrupted. It is the headless client: the same engine as the
// Windows app, without the window. It must run with the right to create a
// network interface (root, or CAP_NET_ADMIN, on Linux; an elevated prompt
// on Windows).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"lanora/internal/client/control"
	"lanora/internal/client/daemon"
	"lanora/internal/client/engine"
	"lanora/internal/client/ipc"
	"lanora/internal/client/netcfg"
	"lanora/internal/client/settings"
	"lanora/internal/proto"
	"lanora/internal/version"
)

const usage = `Usage: lanora-cli <command> [options]

Commands:
  up        join a room and stay connected until interrupted
  doctor    check this computer before joining anything (Windows; safe to
            run next to another VPN: it creates no adapter)
  daemon    run the background service that the Lanora window talks to
  version   print the version

Run "lanora-cli up -h" for the options of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "up":
		os.Exit(up(os.Args[2:]))
	case "doctor":
		os.Exit(doctor(os.Args[2:]))
	case "daemon":
		os.Exit(runDaemon(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Printf("lanora-cli %s (protocol %d, %s/%s)\n", version.Version, version.Protocol, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "lanora-cli: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

// doctor reports whether this computer is ready for Lanora, without doing
// anything that could disturb another VPN: no adapter is created and the
// network driver library is not loaded.
func doctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	server := fs.String("server", os.Getenv("LANORA_SERVER"), "also check that this server can be reached (env LANORA_SERVER)")
	fs.Parse(args)

	fmt.Printf("Lanora %s (protocol %d) on %s/%s\n\n", version.Version, version.Protocol, runtime.GOOS, runtime.GOARCH)
	failed := 0
	report := func(ok bool, name, detail string) {
		mark := " ok "
		if !ok {
			mark, failed = "FAIL", failed+1
		}
		fmt.Printf("[%s] %s\n       %s\n", mark, name, detail)
	}
	checks := netcfg.Preflight()
	for _, c := range checks {
		report(c.OK, c.Name, c.Detail)
	}
	if len(checks) == 0 {
		fmt.Println("The checks of the network adapter are for Windows; there is nothing to check on this system.")
	}

	if *server != "" {
		addr, err := control.ParseAddress(*server)
		if err != nil {
			report(false, "Server", err.Error())
		} else {
			_, key, _ := ed25519.GenerateKey(rand.Reader) // only a greeting is exchanged; nothing is signed
			cl := control.New(addr, key)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			start := time.Now()
			hello, err := cl.Hello(ctx)
			cancel()
			cl.Close()
			if err != nil {
				report(false, "Server", err.Error())
			} else {
				report(true, "Server", fmt.Sprintf("%q answered in %s: version %s, protocol %d.",
					hello.Server, time.Since(start).Round(time.Millisecond), hello.Version, hello.Protocol))
			}
		}
	}

	if d := netcfg.Diagnostics(); d != "" {
		fmt.Printf("\n%s", d)
	}
	fmt.Println()
	if failed > 0 {
		fmt.Printf("%d check(s) failed. Do not join a room from this computer until they pass.\n", failed)
		return 1
	}
	if len(checks) > 0 {
		fmt.Println("All checks passed.")
	}
	return 0
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func up(args []string) int {
	host, _ := os.Hostname()
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	var (
		server    = fs.String("server", os.Getenv("LANORA_SERVER"), "server address, e.g. https://lan.example.com or https://203.0.113.5:8443/#pin=sha256:... (env LANORA_SERVER)")
		room      = fs.String("room", os.Getenv("LANORA_ROOM"), "room ID (env LANORA_ROOM)")
		password  = fs.String("password", "", "room password; prefer the LANORA_PASSWORD environment variable, which does not show up in process listings")
		nickname  = fs.String("nickname", envOr("LANORA_NICKNAME", host), "name shown to other members (env LANORA_NICKNAME)")
		stateDir  = fs.String("state", os.Getenv("LANORA_STATE_DIR"), "directory for the device identity (env LANORA_STATE_DIR; default: the system location)")
		port      = fs.Uint("port", 0, "local UDP port (default: any free port)")
		relayOnly = fs.Bool("relay-only", false, "never connect directly to other members; send everything through the relay")
		noLAN     = fs.Bool("no-lan-priority", false, "do not make the virtual adapter the preferred interface for broadcasts (Windows)")
		asJSON    = fs.Bool("json", false, "print state changes as JSON lines")
		verbose   = fs.Bool("v", false, "verbose logging")
	)
	fs.Parse(args)

	pw := *password
	if pw == "" {
		pw = os.Getenv("LANORA_PASSWORD")
	}
	if *server == "" || *room == "" || pw == "" {
		fmt.Fprintln(os.Stderr, "lanora-cli: -server, -room and a password are required")
		fs.Usage()
		return 2
	}
	addr, err := control.ParseAddress(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lanora-cli:", err)
		return 2
	}

	dir := *stateDir
	if dir == "" {
		if dir, err = settings.UserDir(); err != nil {
			fmt.Fprintln(os.Stderr, "lanora-cli:", err)
			return 1
		}
	}
	store, err := settings.Open(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lanora-cli:", err)
		return 1
	}

	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	netcfg.LogDriverMessages(logger)

	printer := &statePrinter{json: *asJSON}
	eng := engine.New(engine.Options{
		Server:      addr,
		RoomID:      *room,
		Password:    pw,
		Nickname:    *nickname,
		Identity:    store.Identity(),
		Adapter:     netcfg.Config{Name: netcfg.DefaultName, LANPriority: !*noLAN, PrivateNetwork: true},
		OpenAdapter: netcfg.Open,
		Port:        uint16(*port),
		RelayOnly:   *relayOnly,
		// A terminal session is expected to ride out a server that is
		// briefly unreachable when it starts.
		Persistent: true,
		OnState:    printer.print,
		Logger:     logger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := eng.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "lanora-cli:", err)
		return 1
	}
	return 0
}

// runDaemon serves the Lanora window over the local channel, as the Lanora
// service does on Windows.
func runDaemon(args []string) int {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	stateDir := fs.String("state", os.Getenv("LANORA_STATE_DIR"), "directory for settings and the device identity (env LANORA_STATE_DIR; default: the system location)")
	verbose := fs.Bool("v", false, "verbose logging")
	fs.Parse(args)

	dir := *stateDir
	if dir == "" {
		var err error
		if dir, err = settings.DefaultDir(); err != nil {
			fmt.Fprintln(os.Stderr, "lanora-cli:", err)
			return 1
		}
	}
	store, err := settings.Open(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lanora-cli:", err)
		return 1
	}
	listener, err := ipc.Listen()
	if err != nil {
		fmt.Fprintln(os.Stderr, "lanora-cli:", err)
		return 1
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	netcfg.LogDriverMessages(logger)
	d := daemon.New(daemon.Options{
		Store:       store,
		OpenAdapter: netcfg.Open,
		Logger:      logger,
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d.AutoConnect()
	if err := d.Serve(ctx, listener); err != nil {
		fmt.Fprintln(os.Stderr, "lanora-cli:", err)
		return 1
	}
	return 0
}

// statePrinter writes a line whenever something a person watching the
// terminal would care about changes.
type statePrinter struct {
	json bool
	last string
}

// jsonState is the machine-readable form of a state change.
type jsonState struct {
	Phase     string     `json:"phase"`
	Detail    string     `json:"detail,omitempty"`
	Error     string     `json:"error,omitempty"`
	ErrorCode string     `json:"error_code,omitempty"`
	Room      string     `json:"room,omitempty"`
	RoomID    string     `json:"room_id,omitempty"`
	Subnet    string     `json:"subnet,omitempty"`
	IP        string     `json:"ip,omitempty"`
	Relay     string     `json:"relay"`
	Public    string     `json:"public,omitempty"`
	Peers     []jsonPeer `json:"peers"`
}

type jsonPeer struct {
	IP       string `json:"ip"`
	Nickname string `json:"nickname"`
	Via      string `json:"via"`
	Addr     string `json:"addr,omitempty"`
	RTTms    int    `json:"rtt_ms"`
}

func (p *statePrinter) print(s engine.State) {
	js := jsonState{
		Phase: s.Phase.String(), Detail: s.Detail, Error: s.Error, ErrorCode: string(s.ErrorCode),
		Room: s.Room.Name, RoomID: s.Room.ID, Relay: s.Relay, Peers: []jsonPeer{},
	}
	if s.IP.IsValid() {
		js.IP, js.Subnet = s.IP.String(), s.Room.Subnet.String()
	}
	if s.PublicAddr.IsValid() {
		js.Public = s.PublicAddr.String()
	}
	var text strings.Builder
	fmt.Fprintf(&text, "%s", s.Phase)
	if s.Detail != "" {
		fmt.Fprintf(&text, " (%s)", s.Detail)
	}
	if s.Phase == engine.PhaseConnected || s.Phase == engine.PhaseReconnecting {
		relay := s.Relay
		if relay == "" {
			relay = "unreachable"
		}
		fmt.Fprintf(&text, "  room=%q ip=%s relay=%s", s.Room.Name, s.IP, relay)
	}
	for _, peer := range s.Peers {
		jp := jsonPeer{IP: peer.IP.String(), Nickname: peer.Nickname, Via: peer.Via, RTTms: -1}
		if peer.Addr.IsValid() {
			jp.Addr = peer.Addr.String()
		}
		js.Peers = append(js.Peers, jp)
		// Latency is left out of the comparison below: it changes every
		// second and would turn the output into noise.
		fmt.Fprintf(&text, "\n  %-15s %-20s %s", peer.IP, peer.Nickname, describeVia(peer))
		if peer.RTT >= 0 {
			jp.RTTms = int(peer.RTT.Round(time.Millisecond) / time.Millisecond)
			js.Peers[len(js.Peers)-1] = jp
		}
	}
	key := text.String()
	if key == p.last {
		return
	}
	p.last = key
	if p.json {
		raw, _ := json.Marshal(js)
		fmt.Println(string(raw))
		return
	}
	fmt.Println(time.Now().Format("15:04:05"), key)
}

func describeVia(p engine.Peer) string {
	switch p.Via {
	case proto.ViaDirect:
		return "direct " + p.Addr.String()
	case proto.ViaRelay:
		return "relayed"
	}
	return "connecting"
}
