// Package daemon is the long-running half of the Lanora client. It owns the
// room connection and the saved settings, and serves the window over the
// local channel defined in package ipc. On Windows it runs inside the Lanora
// service; elsewhere "lanora-cli daemon" runs it.
package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"lanora/internal/client/control"
	"lanora/internal/client/engine"
	"lanora/internal/client/ipc"
	"lanora/internal/client/netcfg"
	"lanora/internal/client/settings"
	"lanora/internal/proto"
	"lanora/internal/version"
)

// Options configures a Daemon.
type Options struct {
	Store       *settings.Store
	OpenAdapter netcfg.OpenFunc
	Logger      *slog.Logger
	// Diagnostics, if set, adds platform-specific detail to the
	// troubleshooting report.
	Diagnostics func() string
}

// Daemon runs room connections on behalf of local windows.
type Daemon struct {
	opts Options
	log  *slog.Logger
	host string

	mu     sync.Mutex
	state  engine.State // last state reported by the engine
	eng    *engine.Engine
	cancel context.CancelFunc
	done   chan struct{} // closed when the current engine has fully stopped
	subs   map[chan ipc.Status]struct{}
}

// New returns a daemon with no connection.
func New(opts Options) *Daemon {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	host, _ := os.Hostname()
	return &Daemon{
		opts: opts,
		log:  opts.Logger.With("component", "daemon"),
		host: host,
		subs: make(map[chan ipc.Status]struct{}),
	}
}

// Serve answers windows connecting to ln until ctx is cancelled, then leaves
// the room and returns.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var conns sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			d.log.Warn("accepting a local connection", "err", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		conns.Add(1)
		go func() {
			defer conns.Done()
			d.serveConn(ctx, conn)
		}()
	}
	d.stopEngine()
	conns.Wait()
	return nil
}

// AutoConnect rejoins the remembered room if the user asked for that. It is
// called once when the daemon starts.
func (d *Daemon) AutoConnect() {
	s := d.opts.Store.Settings()
	if !s.AutoConnect || !s.Remember || s.Server == "" || s.RoomID == "" || d.opts.Store.Password() == "" {
		return
	}
	// At start-up (often at boot, before the network is ready) the server
	// may not be reachable yet: keep trying rather than giving up.
	err := d.connect(ipc.ConnectArgs{Server: s.Server, RoomID: s.RoomID, Nickname: s.Nickname, Remember: true}, true)
	if err != nil {
		d.log.Warn("automatic connection not started", "err", err)
	}
}

// Rebind tells the connection that the machine's network may have changed
// (it resumed from sleep, for instance).
func (d *Daemon) Rebind() {
	d.mu.Lock()
	eng := d.eng
	d.mu.Unlock()
	if eng != nil {
		eng.Rebind()
	}
}

// connect starts joining a room, leaving any current one first.
func (d *Daemon) connect(args ipc.ConnectArgs, persistent bool) error {
	addr, err := control.ParseAddress(args.Server)
	if err != nil {
		return err
	}
	room, err := proto.NormalizeRoomID(args.RoomID)
	if err != nil {
		return errors.New("A room ID is 9 letters and digits, for example 7KQ-2MX-9DW.")
	}
	nickname := proto.CleanNickname(args.Nickname)
	if nickname == "" {
		nickname = proto.CleanNickname(d.host)
	}
	if nickname == "" {
		nickname = "Lanora user"
	}

	store := d.opts.Store
	password := args.Password
	if password == "" {
		// The window sends no password when the user left the field as it
		// was; that only makes sense for the room the password was saved
		// for.
		if prev := store.Settings(); prev.RoomID == room && prev.Server == addr.String() {
			password = store.Password()
		}
		if password == "" {
			return errors.New("Enter the room password.")
		}
	}
	var save *string
	if args.Remember {
		save = &password
	}
	if err := store.Update(func(s *settings.Settings) {
		s.Server, s.RoomID, s.Nickname, s.Remember = addr.String(), room, nickname, args.Remember
	}, save); err != nil {
		return fmt.Errorf("Lanora could not save its settings: %w", err)
	}
	prefs := store.Settings()

	d.stopEngine()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	eng := engine.New(engine.Options{
		Server:   addr,
		RoomID:   room,
		Password: password,
		Nickname: nickname,
		Identity: store.Identity(),
		Adapter: netcfg.Config{
			Name:           netcfg.DefaultName,
			LANPriority:    prefs.LANPriority,
			PrivateNetwork: prefs.PrivateNetwork,
		},
		OpenAdapter: d.opts.OpenAdapter,
		RelayOnly:   prefs.RelayOnly,
		Persistent:  persistent,
		Logger:      d.opts.Logger,
		OnState:     func(s engine.State) { d.onState(done, s) },
	})

	d.mu.Lock()
	d.eng, d.cancel, d.done = eng, cancel, done
	d.state = engine.State{Phase: engine.PhaseConnecting, Detail: "Contacting the server…"}
	d.mu.Unlock()
	d.publish()

	go func() {
		defer close(done)
		err := eng.Run(ctx)
		cancel()
		var api *proto.APIError
		if errors.As(err, &api) && api.Code == proto.CodeInvalidCredentials {
			// The remembered password is wrong (it was changed, or mistyped
			// when it was saved). Forget it so the window asks again
			// instead of offering to reuse it.
			forget := ""
			store.Update(func(*settings.Settings) {}, &forget)
			d.publish()
		}
	}()
	return nil
}

// onState receives the engine's state. States from an engine that has been
// replaced are ignored.
func (d *Daemon) onState(owner chan struct{}, s engine.State) {
	d.mu.Lock()
	if d.done != owner {
		d.mu.Unlock()
		return
	}
	d.state = s
	d.mu.Unlock()
	d.publish()
}

// stopEngine leaves the current room, if any, and waits until the adapter
// is gone.
func (d *Daemon) stopEngine() {
	d.mu.Lock()
	cancel, done := d.cancel, d.done
	d.eng, d.cancel, d.done = nil, nil, nil
	d.state = engine.State{}
	d.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (d *Daemon) disconnect() {
	d.stopEngine()
	d.publish()
}

// Status returns what the window shows.
func (d *Daemon) Status() ipc.Status {
	d.mu.Lock()
	s := d.state
	d.mu.Unlock()

	c := ipc.Connection{
		Phase: s.Phase.String(), Detail: s.Detail, Error: s.Error, ErrorCode: string(s.ErrorCode),
		RoomID: s.Room.ID, RoomName: s.Room.Name, Nickname: s.Nickname, Since: s.Since,
		Relay: s.Relay, Rx: s.Rx, Tx: s.Tx, Peers: make([]ipc.Peer, 0, len(s.Peers)),
	}
	if s.IP.IsValid() {
		c.IP, c.Subnet = s.IP.String(), s.Room.Subnet.String()
	}
	if s.PublicAddr.IsValid() {
		c.PublicAddr = s.PublicAddr.String()
	}
	for _, p := range s.Peers {
		peer := ipc.Peer{IP: p.IP.String(), Nickname: p.Nickname, Via: p.Via, RTTms: -1}
		if p.Addr.IsValid() {
			peer.Addr = p.Addr.String()
		}
		if p.RTT >= 0 {
			peer.RTTms = int(p.RTT.Round(time.Millisecond) / time.Millisecond)
		}
		c.Peers = append(c.Peers, peer)
	}
	return ipc.Status{
		Version:     version.Version,
		Hostname:    d.host,
		Connection:  c,
		Settings:    d.opts.Store.Settings(),
		HasPassword: d.opts.Store.Password() != "",
	}
}

// publish sends the current status to every connected window.
func (d *Daemon) publish() {
	st := d.Status()
	d.mu.Lock()
	for ch := range d.subs {
		// A window that has not picked up the previous status gets the new
		// one in its place: only the latest matters.
		select {
		case ch <- st:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- st:
			default:
			}
		}
	}
	d.mu.Unlock()
}

func (d *Daemon) updateSettings(a ipc.SettingsArgs) error {
	server := ""
	if a.Server != nil && *a.Server != "" {
		addr, err := control.ParseAddress(*a.Server)
		if err != nil {
			return err
		}
		server = addr.String()
	}
	err := d.opts.Store.Update(func(s *settings.Settings) {
		if a.Server != nil {
			s.Server = server
		}
		if a.AutoConnect != nil {
			s.AutoConnect = *a.AutoConnect
		}
		if a.LANPriority != nil {
			s.LANPriority = *a.LANPriority
		}
		if a.PrivateNetwork != nil {
			s.PrivateNetwork = *a.PrivateNetwork
		}
		if a.RelayOnly != nil {
			s.RelayOnly = *a.RelayOnly
		}
	}, nil)
	if err != nil {
		return fmt.Errorf("Lanora could not save its settings: %w", err)
	}
	return nil
}

// serveConn handles one window.
func (d *Daemon) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	var writeMu sync.Mutex
	enc := json.NewEncoder(conn)
	send := func(r ipc.Response) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return enc.Encode(r)
	}

	// Status events for this window.
	sub := make(chan ipc.Status, 1)
	d.mu.Lock()
	d.subs[sub] = struct{}{}
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.subs, sub)
		d.mu.Unlock()
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case st := <-sub:
				raw, _ := json.Marshal(st)
				if send(ipc.Response{Event: ipc.EventStatus, Result: raw}) != nil {
					cancel()
					return
				}
			}
		}
	}()

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 16<<10), 256<<10)
	for sc.Scan() {
		var req ipc.Request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			return
		}
		result, err := d.handle(req)
		resp := ipc.Response{ID: req.ID}
		if err != nil {
			resp.Error = err.Error()
		} else if result != nil {
			resp.Result, _ = json.Marshal(result)
		}
		if send(resp) != nil {
			return
		}
	}
}

// handle performs one request and returns its result.
func (d *Daemon) handle(req ipc.Request) (any, error) {
	switch req.Op {
	case ipc.OpStatus:
		return d.Status(), nil

	case ipc.OpConnect:
		var args ipc.ConnectArgs
		if err := json.Unmarshal(req.Args, &args); err != nil {
			return nil, errors.New("malformed request")
		}
		return nil, d.connect(args, false)

	case ipc.OpDisconnect:
		d.disconnect()
		return nil, nil

	case ipc.OpSettings:
		var args ipc.SettingsArgs
		if err := json.Unmarshal(req.Args, &args); err != nil {
			return nil, errors.New("malformed request")
		}
		if err := d.updateSettings(args); err != nil {
			return nil, err
		}
		d.publish()
		return d.Status(), nil

	case ipc.OpDiagnostics:
		return d.diagnostics(), nil
	}
	return nil, fmt.Errorf("this version of the Lanora service does not understand %q; update Lanora", req.Op)
}

// diagnostics returns a plain-text troubleshooting report.
func (d *Daemon) diagnostics() string {
	st := d.Status()
	c := st.Connection
	out := fmt.Sprintf("Lanora %s on %s\nTime: %s\n\nConnection: %s", st.Version, st.Hostname, time.Now().Format(time.RFC3339), c.Phase)
	if c.Detail != "" {
		out += " (" + c.Detail + ")"
	}
	if c.Error != "" {
		out += "\nLast error: " + c.Error
	}
	if c.IP != "" {
		relay := c.Relay
		if relay == "" {
			relay = "not reachable"
		}
		out += fmt.Sprintf("\nRoom: %s (%s)\nVirtual address: %s in %s\nRelay: %s\nPublic address seen by the relay: %s\n",
			c.RoomName, proto.FormatRoomID(c.RoomID), c.IP, c.Subnet, relay, orDash(c.PublicAddr))
		for _, p := range c.Peers {
			rtt := "-"
			if p.RTTms >= 0 {
				rtt = fmt.Sprintf("%d ms", p.RTTms)
			}
			out += fmt.Sprintf("  %-15s %-20s %-7s %-22s %s\n", p.IP, p.Nickname, p.Via, orDash(p.Addr), rtt)
		}
	}
	s := st.Settings
	out += fmt.Sprintf("\nServer: %s\nLAN priority: %v, private network: %v, relay only: %v, connect at start: %v\n",
		orDash(s.Server), s.LANPriority, s.PrivateNetwork, s.RelayOnly, s.AutoConnect)
	if d.opts.Diagnostics != nil {
		out += "\n" + d.opts.Diagnostics()
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
