package e2e

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"

	"lanora/internal/client/daemon"
	"lanora/internal/client/ipc"
	"lanora/internal/client/netcfg"
	"lanora/internal/client/settings"
	"lanora/internal/proto"
)

// testDaemon is a client daemon with a userspace adapter, reachable over a
// Unix socket in a temporary directory, plus a window-side client for it.
type testDaemon struct {
	t      *testing.T
	dir    string
	client *ipc.Client
	stop   context.CancelFunc
	done   chan struct{}
}

func startDaemon(t *testing.T, dir string) *testDaemon {
	t.Helper()
	store, err := settings.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := daemon.New(daemon.Options{
		Store:  store,
		Logger: testLogger(),
		OpenAdapter: func(cfg netcfg.Config) (netcfg.Adapter, error) {
			dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.IP}, nil, cfg.MTU)
			if err != nil {
				return nil, err
			}
			return &stackAdapter{dev: dev, net: tnet}, nil
		},
		Diagnostics: func() string { return "platform section" },
	})
	ln, err := net.Listen("unix", filepath.Join(dir, "d.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	td := &testDaemon{t: t, dir: dir, stop: cancel, done: make(chan struct{})}
	go func() { d.Serve(ctx, ln); close(td.done) }()
	d.AutoConnect()

	conn, err := net.Dial("unix", filepath.Join(dir, "d.sock"))
	if err != nil {
		t.Fatal(err)
	}
	td.client = ipc.NewClient(conn)
	t.Cleanup(td.close)
	return td
}

func (d *testDaemon) close() {
	d.client.Close()
	d.stop()
	select {
	case <-d.done:
	case <-time.After(15 * time.Second):
		d.t.Error("daemon did not stop")
	}
}

// waitStatus waits for a pushed status satisfying pred.
func (d *testDaemon) waitStatus(what string, pred func(ipc.Status) bool) ipc.Status {
	d.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if st, err := d.client.Status(ctx); err == nil && pred(st) {
		return st
	}
	deadline := time.After(25 * time.Second)
	var last ipc.Status
	for {
		select {
		case st := <-d.client.Events():
			if last = st; pred(st) {
				return st
			}
		case <-deadline:
			d.t.Fatalf("timed out waiting for %s; last status: %+v", what, last.Connection)
		}
	}
}

func TestDaemonOverIPC(t *testing.T) {
	s := startServer(t, nil)
	room := s.room("daemon room", password, 8)
	ctx := context.Background()
	peer := s.client("peer", room.PublicID, password)
	peer.waitConnected()

	dir := t.TempDir()
	d := startDaemon(t, dir)

	st, err := d.client.Status(ctx)
	if err != nil || st.Connection.Phase != ipc.PhaseIdle || st.Version == "" || !st.Settings.LANPriority {
		t.Fatalf("initial status: %+v, %v", st, err)
	}

	// Mistakes are reported in words the window can show as they are.
	for _, bad := range []struct {
		args ipc.ConnectArgs
		want string
	}{
		{ipc.ConnectArgs{Server: "", RoomID: room.PublicID, Password: password}, "server address"},
		{ipc.ConnectArgs{Server: "http://example.com", RoomID: room.PublicID, Password: password}, "https://"},
		{ipc.ConnectArgs{Server: s.addr.String(), RoomID: "nope", Password: password}, "room ID"},
		{ipc.ConnectArgs{Server: s.addr.String(), RoomID: room.PublicID}, "password"},
	} {
		if err := d.client.Connect(ctx, bad.args); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("connect %+v: error %v, want one mentioning %q", bad.args, err, bad.want)
		}
	}

	// Join, remembering the room.
	args := ipc.ConnectArgs{Server: s.addr.String(), RoomID: proto.FormatRoomID(room.PublicID), Password: password, Nickname: "daemon", Remember: true}
	if err := d.client.Connect(ctx, args); err != nil {
		t.Fatal(err)
	}
	st = d.waitStatus("connected with a reachable peer", func(st ipc.Status) bool {
		c := st.Connection
		return c.Phase == ipc.PhaseConnected && len(c.Peers) == 1 && c.Peers[0].Via != proto.ViaNone
	})
	c := st.Connection
	if c.RoomName != "daemon room" || c.Nickname != "daemon" || c.Subnet != "10.214.0.0/24" || c.Peers[0].Nickname != "peer" || !st.HasPassword {
		t.Fatalf("connected status: %+v", st)
	}
	myIP := c.IP

	report, err := d.client.Diagnostics(ctx)
	if err != nil || !strings.Contains(report, "daemon room") || !strings.Contains(report, "platform section") || !strings.Contains(report, c.Peers[0].IP) {
		t.Fatalf("diagnostics: %v\n%s", err, report)
	}

	// Preferences are saved and reported back.
	on := true
	st, err = d.client.UpdateSettings(ctx, ipc.SettingsArgs{AutoConnect: &on, RelayOnly: &on})
	if err != nil || !st.Settings.AutoConnect || !st.Settings.RelayOnly || !st.Settings.LANPriority {
		t.Fatalf("settings: %+v, %v", st.Settings, err)
	}

	if err := d.client.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	d.waitStatus("idle", func(st ipc.Status) bool { return st.Connection.Phase == ipc.PhaseIdle })
	peer.wait("the daemon's member to leave", 10*time.Second, func(st engineState) bool { return len(st.Peers) == 0 })

	// Reconnecting with the password field left empty uses the saved one.
	args.Password = ""
	if err := d.client.Connect(ctx, args); err != nil {
		t.Fatalf("connect with the remembered password: %v", err)
	}
	d.waitStatus("connected again", func(st ipc.Status) bool { return st.Connection.Phase == ipc.PhaseConnected })
	d.close()

	// A restarted daemon with "connect at start" rejoins by itself and gets
	// the same address.
	d2 := startDaemon(t, dir)
	st = d2.waitStatus("automatic reconnection", func(st ipc.Status) bool { return st.Connection.Phase == ipc.PhaseConnected })
	if st.Connection.IP != myIP {
		t.Fatalf("address changed across a restart: %s → %s", myIP, st.Connection.IP)
	}

	// When the room's password changes, the saved one is forgotten and the
	// daemon reports why it stopped.
	hash, _ := s.hasher.Hash(ctx, "another-password-entirely")
	if _, err := s.app.Store.SetRoomPassword(ctx, room.ID, hash); err != nil {
		t.Fatal(err)
	}
	s.app.Hub.CloseRoom(room.ID, proto.CodeInvalidCredentials, "The room password was changed.")
	st = d2.waitStatus("stopped by the password change", func(st ipc.Status) bool {
		return st.Connection.Phase == ipc.PhaseStopped && !st.HasPassword
	})
	if st.Connection.ErrorCode != string(proto.CodeInvalidCredentials) || !strings.Contains(st.Connection.Error, "password was changed") {
		t.Fatalf("stopped status: %+v", st.Connection)
	}
}
