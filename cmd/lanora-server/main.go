// Command lanora-server runs the Lanora control server (signalling, room
// management, dashboard and built-in relay) or, with LANORA_MODE=relay, a
// stand-alone relay node.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"lanora/internal/proto"
	"lanora/internal/server"
	"lanora/internal/server/auth"
	"lanora/internal/server/config"
	"lanora/internal/server/store"
	"lanora/internal/version"
)

const usage = `Usage: lanora-server [command]

Commands:
  serve                         run the server (default)
  healthcheck                   exit 0 if the local server answers /healthz
  pin                           print the certificate pin clients must append to
                                the server address (self-signed TLS only)
  backup <file>                 write a consistent copy of the database to <file>
  reset-password <user> [pass]  set an administrator's password (generated when
                                omitted) and re-enable the account
  version                       print the version
  help                          show this text

The server is configured through environment variables:

`

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "healthcheck":
		err = healthcheck()
	case "pin":
		err = pin()
	case "backup":
		err = backup(os.Args[2:])
	case "reset-password":
		err = resetPassword(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("lanora-server %s (protocol %d, %s/%s, %s)\n", version.Version, version.Protocol, runtime.GOOS, runtime.GOARCH, runtime.Version())
	case "help", "-h", "--help":
		fmt.Print(usage, config.Usage())
	default:
		fmt.Fprintf(os.Stderr, "lanora-server: unknown command %q\n\n%s%s", cmd, usage, config.Usage())
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lanora-server:", err)
		os.Exit(1)
	}
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	// SIGTERM is what Docker and systemd send to stop a service; both it
	// and Ctrl-C start a graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Run(ctx, cfg, os.Stdout)
}

// healthcheck probes the server on the loopback interface. It is meant for
// container health checks, where the image has no curl. The certificate is
// not verified: the probe never leaves the machine, and the certificate is
// issued for the public name, not for localhost.
func healthcheck() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return err
	}
	scheme := "https"
	if cfg.TLSMode == config.TLSOff {
		scheme = "http"
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(scheme + "://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server answered HTTP %d", resp.StatusCode)
	}
	return nil
}

func pin() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	p, err := server.SelfSignedPin(cfg)
	if err != nil {
		return err
	}
	fmt.Println(p)
	return nil
}

func openStore(ctx context.Context) (*store.Store, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(cfg.DatabasePath()); err != nil {
		return nil, fmt.Errorf("no database at %s (is LANORA_DATA_DIR set correctly?)", cfg.DatabasePath())
	}
	return store.Open(ctx, cfg.DatabasePath())
}

func backup(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: lanora-server backup <file>")
	}
	ctx := context.Background()
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Backup(ctx, args[0]); err != nil {
		return err
	}
	fmt.Println("database copied to", args[0])
	return nil
}

func resetPassword(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: lanora-server reset-password <user> [password]")
	}
	ctx := context.Background()
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	admin, err := st.AdminByUsername(ctx, args[0])
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no administrator named %q", args[0])
	} else if err != nil {
		return err
	}
	password, generated := "", true
	if len(args) == 2 {
		password, generated = args[1], false
		if len(password) < 10 {
			return errors.New("the password must be at least 10 characters long")
		}
	} else {
		password = proto.NewRoomPassword()
	}
	hash, err := auth.NewHasher(1).Hash(ctx, password)
	if err != nil {
		return err
	}
	enabled := false
	if _, err := st.UpdateAdmin(ctx, admin.ID, store.AdminPatch{PasswordHash: &hash, Disabled: &enabled}); err != nil {
		return err
	}
	if generated {
		fmt.Printf("new password for %s: %s\n", admin.Username, password)
	} else {
		fmt.Printf("password updated for %s\n", admin.Username)
	}
	fmt.Println("all of this account's dashboard sessions were signed out")
	return nil
}
