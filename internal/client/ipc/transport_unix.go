//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// SocketPath returns where the service listens: $LANORA_SOCKET if set,
// otherwise /run/lanora.sock for a service running as root, or a socket in
// the user's runtime directory.
func SocketPath() string {
	if p := os.Getenv("LANORA_SOCKET"); p != "" {
		return p
	}
	if os.Geteuid() == 0 {
		return "/run/lanora.sock"
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "lanora.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("lanora-%d.sock", os.Getuid()))
}

// Listen opens the service's end of the channel.
func Listen() (net.Listener, error) {
	path := SocketPath()
	// A socket file left by a previous run must go, but one a live service
	// is listening on must not be taken over.
	if conn, err := net.Dial("unix", path); err == nil {
		conn.Close()
		return nil, fmt.Errorf("another Lanora service is already running (%s)", path)
	}
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// Local users may control the connection, as on Windows.
	os.Chmod(path, 0o666)
	return ln, nil
}

func dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", SocketPath())
	if err != nil {
		// The window may run as an ordinary user while the service runs as
		// root and listens at the system location.
		if c2, err2 := d.DialContext(ctx, "unix", "/run/lanora.sock"); err2 == nil {
			return c2, nil
		}
	}
	return conn, err
}
