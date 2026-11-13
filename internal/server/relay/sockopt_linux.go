package relay

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortSupported reports whether several sockets can share one UDP port
// with the kernel spreading incoming flows between them.
const reusePortSupported = true

func socketControl(reusePort bool) func(network, address string, c syscall.RawConn) error {
	if !reusePort {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}); err != nil {
			return err
		}
		return serr
	}
}
