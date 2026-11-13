//go:build !linux

package relay

import "syscall"

// reusePortSupported is false where SO_REUSEPORT does not load-balance UDP
// flows; the relay then uses a single socket.
const reusePortSupported = false

func socketControl(bool) func(network, address string, c syscall.RawConn) error { return nil }
