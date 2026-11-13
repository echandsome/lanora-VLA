package ipc

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

// PipeName is the named pipe the service listens on.
const PipeName = `\\.\pipe\Lanora`

// pipeSecurity lets the service (SYSTEM), administrators and whoever is
// logged on at the console or over Remote Desktop use the pipe, and refuses
// anyone arriving over the network: a named pipe is otherwise reachable
// from other machines through file sharing.
const pipeSecurity = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// Listen opens the service's end of the channel.
func Listen() (net.Listener, error) {
	return winio.ListenPipe(PipeName, &winio.PipeConfig{
		SecurityDescriptor: pipeSecurity,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
}

func dial(ctx context.Context) (net.Conn, error) {
	return winio.DialPipeContext(ctx, PipeName)
}
