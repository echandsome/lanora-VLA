//go:build windows || lanoraui

package ui

import (
	"context"
	"errors"
	"sync"
	"time"

	"lanora/internal/client/ipc"
)

// errNoService is returned for requests made while the window is not
// connected to the Lanora service.
var errNoService = errors.New("The Lanora service is not running.")

// link keeps the window connected to the service: it dials, follows status
// updates, and dials again whenever the connection is lost.
type link struct {
	notify func() // asks the window to redraw

	mu        sync.Mutex
	client    *ipc.Client
	status    ipc.Status
	connected bool
	attempts  int // consecutive failed dials
}

func newLink(notify func()) *link { return &link{notify: notify} }

// run maintains the connection until ctx is cancelled.
func (l *link) run(ctx context.Context) {
	for ctx.Err() == nil {
		dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		client, err := ipc.Dial(dctx)
		cancel()
		if err != nil {
			l.mu.Lock()
			l.attempts++
			l.mu.Unlock()
			l.notify()
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}

		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		status, err := client.Status(sctx)
		cancel()
		if err != nil {
			client.Close()
			continue
		}
		l.mu.Lock()
		l.client, l.status, l.connected, l.attempts = client, status, true, 0
		l.mu.Unlock()
		l.notify()

	follow:
		for {
			select {
			case st := <-client.Events():
				l.mu.Lock()
				l.status = st
				l.mu.Unlock()
				l.notify()
			case <-client.Done():
				break follow
			case <-ctx.Done():
				client.Close()
				break follow
			}
		}
		l.mu.Lock()
		l.client, l.connected = nil, false
		l.mu.Unlock()
		l.notify()
	}
}

// snapshot returns whether the service is reachable and its latest status.
// tried is false until the first dial has finished, so the window can show
// nothing rather than "not installed" for the first instant.
func (l *link) snapshot() (connected, tried bool, st ipc.Status) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.connected, l.connected || l.attempts > 0, l.status
}

// call runs fn with the service client.
func (l *link) call(fn func(context.Context, *ipc.Client) error) error {
	l.mu.Lock()
	client := l.client
	l.mu.Unlock()
	if client == nil {
		return errNoService
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return fn(ctx, client)
}

// setStatus records a status returned by a request, so the window does not
// wait for the matching event to show it.
func (l *link) setStatus(st ipc.Status) {
	l.mu.Lock()
	l.status = st
	l.mu.Unlock()
}
