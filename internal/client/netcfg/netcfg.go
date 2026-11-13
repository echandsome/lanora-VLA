// Package netcfg creates and configures the virtual network adapter.
//
// The rules it follows are what let Lanora run next to another VPN client
// without either disturbing the other:
//
//   - The adapter gets one address and the on-link route for the room's
//     subnet that comes with it. Nothing else: no default gateway, no DNS
//     servers, no routes for other networks.
//   - No setting outside the adapter is changed. Other adapters, the system
//     routing table, DNS configuration and firewall filters are left alone.
//   - The adapter exists only while a room is joined. Disconnecting removes
//     it, and with it every trace of Lanora in the network configuration.
//   - Before the adapter is created, the room's subnet is checked against
//     the routes the system already has, and an overlap is refused instead
//     of being allowed to capture another network's traffic.
package netcfg

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

// DefaultName is the name of the virtual adapter.
const DefaultName = "Lanora"

// Config describes the adapter to create.
type Config struct {
	Name   string
	IP     netip.Addr   // this machine's address in the room
	Subnet netip.Prefix // the room's subnet
	MTU    int

	// LANPriority makes the adapter the preferred interface for broadcast
	// and multicast, which is how LAN games and discovery protocols find
	// the room's members when they do not ask for a specific adapter. It
	// affects nothing else: the adapter has no default route and no DNS
	// servers, so ordinary traffic and name resolution are untouched.
	LANPriority bool

	// PrivateNetwork marks the adapter's network as private, so that
	// programs the user allowed on private networks (file sharing, game
	// servers) accept connections from the room.
	PrivateNetwork bool

	// Logger receives an account of each step of setting the adapter up.
	// When something goes wrong on a machine nobody can look at, this is
	// what there is to go on. Nil discards it.
	Logger *slog.Logger
}

func (c Config) log() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// LogDriverMessages sends what the network driver library itself reports to
// logger. On Windows the Wintun library writes its own account of creating
// an adapter (which driver it found, whether it installed one, why a step
// failed) to Go's standard logger, where a service would otherwise lose it.
// Call it once, early.
func LogDriverMessages(logger *slog.Logger) {
	log.SetFlags(0)
	log.SetOutput(driverLog{logger.With("part", "driver")})
}

type driverLog struct{ log *slog.Logger }

func (w driverLog) Write(p []byte) (int, error) {
	if line := strings.TrimSpace(string(p)); line != "" {
		w.log.Info(line)
	}
	return len(p), nil
}

// Adapter is an open virtual adapter.
type Adapter interface {
	// Device is the packet interface to hand to WireGuard.
	Device() tun.Device
	// Name is the adapter's name as the operating system knows it.
	Name() string
	// Close removes the adapter and everything configured on it.
	Close() error
}

// OpenFunc creates an adapter. Open is the real implementation; tests
// substitute an in-memory network stack.
type OpenFunc func(Config) (Adapter, error)

// ConflictError reports that the room's subnet collides with a network this
// machine is already using.
type ConflictError struct {
	Subnet    netip.Prefix
	Other     string // the colliding route or address
	Interface string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("This room uses the address range %s, which is already in use on this computer (%s on %q). "+
		"Joining would disrupt that connection, so Lanora did not connect. "+
		"Ask the room's administrator to give the room a different range.",
		e.Subnet, e.Other, e.Interface)
}

// route is one entry of the system's IPv4 routing table.
type route struct {
	dst   netip.Prefix // zero bits for a default route
	gw    netip.Addr   // next hop; invalid for an on-link route
	iface string
}

// findConflict looks for a reason not to bring the room's subnet up on this
// machine. The adapter adds exactly one route, for the subnet itself, so
// the question is whether that route would take traffic away from something
// that is using those addresses now:
//
//   - an existing route for addresses inside the subnet (another network
//     with the same range, or this machine's own address on one), or
//   - a gateway inside the subnet: the next hop of some other route, such
//     as another VPN's tunnel gateway, would become unreachable.
//
// A wider route that merely contains the subnet (a default route, a VPN's
// 0.0.0.0/1, a corporate 10.0.0.0/8) is not a conflict: it keeps working
// for the rest of its range, and nothing in it is known to live in the
// room's /24. Routes on the adapter itself (self) are ignored.
func findConflict(subnet netip.Prefix, routes []route, self string) *ConflictError {
	for _, r := range routes {
		if r.iface == self {
			continue
		}
		if r.gw.IsValid() && subnet.Contains(r.gw) {
			return &ConflictError{Subnet: subnet, Other: "gateway " + r.gw.String(), Interface: r.iface}
		}
		if r.dst.IsValid() && r.dst.Addr().Is4() && r.dst.Bits() >= subnet.Bits() && subnet.Contains(r.dst.Addr()) {
			return &ConflictError{Subnet: subnet, Other: r.dst.String(), Interface: r.iface}
		}
	}
	return nil
}
