package netcfg

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

// linuxName is the interface name used on Linux, where names are limited
// to 15 characters and conventionally lower case.
const linuxName = "lanora0"

type linuxAdapter struct {
	dev  tun.Device
	name string
}

func (a *linuxAdapter) Device() tun.Device { return a.dev }
func (a *linuxAdapter) Name() string       { return a.name }

// Close removes the interface. A TUN device disappears when its file
// descriptor is closed, taking its address and route with it.
func (a *linuxAdapter) Close() error { return a.dev.Close() }

// Open creates the TUN interface and gives it the room address. It needs
// CAP_NET_ADMIN.
func Open(cfg Config) (Adapter, error) {
	name := cfg.Name
	if name == "" || name == DefaultName {
		name = linuxName
	}
	routes, err := systemRoutes()
	if err != nil {
		return nil, fmt.Errorf("reading the routing table: %w", err)
	}
	if c := findConflict(cfg.Subnet, routes, name); c != nil {
		return nil, c
	}

	dev, err := tun.CreateTUN(name, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("creating the network interface (is this running as root with /dev/net/tun available?): %w", err)
	}
	if actual, err := dev.Name(); err == nil {
		name = actual
	}
	fail := func(what string, err error) (Adapter, error) {
		dev.Close()
		return nil, fmt.Errorf("%s %s: %w", what, name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fail("finding interface", err)
	}
	// Adding the address also installs the on-link route for the subnet.
	// That is the only route this interface gets.
	addr := &netlink.Addr{IPNet: &net.IPNet{
		IP:   cfg.IP.AsSlice(),
		Mask: net.CIDRMask(cfg.Subnet.Bits(), 32),
	}}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fail("assigning the address to", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fail("bringing up", err)
	}
	return &linuxAdapter{dev: dev, name: name}, nil
}

// systemRoutes returns the IPv4 routes and local addresses of the machine.
func systemRoutes() ([]route, error) {
	names := map[int]string{}
	ifName := func(index int) string {
		if n, ok := names[index]; ok {
			return n
		}
		n := fmt.Sprintf("interface %d", index)
		if l, err := netlink.LinkByIndex(index); err == nil {
			n = l.Attrs().Name
		}
		names[index] = n
		return n
	}

	list, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	var out []route
	for _, r := range list {
		var rt route
		rt.iface = ifName(r.LinkIndex)
		if r.Dst != nil {
			if a, ok := netip.AddrFromSlice(r.Dst.IP); ok {
				ones, _ := r.Dst.Mask.Size()
				rt.dst = netip.PrefixFrom(a.Unmap(), ones)
			}
		} else {
			rt.dst = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		}
		if a, ok := netip.AddrFromSlice(r.Gw); ok {
			rt.gw = a.Unmap()
		}
		out = append(out, rt)
	}

	// An address without a connected route (a /32) is only in the local
	// table; include it so an address inside the room's range is noticed.
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			out = append(out, route{dst: netip.PrefixFrom(ip.Unmap(), 32), iface: ifName(a.LinkIndex)})
		}
	}
	return out, nil
}
