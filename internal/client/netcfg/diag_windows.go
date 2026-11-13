package netcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Diagnostics describes this machine's network set-up as it matters for
// running next to another VPN: the adapters and their metrics, whether
// Astrill VPN is present, whether its socket hook is loaded into this
// process, and the routes that touch the room's range. It changes nothing.
func Diagnostics() string {
	var b strings.Builder

	b.WriteString("Other VPN software\n")
	astrill := false
	for _, dir := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles")} {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "Astrill")); err == nil {
			astrill = true
		}
	}
	fmt.Fprintf(&b, "  Astrill VPN installed: %s\n", yesNo(astrill))
	devices, complete := legacyWintunDevices()
	if len(devices) == 0 {
		b.WriteString("  Old-style Wintun adapters (the kind Astrill uses): none\n")
	} else {
		b.WriteString("  Old-style Wintun adapters (the kind Astrill uses):\n")
		for _, d := range sorted(devices) {
			fmt.Fprintf(&b, "    %s\n", d.String())
			if v, known := d.driver(); d.bound && (!known || v.olderThan(embeddedDriver)) {
				fmt.Fprintf(&b, "      <-- its Wintun driver is older than Lanora's (%s) or could not be identified; "+
					"Lanora will not connect rather than replace it\n", embeddedDriver)
			}
		}
		b.WriteString("    Lanora loads its network driver library in a way that cannot remove these, and checks afterwards.\n")
	}
	if !complete {
		b.WriteString("    (part of the device registry could not be read; there may be more)\n")
	}
	// The hook is a DLL injected into programs that use sockets. It must
	// not be in the service.
	hooked := false
	for _, dll := range []string{"ASProxy64.dll", "ASProxy.dll"} {
		name, _ := windows.UTF16PtrFromString(dll)
		var h windows.Handle
		if windows.GetModuleHandleEx(0, name, &h) == nil && h != 0 {
			hooked = true
		}
	}
	fmt.Fprintf(&b, "  Astrill socket hook installed on this computer: %s\n", yesNo(socketHookInstalled()))
	fmt.Fprintf(&b, "  Astrill socket hook loaded into this Lanora process: %s", yesNo(hooked))
	if hooked {
		b.WriteString("  <-- unexpected; Lanora's traffic may be intercepted")
	}
	b.WriteString("\n\nNetwork adapters (lower metric = preferred for broadcasts)\n")

	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		fmt.Fprintf(&b, "  could not be listed: %v\n", err)
	}
	sort.Slice(adapters, func(i, j int) bool { return adapters[i].Ipv4Metric < adapters[j].Ipv4Metric })
	for _, a := range adapters {
		if a.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		var addrs []string
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			if ip := u.Address.IP(); ip != nil {
				addrs = append(addrs, fmt.Sprintf("%s/%d", ip, u.OnLinkPrefixLength))
			}
		}
		gateway := "none"
		if g := a.FirstGatewayAddress; g != nil {
			if ip := g.Address.IP(); ip != nil {
				gateway = ip.String()
			}
		}
		fmt.Fprintf(&b, "  metric %-5d %-28s %-34s gateway %-15s %s\n",
			a.Ipv4Metric, a.FriendlyName(), strings.Join(addrs, " "), gateway, a.Description())
	}

	b.WriteString("\nRoutes with a gateway, and default routes\n")
	if routes, err := systemRoutes(); err == nil {
		for _, r := range routes {
			if r.gw.IsValid() || r.dst.Bits() <= 1 {
				gw := "on-link"
				if r.gw.IsValid() {
					gw = "via " + r.gw.String()
				}
				fmt.Fprintf(&b, "  %-20s %-22s %s\n", r.dst, gw, r.iface)
			}
		}
	}
	return b.String()
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// socketHookInstalled reports whether Astrill's layered service provider is
// registered in the Winsock catalog.
func socketHookInstalled() bool {
	const catalog = `SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, catalog, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer key.Close()
	names, _ := key.ReadSubKeyNames(-1)
	for _, name := range names {
		entry, err := registry.OpenKey(registry.LOCAL_MACHINE, catalog+`\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		// The provider's DLL path is at the start of the packed entry, as
		// plain ASCII.
		item, _, err := entry.GetBinaryValue("PackedCatalogItem")
		entry.Close()
		if err == nil && strings.Contains(strings.ToLower(string(item)), "asproxy") {
			return true
		}
	}
	return false
}
