package netcfg

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// adapterGUID is the fixed identity of Lanora's adapter. Windows keys what
// it remembers about a network (above all whether the user marked it
// private or public) on this GUID, so a fixed one makes that choice stick
// across connections instead of a new "Network N" appearing every time.
var adapterGUID = windows.GUID{
	Data1: 0x4c616e6f, Data2: 0x7261, Data3: 0x4c41,
	Data4: [8]byte{0x8e, 0x4e, 0x76, 0x69, 0x72, 0x74, 0x6c, 0x61},
}

const (
	pingRuleName    = "Lanora (ping from room members)"
	createAttempts  = 5
	settleAttempts  = 20
	settleInterval  = 500 * time.Millisecond
	lanPriorityCost = 1 // interface metric used when LANPriority is on
	toolTimeout     = 20 * time.Second
)

type winAdapter struct {
	dev  tun.Device
	name string
	log  *slog.Logger

	closeOnce sync.Once
	stop      chan struct{} // ends the background set-up
}

func (a *winAdapter) Device() tun.Device { return a.dev }
func (a *winAdapter) Name() string       { return a.name }

// Close removes the adapter. Its address and route go with it, and the
// firewall rule added for it is removed, leaving the network configuration
// as it was before the room was joined.
func (a *winAdapter) Close() error {
	var err error
	a.closeOnce.Do(func() {
		close(a.stop)
		err = a.dev.Close()
		runHidden("netsh", "advfirewall", "firewall", "delete", "rule", "name="+pingRuleName)
		a.log.Info("the adapter was removed", "err", err)
	})
	return err
}

// Open creates Lanora's adapter and configures it for the room. It needs
// administrator rights (the Lanora service has them).
func Open(cfg Config) (Adapter, error) {
	name := cfg.Name
	if name == "" {
		name = DefaultName
	}
	log := cfg.log()
	routes, err := systemRoutes()
	if err != nil {
		return nil, fmt.Errorf("reading the routing table: %w", err)
	}
	if c := findConflict(cfg.Subnet, routes, name); c != nil {
		log.Warn("the room's address range is already in use on this computer", "subnet", cfg.Subnet, "other", c.Other, "interface", c.Interface)
		return nil, c
	}
	if err := ensureWintun(log); err != nil {
		return nil, err
	}

	log.Info("creating the adapter", "name", name, "address", cfg.IP, "subnet", cfg.Subnet, "mtu", cfg.MTU)
	tun.WintunTunnelType = "Lanora"
	var dev tun.Device
	for attempt := 1; ; attempt++ {
		dev, err = tun.CreateTUNWithRequestedGUID(name, &adapterGUID, cfg.MTU)
		if err == nil {
			break
		}
		log.Warn("the adapter could not be created", "attempt", attempt, "of", createAttempts, "err", err)
		// After a crash Windows can take a moment to let go of the previous
		// adapter with this identity.
		if attempt == createAttempts {
			return nil, fmt.Errorf("Lanora could not create its network adapter: %w", err)
		}
		time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
	}
	native, ok := dev.(*tun.NativeTun)
	if !ok {
		dev.Close()
		return nil, errors.New("unexpected adapter type")
	}
	luid := winipcfg.LUID(native.LUID())
	if v, err := native.RunningVersion(); err == nil {
		log.Info("the adapter exists", "luid", uint64(luid), "wintun_driver", fmt.Sprintf("%d.%d", v>>16, v&0xffff))
	} else {
		log.Info("the adapter exists", "luid", uint64(luid))
	}

	if err := configure(luid, cfg); err != nil {
		log.Error("the adapter could not be configured", "err", err)
		dev.Close()
		return nil, fmt.Errorf("Lanora could not configure its network adapter: %w", err)
	}
	log.Info("the adapter has its address; nothing else on this computer was changed",
		"address", netip.PrefixFrom(cfg.IP, cfg.Subnet.Bits()), "lan_priority", cfg.LANPriority)

	a := &winAdapter{dev: dev, name: name, log: log, stop: make(chan struct{})}
	go a.finish(cfg)
	return a, nil
}

// settle retries an operation that fails with "not found" while Windows is
// still bringing a newly created interface into existence.
func settle(op func() error) error {
	var err error
	for i := 0; i < settleAttempts; i++ {
		if err = op(); !errors.Is(err, windows.ERROR_NOT_FOUND) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return err
		}
		time.Sleep(settleInterval)
	}
	return err
}

// configure gives the adapter its address and interface settings. This is
// the whole of Lanora's footprint in the Windows network configuration:
// one address, whose on-link route for the room's subnet Windows adds by
// itself. No gateway, no DNS server and no other route is set, so nothing
// here can redirect traffic that is not addressed to the room.
func configure(luid winipcfg.LUID, cfg Config) error {
	err := settle(func() error {
		ipif, err := luid.IPInterface(windows.AF_INET)
		if err != nil {
			return err
		}
		ipif.NLMTU = uint32(cfg.MTU)
		// The address is assigned by the server and known to be unique:
		// skip duplicate-address detection so it is usable at once.
		ipif.DadTransmits = 0
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		if cfg.LANPriority {
			// Windows sends a broadcast or multicast that a program did not
			// pin to an adapter out of the interface with the lowest
			// metric. LAN games announce themselves that way, so the room's
			// adapter must be that interface for other members to see them.
			// The metric only ranks routes to the same destination. This
			// adapter has routes for the room's subnet, broadcast and
			// multicast and nothing else, so no other traffic is affected.
			ipif.UseAutomaticMetric = false
			ipif.Metric = lanPriorityCost
		}
		return ipif.Set()
	})
	if err != nil {
		return fmt.Errorf("interface settings: %w", err)
	}

	address := netip.PrefixFrom(cfg.IP, cfg.Subnet.Bits())
	err = settle(func() error { return luid.SetIPAddresses([]netip.Prefix{address}) })
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("the address %s is already assigned to another network adapter on this computer", cfg.IP)
	}
	if err != nil {
		return fmt.Errorf("assigning %s: %w", address, err)
	}

	// The room carries IPv4 only. Quieten IPv6 on the adapter so Windows
	// does not keep soliciting routers on a link that has none. Best
	// effort: IPv6 may be disabled on this machine altogether.
	if ipif, err := luid.IPInterface(windows.AF_INET6); err == nil {
		ipif.DadTransmits = 0
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		ipif.Set()
	}
	return nil
}

// finish does the parts of set-up that are worth having but not worth
// delaying or failing the connection for.
func (a *winAdapter) finish(cfg Config) {
	// Windows blocks incoming pings by default, and "can you ping me?" is
	// the first thing people try. Allow echo requests, from the room's
	// subnet only, to this machine's room address only.
	runHidden("netsh", "advfirewall", "firewall", "delete", "rule", "name="+pingRuleName)
	if out, err := runHidden("netsh", "advfirewall", "firewall", "add", "rule", "name="+pingRuleName,
		"dir=in", "action=allow", "protocol=icmpv4:8,any", "profile=any",
		"remoteip="+cfg.Subnet.String(), "localip="+cfg.IP.String()); err != nil {
		a.log.Warn("could not allow pings from the room through Windows Firewall", "err", err, "output", out)
	}

	if cfg.PrivateNetwork {
		if err := a.markPrivate(); err != nil {
			a.log.Warn("could not mark the room's network as private", "err", err)
		} else {
			a.log.Info("the room's network is marked private")
		}
	}
}

// markPrivate sets the adapter's network category to Private. A new network
// starts out Public, where Windows Firewall refuses the incoming
// connections that file sharing and hosting a game need. Windows takes a
// few seconds to list a new adapter's network, so the script waits for it.
// The category is remembered for the adapter's GUID; after the first time
// this finds nothing to change.
func (a *winAdapter) markPrivate() error {
	script := fmt.Sprintf(`$ErrorActionPreference = 'SilentlyContinue'
for ($i = 0; $i -lt 40; $i++) {
  $p = Get-NetConnectionProfile -InterfaceAlias '%s'
  if ($p) {
    if ($p.NetworkCategory -eq 'Public') { Set-NetConnectionProfile -InterfaceAlias '%s' -NetworkCategory Private }
    exit 0
  }
  Start-Sleep -Milliseconds 500
}
exit 1`, a.name, a.name)
	cmd := hiddenCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-a.stop:
		cmd.Process.Kill()
		<-done
		return nil // the room was left meanwhile
	}
}

func hiddenCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

// runHidden runs a system tool without flashing a console window and
// returns its combined output. The tool gets a limited time: leaving a room
// must not wait for ever on a helper that hangs.
func runHidden(name string, args ...string) (string, error) {
	cmd := hiddenCommand(name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return strings.TrimSpace(out.String()), err
	case <-time.After(toolTimeout):
		cmd.Process.Kill()
		<-done
		return strings.TrimSpace(out.String()), fmt.Errorf("%s did not finish within %s", name, toolTimeout)
	}
}

// systemRoutes returns the machine's IPv4 routing table with interface
// names resolved.
func systemRoutes() ([]route, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	aliases := map[winipcfg.LUID]string{}
	alias := func(luid winipcfg.LUID) string {
		if a, ok := aliases[luid]; ok {
			return a
		}
		a := fmt.Sprintf("interface %d", uint64(luid))
		if row, err := luid.Interface(); err == nil {
			a = row.Alias()
		}
		aliases[luid] = a
		return a
	}
	out := make([]route, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		rt := route{dst: r.DestinationPrefix.Prefix(), iface: alias(r.InterfaceLUID)}
		if gw := r.NextHop.Addr(); gw.IsValid() && !gw.IsUnspecified() {
			rt.gw = gw
		}
		out = append(out, rt)
	}
	return out, nil
}
