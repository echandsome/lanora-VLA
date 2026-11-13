package transport

import (
	"net"
	"net/netip"
	"slices"
	"sort"
	"time"

	"lanora/internal/proto"
)

const (
	maintainEvery = 500 * time.Millisecond
	gatherEvery   = 5 * time.Second
)

// wake makes the maintenance loop run now instead of at its next tick.
func (t *Transport) wake() {
	select {
	case t.rebind <- struct{}{}:
	default:
	}
}

// Rebind tells the transport that the local network may have changed (the
// machine resumed from sleep, another VPN connected or disconnected). Every
// path is verified again and the relay binding is renewed.
func (t *Transport) Rebind() {
	t.forceRebind.Store(true)
	t.wake()
}

// RebindRelay renews the relay binding now instead of at the next
// keepalive. It is called when the server is known to have restarted: its
// relay has forgotten every client, and until this client binds again its
// peers cannot reach it through the relay.
func (t *Transport) RebindRelay() {
	t.relay.rebind()
	t.wake()
}

// maintain is the transport's background loop: it keeps the relay binding
// alive, notices local network changes, publishes this client's addresses
// and drives every peer's path probing.
func (t *Transport) maintain(stop <-chan struct{}) {
	defer t.wg.Done()
	tick := time.NewTicker(maintainEvery)
	defer tick.Stop()

	var (
		local      []netip.AddrPort
		lastGather time.Time
		gathered   bool
	)
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		case <-t.rebind:
		}
		now := time.Now()

		forced := t.forceRebind.Swap(false)
		if forced || now.Sub(lastGather) >= gatherEvery {
			lastGather = now
			current := t.gatherLocal()
			if forced || (gathered && !slices.Equal(current, local)) {
				t.networkChanged(now)
			}
			local, gathered = current, true
		}

		t.relay.tick(now)
		t.publish(local)

		relayUp := t.relay.up()
		t.peersMu.RLock()
		peers := make([]*peer, 0, len(t.peers))
		for _, p := range t.peers {
			peers = append(peers, p)
		}
		t.peersMu.RUnlock()
		for _, p := range peers {
			probes, punch := p.tick(now, relayUp)
			for _, pr := range probes {
				t.sendPing(p, pr)
			}
			if punch && t.cfg.Signal != nil {
				t.cfg.Signal.RequestPunch(p.ip)
			}
		}
	}
}

// networkChanged re-verifies everything after the local network changed.
func (t *Transport) networkChanged(now time.Time) {
	t.log.Info("local network changed; re-verifying paths")
	t.relay.rebind()
	t.peersMu.RLock()
	for _, p := range t.peers {
		p.networkChanged(now)
	}
	t.peersMu.RUnlock()
}

// Endpoints returns the addresses this client can currently be reached at:
// its public address as seen by the relay, followed by its local ones.
func (t *Transport) Endpoints() []netip.AddrPort {
	return t.endpoints(t.gatherLocal())
}

func (t *Transport) endpoints(local []netip.AddrPort) []netip.AddrPort {
	if t.cfg.RelayOnly {
		return nil
	}
	out := make([]netip.AddrPort, 0, len(local)+1)
	if pub := t.relay.publicAddr(); pub.IsValid() && (t.cfg.AllowLoopback || !pub.Addr().IsLoopback()) {
		out = append(out, pub)
	}
	for _, ep := range local {
		if len(out) >= proto.MaxEndpoints {
			break
		}
		if !slices.Contains(out, ep) {
			out = append(out, ep)
		}
	}
	return out
}

// publish announces this client's addresses to the room when they change.
func (t *Transport) publish(local []netip.AddrPort) {
	if t.cfg.Signal == nil {
		return
	}
	eps := t.endpoints(local)
	t.localMu.Lock()
	changed := !slices.Equal(eps, t.published)
	if changed {
		t.published = eps
	}
	t.localMu.Unlock()
	if changed {
		t.cfg.Signal.PublishEndpoints(eps)
	}
}

// gatherLocal lists the local addresses peers might reach this client at,
// paired with the transport's UDP port. Addresses inside the room's subnet
// (the virtual adapter's own) are never offered: a peer dialling one would
// send tunnel packets through the tunnel.
func (t *Transport) gatherLocal() []netip.AddrPort {
	port := t.Port()
	if port == 0 {
		return nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var v4, v6 []netip.Addr
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || t.cfg.Subnet.Contains(ip) {
				continue
			}
			switch {
			case ip.Is4():
				v4 = append(v4, ip)
			case t.conn6 != nil && ip.IsGlobalUnicast() && !ip.IsPrivate():
				v6 = append(v6, ip)
			}
		}
	}
	less := func(s []netip.Addr) func(i, j int) bool { return func(i, j int) bool { return s[i].Less(s[j]) } }
	sort.Slice(v4, less(v4))
	sort.Slice(v6, less(v6))

	// Leave room for the public address, and keep IPv6 from crowding out
	// IPv4 on machines with many temporary addresses.
	const maxLocal = proto.MaxEndpoints - 1
	if len(v6) > 3 {
		v6 = v6[:3]
	}
	if len(v4) > maxLocal-len(v6) {
		v4 = v4[:maxLocal-len(v6)]
	}
	out := make([]netip.AddrPort, 0, len(v4)+len(v6))
	for _, ip := range slices.Compact(append(v4, v6...)) {
		out = append(out, netip.AddrPortFrom(ip, port))
	}
	return out
}
