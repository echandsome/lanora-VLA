package transport

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/nacl/box"

	"lanora/internal/proto"
)

// Path timing. A peer we are exchanging traffic with is probed often, so a
// dead path is noticed within a few seconds; an idle peer is probed just
// often enough to keep NAT mappings open (home routers commonly forget an
// idle UDP mapping after 30 seconds).
const (
	activeWindow  = 15 * time.Second // traffic this recent makes a peer "active"
	activePing    = 1500 * time.Millisecond
	activeTimeout = 5 * time.Second
	idlePing      = 12 * time.Second
	idleTimeout   = 40 * time.Second

	pingExpiry     = 5 * time.Second  // an unanswered ping is forgotten after this
	fullProbeEvery = 60 * time.Second // re-test every candidate, looking for a better path
	relayPingFirst = time.Second      // until the relay path has answered once
	relayPingFast  = 5 * time.Second
	relayPingSlow  = 30 * time.Second
	relayAlive     = 75 * time.Second // relay path counts as working this long after a pong
	punchInterval  = 2 * time.Second
	learnedTTL     = 5 * time.Minute // unconfirmed learned addresses are dropped after this
	maxCandidates  = 32
)

// discoveryBackoff is the delay before each successive attempt to find a
// direct path to a peer that has none. After the last entry the final delay
// repeats for as long as the peer stays relayed.
var discoveryBackoff = []time.Duration{
	time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second, 30 * time.Second,
}

// peer is the transport's state for one room member.
type peer struct {
	t  *Transport
	ip netip.Addr
	id proto.PeerID
	ep *endpoint

	shared atomic.Pointer[[32]byte] // discovery box key shared with this peer

	// Hot-path state, read without the lock.
	best     atomic.Pointer[netip.AddrPort] // verified direct path; nil means "use the relay"
	suspect  atomic.Bool                    // a pong on best is overdue
	lastSend atomic.Int64                   // last WireGuard packet sent (Unix nanoseconds)
	lastRecv atomic.Int64                   // last WireGuard packet received

	mu        sync.Mutex
	discoPub  proto.Key32
	cands     map[netip.AddrPort]*candidate
	pings     map[proto.DiscoTxID]pingRecord
	nextProbe time.Time // when to next look for a direct path
	round     int       // index into discoveryBackoff
	quietOnce bool      // the next discovery round must not ask the peer to punch
	lastFull  time.Time
	lastPunch time.Time
	relayPing time.Time
	relayPong time.Time
	relayRTT  time.Duration // -1 until measured
}

type candidate struct {
	addr       netip.AddrPort
	advertised bool // listed by the peer itself (false: learned from a ping it sent us)
	added      time.Time
	lastPing   time.Time
	lastPong   time.Time
	rtt        time.Duration
}

type pingRecord struct {
	addr netip.AddrPort // zero value: sent through the relay
	sent time.Time
}

// probe is a ping to transmit once the peer's lock has been released.
type probe struct {
	addr netip.AddrPort
	tx   proto.DiscoTxID
}

// PeerStatus describes how a peer is currently reached.
type PeerStatus struct {
	IP   netip.Addr
	Via  string         // proto.ViaDirect, proto.ViaRelay or proto.ViaNone
	Addr netip.AddrPort // the direct address in use, if any
	RTT  time.Duration  // -1 when not measured yet
}

// SetPeer adds a room member or updates what is known about it.
func (t *Transport) SetPeer(info proto.Peer) {
	if !info.IP.Is4() || info.IP == t.cfg.Self {
		return
	}
	id := proto.PeerIDOf(info.IP)
	now := time.Now()

	t.peersMu.Lock()
	p := t.peers[id]
	if p == nil {
		p = &peer{
			t: t, ip: info.IP, id: id,
			cands:    make(map[netip.AddrPort]*candidate),
			pings:    make(map[proto.DiscoTxID]pingRecord),
			relayRTT: -1,
		}
		p.ep = &endpoint{p: p}
		t.peers[id] = p
	}
	t.peersMu.Unlock()

	p.mu.Lock()
	if p.discoPub != info.DiscoPub {
		// A new discovery key means the peer started a new session: nothing
		// learned about the old one can be trusted to still hold.
		var shared [32]byte
		pub := [32]byte(info.DiscoPub)
		box.Precompute(&shared, &pub, t.cfg.DiscoKey)
		p.shared.Store(&shared)
		p.discoPub = info.DiscoPub
		p.resetPathsLocked()
	}
	p.setAdvertisedLocked(info.Endpoints, now)
	p.nextProbe, p.round = now, 0
	p.mu.Unlock()
}

// RemovePeer forgets a room member.
func (t *Transport) RemovePeer(ip netip.Addr) {
	if !ip.Is4() {
		return
	}
	id := proto.PeerIDOf(ip)
	t.peersMu.Lock()
	p := t.peers[id]
	delete(t.peers, id)
	t.peersMu.Unlock()
	if p == nil {
		return
	}
	p.mu.Lock()
	p.resetPathsLocked()
	p.mu.Unlock()
}

// HandlePunch reacts to a peer asking us to probe its addresses now.
func (t *Transport) HandlePunch(from netip.Addr, eps []netip.AddrPort) {
	if !from.Is4() {
		return
	}
	p := t.peer(proto.PeerIDOf(from))
	if p == nil {
		return
	}
	now := time.Now()
	p.mu.Lock()
	p.setAdvertisedLocked(eps, now)
	// Probe at once, but do not ask the peer to punch back: it is already
	// probing us, and answering a punch with a punch would never end.
	p.nextProbe, p.round, p.quietOnce = now, 0, true
	p.mu.Unlock()
	t.wake()
}

// resetPathsLocked drops everything known about how to reach the peer.
func (p *peer) resetPathsLocked() {
	for addr := range p.cands {
		p.t.byAddr.CompareAndDelete(addr, p)
	}
	clear(p.cands)
	clear(p.pings)
	p.best.Store(nil)
	p.suspect.Store(false)
	p.relayRTT, p.relayPong = -1, time.Time{}
}

// usable reports whether an address may be probed at all.
func (t *Transport) usable(addr netip.AddrPort) bool {
	a := addr.Addr()
	if t.cfg.RelayOnly || !a.IsValid() || addr.Port() == 0 || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return false
	}
	if a.IsLoopback() && !t.cfg.AllowLoopback {
		return false
	}
	// An address inside the room's own subnet would send tunnel packets
	// into the tunnel.
	if t.cfg.Subnet.Contains(a) {
		return false
	}
	return a.Is4() || t.conn6 != nil
}

// setAdvertisedLocked replaces the set of addresses the peer advertises.
// Addresses learned from the peer's own pings are kept, as is the path in
// use even if the peer no longer lists it: it is dropped when it stops
// answering, not before.
func (p *peer) setAdvertisedLocked(eps []netip.AddrPort, now time.Time) {
	listed := make(map[netip.AddrPort]bool, len(eps))
	for _, ep := range eps {
		ep = netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port())
		if len(listed) >= proto.MaxEndpoints || !p.t.usable(ep) {
			continue
		}
		listed[ep] = true
		if c := p.cands[ep]; c != nil {
			c.advertised = true
		} else {
			p.cands[ep] = &candidate{addr: ep, advertised: true, added: now}
		}
	}
	best := p.best.Load()
	for addr, c := range p.cands {
		if c.advertised && !listed[addr] && (best == nil || *best != addr) {
			c.advertised = false
			if c.lastPong.IsZero() {
				delete(p.cands, addr)
				p.t.byAddr.CompareAndDelete(addr, p)
			}
		}
	}
}

// heardFrom records that an authenticated ping from the peer arrived from
// addr. Such an address is a candidate even if the peer never advertised it
// (it may be behind a NAT that gives every destination a different port).
// It returns a ping to send back, if the address should be tested now.
func (p *peer) heardFrom(addr netip.AddrPort, now time.Time) (probe, bool) {
	if !p.t.usable(addr) {
		return probe{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.cands[addr]
	if c == nil {
		if len(p.cands) >= maxCandidates {
			p.evictLocked()
		}
		c = &candidate{addr: addr, added: now}
		p.cands[addr] = c
	}
	p.t.byAddr.Store(addr, p)
	if now.Sub(c.lastPing) < 500*time.Millisecond {
		return probe{}, false
	}
	return p.pingLocked(c, now), true
}

// evictLocked makes room for a new candidate by dropping the one least
// likely to matter: never the path in use, and unconfirmed before confirmed.
func (p *peer) evictLocked() {
	best := p.best.Load()
	var victim *candidate
	for _, c := range p.cands {
		if best != nil && c.addr == *best {
			continue
		}
		if victim == nil || c.lastPong.Before(victim.lastPong) ||
			(c.lastPong.Equal(victim.lastPong) && c.added.Before(victim.added)) {
			victim = c
		}
	}
	if victim != nil {
		delete(p.cands, victim.addr)
		p.t.byAddr.CompareAndDelete(victim.addr, p)
	}
}

func (p *peer) pingLocked(c *candidate, now time.Time) probe {
	tx := proto.NewDiscoTxID()
	p.pings[tx] = pingRecord{addr: c.addr, sent: now}
	c.lastPing = now
	return probe{addr: c.addr, tx: tx}
}

func (p *peer) pingRelayLocked(now time.Time) probe {
	tx := proto.NewDiscoTxID()
	p.pings[tx] = pingRecord{sent: now}
	p.relayPing = now
	return probe{tx: tx}
}

func smooth(old, sample time.Duration) time.Duration {
	if old <= 0 {
		return sample
	}
	return (old*7 + sample*3) / 10
}

// handlePong processes the answer to one of our pings.
func (p *peer) handlePong(tx proto.DiscoTxID, from netip.AddrPort, viaRelay bool, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rec, ok := p.pings[tx]
	if !ok {
		return
	}
	// The answer must come back the way the ping went, or it proves nothing
	// about that path.
	relayPing := !rec.addr.IsValid()
	if relayPing != viaRelay || (!relayPing && rec.addr != from) {
		return
	}
	delete(p.pings, tx)
	rtt := now.Sub(rec.sent)

	if relayPing {
		p.relayRTT, p.relayPong = smooth(p.relayRTT, rtt), now
		return
	}
	c := p.cands[from]
	if c == nil {
		return
	}
	c.rtt, c.lastPong = smooth(c.rtt, rtt), now
	p.t.byAddr.Store(from, p)

	best := p.best.Load()
	switch {
	case best == nil:
		p.useLocked(c)
	case *best == from:
		p.suspect.Store(false)
	default:
		// Move only for a clear improvement, so two similar paths do not
		// take turns.
		cur := p.cands[*best]
		if cur == nil || c.rtt+max(3*time.Millisecond, cur.rtt/5) < cur.rtt {
			p.useLocked(c)
		}
	}
}

func (p *peer) useLocked(c *candidate) {
	addr := c.addr
	p.best.Store(&addr)
	p.suspect.Store(false)
	p.round = 0
	p.t.log.Info("peer reachable directly", "peer", p.ip.String(), "addr", addr.String(), "rtt", c.rtt.Round(100*time.Microsecond).String())
}

// tick advances the peer's path state. It returns the pings to send and
// whether to ask the peer, through the server, to probe us.
func (p *peer) tick(now time.Time, relayUp bool) (probes []probe, punch bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for tx, rec := range p.pings {
		if now.Sub(rec.sent) > pingExpiry {
			delete(p.pings, tx)
		}
	}
	for addr, c := range p.cands {
		if !c.advertised && c.lastPong.IsZero() && now.Sub(c.added) > learnedTTL {
			delete(p.cands, addr)
			p.t.byAddr.CompareAndDelete(addr, p)
		}
	}

	last := max(p.lastSend.Load(), p.lastRecv.Load())
	active := last != 0 && now.Sub(time.Unix(0, last)) < activeWindow

	if best := p.best.Load(); best != nil {
		interval, timeout := idlePing, idleTimeout
		if active {
			interval, timeout = activePing, activeTimeout
		}
		c := p.cands[*best]
		switch {
		case c == nil || now.Sub(c.lastPong) > timeout:
			p.best.Store(nil)
			p.suspect.Store(false)
			p.nextProbe, p.round = now, 0
			p.t.log.Info("direct path lost, using relay", "peer", p.ip.String(), "addr", best.String())
		default:
			// A pong more than two intervals old means at least one ping
			// went unanswered.
			p.suspect.Store(now.Sub(c.lastPong) > 2*interval+500*time.Millisecond)
			if now.Sub(c.lastPing) >= interval {
				probes = append(probes, p.pingLocked(c, now))
			}
			if now.Sub(p.lastFull) >= fullProbeEvery {
				p.lastFull = now
				for _, other := range p.cands {
					if other != c {
						probes = append(probes, p.pingLocked(other, now))
					}
				}
			}
		}
	}

	if p.best.Load() == nil && !now.Before(p.nextProbe) {
		for _, c := range p.cands {
			probes = append(probes, p.pingLocked(c, now))
		}
		p.lastFull = now
		if p.quietOnce {
			p.quietOnce = false
		} else if now.Sub(p.lastPunch) >= punchInterval {
			p.lastPunch, punch = now, true
		}
		p.nextProbe = now.Add(discoveryBackoff[min(p.round, len(discoveryBackoff)-1)])
		p.round++
	}

	if relayUp {
		interval := relayPingSlow
		switch {
		case p.relayRTT < 0:
			// Not measured yet: the peer may simply not have bound to the
			// relay when the first ping went out, so ask again soon.
			interval = relayPingFirst
		case p.best.Load() == nil && active:
			interval = relayPingFast
		}
		if now.Sub(p.relayPing) >= interval {
			probes = append(probes, p.pingRelayLocked(now))
		}
	}
	return probes, punch
}

// networkChanged makes the peer re-verify everything: after the local
// network changes, no previously working path can be assumed to still work.
func (p *peer) networkChanged(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.cands {
		c.lastPing = time.Time{}
	}
	if p.best.Load() != nil {
		p.suspect.Store(true)
	}
	p.nextProbe, p.round = now, 0
	p.relayPing = time.Time{}
}

func (p *peer) status(now time.Time, relayUp bool) PeerStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := PeerStatus{IP: p.ip, Via: proto.ViaNone, RTT: -1}
	if best := p.best.Load(); best != nil {
		st.Via, st.Addr = proto.ViaDirect, *best
		if c := p.cands[*best]; c != nil && c.rtt > 0 {
			st.RTT = c.rtt
		}
	} else if relayUp && !p.relayPong.IsZero() && now.Sub(p.relayPong) < relayAlive {
		st.Via = proto.ViaRelay
		if p.relayRTT > 0 {
			st.RTT = p.relayRTT
		}
	}
	return st
}

// Peers returns the current path to every peer, ordered by address.
func (t *Transport) Peers() []PeerStatus {
	now := time.Now()
	relayUp := t.relay.up()
	t.peersMu.RLock()
	out := make([]PeerStatus, 0, len(t.peers))
	list := make([]*peer, 0, len(t.peers))
	for _, p := range t.peers {
		list = append(list, p)
	}
	t.peersMu.RUnlock()
	for _, p := range list {
		out = append(out, p.status(now, relayUp))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}

// handleDisco processes a discovery frame. from is the UDP source address,
// or the zero value when the frame came through the relay.
func (t *Transport) handleDisco(frame []byte, from netip.AddrPort, viaRelay bool) {
	sender, ok := proto.DiscoSender(frame)
	if !ok {
		return
	}
	p := t.peer(sender)
	if p == nil {
		return
	}
	shared := p.shared.Load()
	if shared == nil {
		return
	}
	var scratch [proto.DiscoPongLen]byte
	plain, ok := proto.OpenDisco(scratch[:0], frame, shared)
	if !ok {
		return
	}
	typ, tx, _, ok := proto.ParseDisco(plain)
	if !ok {
		return
	}
	now := time.Now()
	switch typ {
	case proto.DiscoPing:
		var out [proto.DiscoPongLen]byte
		t.sendDisco(p, from, proto.AppendDiscoPong(out[:0], tx, from))
		if !viaRelay {
			if pr, ok := p.heardFrom(from, now); ok {
				t.sendPing(p, pr)
			}
		}
	case proto.DiscoPong:
		p.handlePong(tx, from, viaRelay, now)
	}
}

// sendDisco seals and sends a discovery payload to a peer, directly to addr
// or, when addr is the zero value, through the relay.
func (t *Transport) sendDisco(p *peer, addr netip.AddrPort, payload []byte) {
	shared := p.shared.Load()
	if shared == nil || !t.isOpen.Load() {
		return
	}
	bp := t.pool.Get().(*[]byte)
	defer t.pool.Put(bp)
	buf := (*bp)[:0]
	if addr.IsValid() {
		t.writeTo(proto.SealDisco(buf, t.self, shared, payload), addr)
		return
	}
	buf = proto.AppendRelaySend(buf, p.id)
	t.relay.send(proto.SealDisco(buf, t.self, shared, payload))
}

func (t *Transport) sendPing(p *peer, pr probe) {
	var out [proto.DiscoPingLen]byte
	t.sendDisco(p, pr.addr, proto.AppendDiscoPing(out[:0], pr.tx))
}
