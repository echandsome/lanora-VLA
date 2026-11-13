package relay

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"lanora/internal/proto"
)

// TicketTTL is how long a relay ticket is valid. The control server renews
// tickets for connected members well before they expire, so the TTL only
// bounds how long a member that was removed can keep an existing relay
// session on a stand-alone relay node (the built-in relay is told at once).
const TicketTTL = 30 * time.Minute

// Node is a relay as advertised to clients.
type Node struct {
	// UDP is "host:port". An empty host means the host the client used to
	// reach the control server.
	UDP string
	// WS is the URL of the node's stream relay. A path is resolved against
	// the control server URL.
	WS string
}

// Directory decides which relay serves each room and issues the tickets
// that let members bind there.
//
// A room is pinned to one relay by rendezvous hashing, so all of its
// members meet on the same node without any coordination between nodes, and
// adding or removing a node only moves the rooms that were on it.
type Directory struct {
	secret []byte
	local  *Relay // built-in relay, or nil when only stand-alone nodes are used

	mu      sync.RWMutex
	all     []Node
	healthy []Node
}

// NewDirectory returns a directory over the given nodes. local, when set,
// is the in-process relay that revocations are applied to.
func NewDirectory(secret []byte, nodes []Node, local *Relay) *Directory {
	return &Directory{secret: secret, local: local, all: nodes, healthy: nodes}
}

// Ticket returns the relay assignment and credentials for one member.
func (d *Directory) Ticket(room int64, peer netip.Addr) proto.RelayInfo {
	expiry := time.Now().Add(TicketTTL).Unix()
	claims := proto.Claims{Room: uint64(room), Peer: proto.PeerIDOf(peer), Expiry: expiry}.Bytes()
	info := proto.RelayInfo{
		Claims:    claims,
		Key:       proto.RelaySessionKey(d.secret, claims),
		ExpiresAt: expiry,
	}
	if node, ok := d.nodeFor(room); ok {
		info.UDP = []string{node.UDP}
		info.WS = node.WS
	}
	return info
}

// nodeFor picks the relay for a room among the healthy nodes, falling back
// to the full list when none is known healthy (better a stale answer than
// no relay at all).
func (d *Directory) nodeFor(room int64) (Node, bool) {
	d.mu.RLock()
	nodes := d.healthy
	if len(nodes) == 0 {
		nodes = d.all
	}
	d.mu.RUnlock()
	if len(nodes) == 0 {
		return Node{}, false
	}
	best, bestScore := 0, uint64(0)
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], uint64(room))
	for i, n := range nodes {
		h := fnv.New64a()
		h.Write(key[:])
		h.Write([]byte(n.UDP))
		if score := h.Sum64(); i == 0 || score > bestScore {
			best, bestScore = i, score
		}
	}
	return nodes[best], true
}

// Revoke ends a member's session on the built-in relay.
func (d *Directory) Revoke(room int64, peer netip.Addr) {
	if d.local != nil {
		d.local.Revoke(uint64(room), proto.PeerIDOf(peer))
	}
}

// RevokeRoom ends all of a room's sessions on the built-in relay.
func (d *Directory) RevokeRoom(room int64) {
	if d.local != nil {
		d.local.RevokeRoom(uint64(room))
	}
}

// Nodes returns the configured nodes and how many are currently healthy.
func (d *Directory) Nodes() (all []Node, healthy int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]Node(nil), d.all...), len(d.healthy)
}

// Watch probes stand-alone relay nodes until ctx is cancelled and keeps the
// healthy set up to date, calling changed whenever it changes so that rooms
// on a failed node can be moved. It is not needed for the built-in relay.
func (d *Directory) Watch(ctx context.Context, log *slog.Logger, changed func()) {
	const (
		interval  = 10 * time.Second
		timeout   = 2 * time.Second
		threshold = 3 // consecutive failures before a node is taken out
	)
	failures := make(map[string]int)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		d.mu.RLock()
		all := append([]Node(nil), d.all...)
		d.mu.RUnlock()

		var healthy []Node
		for _, n := range all {
			if probeNode(ctx, n.UDP, timeout) {
				failures[n.UDP] = 0
			} else {
				failures[n.UDP]++
			}
			if failures[n.UDP] < threshold {
				healthy = append(healthy, n)
			}
		}

		d.mu.Lock()
		same := len(healthy) == len(d.healthy)
		for i := 0; same && i < len(healthy); i++ {
			same = healthy[i] == d.healthy[i]
		}
		d.healthy = healthy
		d.mu.Unlock()
		if !same {
			log.Warn("relay set changed", "healthy", len(healthy), "configured", len(all))
			if changed != nil {
				changed()
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// probeNode reports whether a relay answers an address probe.
func probeNode(ctx context.Context, addr string, timeout time.Duration) bool {
	var dialer net.Dialer
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialer.DialContext(dctx, "udp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	tx := proto.NewTxID()
	if _, err := conn.Write(proto.AppendProbe(nil, tx)); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	return err == nil && n == proto.ProbeLen && buf[0] == proto.Magic &&
		buf[1] == proto.FrameProbeReply && proto.FrameTxID(buf[:n]) == tx
}
