// Package vnet sits between the virtual network adapter and WireGuard and
// makes a routed (layer 3) tunnel behave like a LAN segment.
//
// WireGuard routes each packet to exactly one peer by destination address,
// so on its own it cannot carry the broadcast and multicast traffic that LAN
// software relies on to find other machines: game lobbies, Windows network
// discovery, mDNS, SSDP. This package supplies that: every broadcast or
// multicast packet the operating system sends on the adapter is delivered to
// every peer in the room, unchanged, and arrives there as the same broadcast
// or multicast packet.
//
// Each copy travels inside WireGuard as an IPv4-in-IPv4 packet addressed to
// one peer. The outer header exists only so WireGuard can route it; the
// receiving side removes it and hands the original packet to its adapter.
// Because the copies are ordinary WireGuard traffic, they are encrypted and
// authenticated exactly like everything else.
//
// The package is also the adapter's packet filter. Only IPv4 between this
// machine's virtual address and the room's subnet passes, in either
// direction, so a room member can reach this machine's virtual address and
// nothing else on it.
package vnet

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	ipv4HeaderLen = 20
	protoIGMP     = 2
	protoIPIP     = 4 // IPv4 encapsulated in IPv4

	// Broadcast budget: how many broadcast/multicast packets per second this
	// client will replicate to the room. Discovery traffic is a few packets
	// per second; the limit only stops a misbehaving program from flooding
	// every peer.
	fanoutPerSecond = 100
	fanoutBurst     = 200
	// maxPending bounds the copies waiting to be handed to WireGuard.
	maxPending = 4096
)

// Stats counts what the device did with broadcast and filtered traffic.
type Stats struct {
	FanoutPackets uint64 // broadcast/multicast packets replicated to peers
	FanoutCopies  uint64 // copies sent
	FanoutDropped uint64 // not replicated: over budget, or queue full
	Delivered     uint64 // broadcast/multicast packets received from peers
	Filtered      uint64 // packets dropped by the address filter
}

// Device wraps the adapter's tun.Device.
type Device struct {
	tun.Device
	self   [4]byte
	subnet netip.Prefix
	bcast  [4]byte // the subnet's directed broadcast address

	peers atomic.Pointer[[][4]byte]

	// Outbound copies waiting for WireGuard to read them. Only Read touches
	// the queue, and WireGuard reads from a single goroutine, but the lock
	// keeps the type safe to use from tests and other callers.
	mu      sync.Mutex
	pending []pendingCopy
	head    int
	ipID    uint16
	tokens  float64
	refill  time.Time

	fanoutPackets, fanoutCopies, fanoutDropped, delivered, filtered atomic.Uint64
}

type pendingCopy struct {
	inner *[]byte // shared by all copies of one packet
	dst   [4]byte
}

// Wrap returns a Device for an adapter that owns the address self inside the
// room's subnet.
func Wrap(dev tun.Device, self netip.Addr, subnet netip.Prefix) *Device {
	d := &Device{Device: dev, self: self.As4(), subnet: subnet.Masked(), tokens: fanoutBurst, refill: time.Now()}
	base := binary.BigEndian.Uint32(d.subnet.Addr().AsSlice())
	binary.BigEndian.PutUint32(d.bcast[:], base|(1<<(32-subnet.Bits())-1))
	empty := [][4]byte{}
	d.peers.Store(&empty)
	return d
}

// SetPeers replaces the list of peers that broadcasts are delivered to.
func (d *Device) SetPeers(ips []netip.Addr) {
	list := make([][4]byte, 0, len(ips))
	for _, ip := range ips {
		if ip.Is4() && ip.As4() != d.self {
			list = append(list, ip.As4())
		}
	}
	d.peers.Store(&list)
}

// Stats returns the device's counters.
func (d *Device) Stats() Stats {
	return Stats{
		FanoutPackets: d.fanoutPackets.Load(),
		FanoutCopies:  d.fanoutCopies.Load(),
		FanoutDropped: d.fanoutDropped.Load(),
		Delivered:     d.delivered.Load(),
		Filtered:      d.filtered.Load(),
	}
}

// isGroup reports whether dst is an address that names every machine on the
// segment: limited broadcast, the subnet's directed broadcast, or multicast.
func (d *Device) isGroup(dst [4]byte) bool {
	return dst == [4]byte{255, 255, 255, 255} || dst == d.bcast || dst[0]&0xf0 == 0xe0
}

func (d *Device) inSubnet(a [4]byte) bool { return d.subnet.Contains(netip.AddrFrom4(a)) }

// ipv4 validates the fixed part of an IPv4 header and returns its addresses
// and protocol.
func ipv4(pkt []byte) (src, dst [4]byte, proto byte, ok bool) {
	if len(pkt) < ipv4HeaderLen || pkt[0]>>4 != 4 {
		return src, dst, 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < ipv4HeaderLen || total < ihl || total > len(pkt) {
		return src, dst, 0, false
	}
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])
	return src, dst, pkt[9], true
}

// Read implements tun.Device: it returns packets for WireGuard to send.
// Unicast packets pass through; broadcast and multicast packets are replaced
// by one encapsulated copy per peer.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		if n := d.drain(bufs, sizes, offset); n > 0 {
			return n, nil
		}
		n, err := d.Device.Read(bufs, sizes, offset)
		kept := 0
		for i := 0; i < n; i++ {
			pkt := bufs[i][offset : offset+sizes[i]]
			src, dst, proto, ok := ipv4(pkt)
			switch {
			case !ok || src != d.self:
				// Not IPv4, or not from this adapter's address.
				sizes[i] = 0
				d.filtered.Add(1)
			case d.isGroup(dst):
				// WireGuard skips zero-length entries, so the original is
				// consumed here and its copies are queued instead.
				sizes[i] = 0
				if proto != protoIGMP { // group membership reports mean nothing to remote peers
					d.fanout(pkt)
				}
			case !d.inSubnet(dst):
				sizes[i] = 0
				d.filtered.Add(1)
			default:
				kept++
			}
		}
		if kept > 0 || err != nil {
			return n, err
		}
		// Everything read was consumed; go round again, which first hands
		// out any copies just queued.
	}
}

// fanout queues one copy of pkt for every peer.
func (d *Device) fanout(pkt []byte) {
	peers := *d.peers.Load()
	if len(peers) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	d.tokens = min(fanoutBurst, d.tokens+now.Sub(d.refill).Seconds()*fanoutPerSecond)
	d.refill = now
	if d.tokens < 1 || len(d.pending)-d.head+len(peers) > maxPending {
		d.fanoutDropped.Add(1)
		return
	}
	d.tokens--

	inner := make([]byte, len(pkt))
	copy(inner, pkt)
	for _, p := range peers {
		d.pending = append(d.pending, pendingCopy{inner: &inner, dst: p})
	}
	d.fanoutPackets.Add(1)
}

// drain moves queued copies into WireGuard's buffers, building the outer
// header of each in place.
func (d *Device) drain(bufs [][]byte, sizes []int, offset int) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for n < len(bufs) && d.head < len(d.pending) {
		c := d.pending[d.head]
		d.pending[d.head] = pendingCopy{}
		d.head++
		inner := *c.inner
		total := ipv4HeaderLen + len(inner)
		if offset+total > len(bufs[n]) || total > 0xffff {
			d.fanoutDropped.Add(1)
			continue
		}
		out := bufs[n][offset : offset+total]
		d.ipID++
		out[0] = 0x45 // version 4, header length 5 words
		out[1] = 0
		binary.BigEndian.PutUint16(out[2:4], uint16(total))
		binary.BigEndian.PutUint16(out[4:6], d.ipID)
		out[6], out[7] = 0, 0 // no flags, not a fragment
		out[8] = 64
		out[9] = protoIPIP
		out[10], out[11] = 0, 0
		copy(out[12:16], d.self[:])
		copy(out[16:20], c.dst[:])
		binary.BigEndian.PutUint16(out[10:12], headerChecksum(out[:ipv4HeaderLen]))
		copy(out[ipv4HeaderLen:], inner)
		sizes[n] = total
		n++
		d.fanoutCopies.Add(1)
	}
	if d.head == len(d.pending) {
		d.pending, d.head = d.pending[:0], 0
	}
	return n
}

// headerChecksum computes the IPv4 header checksum of hdr, whose checksum
// field must be zero.
func headerChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// Write implements tun.Device: it delivers packets WireGuard received from
// peers to the adapter. Encapsulated broadcasts are unwrapped first, and
// anything not addressed to this machine's virtual address is dropped.
//
// WireGuard has already verified that each packet's source address belongs
// to the peer that sent it.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	// Fast path: plain unicast for this machine goes straight through
	// without touching the heap.
	plain := true
	for _, buf := range bufs {
		if d.classify(buf[offset:]) != deliverAsIs {
			plain = false
			break
		}
	}
	if plain {
		return d.Device.Write(bufs, offset)
	}

	// WireGuard calls Write from one goroutine per peer, so the list of
	// packets to deliver must be per call.
	out := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		pkt := buf[offset:]
		switch d.classify(pkt) {
		case deliverAsIs:
			out = append(out, buf)
		case deliverInner:
			// Shift the slice so the inner packet starts where the adapter
			// expects a packet to start.
			hdr := int(pkt[0]&0x0f) * 4
			total := int(binary.BigEndian.Uint16(pkt[2:4]))
			out = append(out, buf[hdr:offset+total])
			d.delivered.Add(1)
		default:
			d.filtered.Add(1)
		}
	}
	if len(out) > 0 {
		if _, err := d.Device.Write(out, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

type verdict int

const (
	drop verdict = iota
	deliverAsIs
	deliverInner
)

// classify decides what to do with a packet received from a peer.
func (d *Device) classify(pkt []byte) verdict {
	src, dst, proto, ok := ipv4(pkt)
	if !ok || dst != d.self || src == d.self || !d.inSubnet(src) {
		return drop
	}
	if proto != protoIPIP {
		return deliverAsIs
	}
	// An encapsulated broadcast. The inner packet must be a broadcast or
	// multicast from the same peer; anything else is an attempt to use the
	// wrapper to get a packet past the address filter.
	hdr := int(pkt[0]&0x0f) * 4
	inner := pkt[hdr:int(binary.BigEndian.Uint16(pkt[2:4]))]
	isrc, idst, _, ok := ipv4(inner)
	if !ok || isrc != src || !d.isGroup(idst) || len(inner) != int(binary.BigEndian.Uint16(inner[2:4])) {
		return drop
	}
	return deliverInner
}
