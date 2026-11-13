package vnet

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeTUN is an in-memory adapter: packets pushed to out are what the
// operating system "sent"; in collects what was delivered to it.
type fakeTUN struct {
	out chan []byte
	in  [][]byte
}

func newFakeTUN() *fakeTUN { return &fakeTUN{out: make(chan []byte, 1024)} }

func (f *fakeTUN) File() *os.File           { return nil }
func (f *fakeTUN) MTU() (int, error)        { return 1280, nil }
func (f *fakeTUN) Name() (string, error)    { return "fake", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return nil }
func (f *fakeTUN) Close() error             { close(f.out); return nil }
func (f *fakeTUN) BatchSize() int           { return 1 }

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-f.out
	if !ok {
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], pkt)
	return 1, nil
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.in = append(f.in, bytes.Clone(b[offset:]))
	}
	return len(bufs), nil
}

var (
	subnet = netip.MustParsePrefix("10.214.3.0/24")
	selfIP = netip.MustParseAddr("10.214.3.5")
	peerB  = netip.MustParseAddr("10.214.3.6")
	peerC  = netip.MustParseAddr("10.214.3.7")
)

// packet builds an IPv4 packet with a valid header checksum.
func packet(src, dst string, proto byte, payload string) []byte {
	p := make([]byte, ipv4HeaderLen+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8], p[9] = 1, proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[10:12], headerChecksum(p[:ipv4HeaderLen]))
	copy(p[ipv4HeaderLen:], payload)
	return p
}

const testOffset = 16 // what WireGuard uses

// readAll returns everything the device hands to WireGuard for the packets
// pushed into the adapter. A trailing unicast marker tells it when to stop.
func readAll(t *testing.T, d *Device, f *fakeTUN, batch int) [][]byte {
	t.Helper()
	marker := packet(selfIP.String(), peerB.String(), 17, "END")
	f.out <- marker
	var got [][]byte
	bufs, sizes := make([][]byte, batch), make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	for {
		n, err := d.Read(bufs, sizes, testOffset)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			pkt := bytes.Clone(bufs[i][testOffset : testOffset+sizes[i]])
			if bytes.Equal(pkt, marker) {
				return got
			}
			got = append(got, pkt)
		}
	}
}

func newDevice() (*Device, *fakeTUN) {
	f := newFakeTUN()
	d := Wrap(f, selfIP, subnet)
	d.SetPeers([]netip.Addr{peerB, peerC, selfIP}) // self is ignored
	return d, f
}

func TestOutboundFilter(t *testing.T) {
	d, f := newDevice()
	keep := packet("10.214.3.5", "10.214.3.6", 6, "tcp to a peer")
	f.out <- keep
	f.out <- packet("10.214.3.5", "8.8.8.8", 17, "to the internet")     // not the room's subnet
	f.out <- packet("10.214.3.5", "10.214.4.6", 17, "another room")     // a different /24
	f.out <- packet("192.168.1.10", "10.214.3.6", 17, "foreign source") // not this adapter's address
	f.out <- []byte{0x60, 0, 0, 0, 0, 0, 0, 0}                          // IPv6
	f.out <- []byte{0x45, 0}                                            // truncated
	got := readAll(t, d, f, 1)
	if len(got) != 1 || !bytes.Equal(got[0], keep) {
		t.Fatalf("passed %d packets, want only the unicast to a peer", len(got))
	}
	if st := d.Stats(); st.Filtered != 5 {
		t.Fatalf("filtered = %d, want 5", st.Filtered)
	}
}

func TestBroadcastFanout(t *testing.T) {
	for _, batch := range []int{1, 128} {
		for _, dst := range []string{"255.255.255.255", "10.214.3.255", "224.0.0.251", "239.255.255.250"} {
			d, f := newDevice()
			orig := packet("10.214.3.5", dst, 17, "who is out there?")
			f.out <- orig
			got := readAll(t, d, f, batch)
			if len(got) != 2 {
				t.Fatalf("batch %d, %s: %d copies, want one per peer", batch, dst, len(got))
			}
			for i, peer := range []netip.Addr{peerB, peerC} {
				c := got[i]
				src, to, proto, ok := ipv4(c)
				if !ok || proto != protoIPIP || src != selfIP.As4() || to != peer.As4() {
					t.Fatalf("copy %d has outer header %v → %v proto %d", i, src, to, proto)
				}
				if headerChecksum(c[:ipv4HeaderLen]) != 0 {
					t.Fatalf("copy %d has a bad outer checksum", i)
				}
				if !bytes.Equal(c[ipv4HeaderLen:], orig) {
					t.Fatalf("copy %d does not carry the original packet unchanged", i)
				}
			}
			if st := d.Stats(); st.FanoutPackets != 1 || st.FanoutCopies != 2 {
				t.Fatalf("stats %+v", st)
			}
		}
	}
}

func TestFanoutSkipsIGMPAndRespectsBudget(t *testing.T) {
	d, f := newDevice()
	f.out <- packet("10.214.3.5", "224.0.0.22", protoIGMP, "membership report")
	if got := readAll(t, d, f, 8); len(got) != 0 {
		t.Fatalf("IGMP was replicated to peers")
	}

	// A flood is cut off at the burst size.
	for i := 0; i < fanoutBurst*3; i++ {
		f.out <- packet("10.214.3.5", "255.255.255.255", 17, "flood")
	}
	got := readAll(t, d, f, 64)
	st := d.Stats()
	if len(got) > (fanoutBurst+20)*2 || st.FanoutDropped < fanoutBurst {
		t.Fatalf("%d copies sent, %d packets dropped", len(got), st.FanoutDropped)
	}

	// With nobody else in the room nothing is queued.
	d2, f2 := newDevice()
	d2.SetPeers(nil)
	f2.out <- packet("10.214.3.5", "255.255.255.255", 17, "alone")
	if got := readAll(t, d2, f2, 8); len(got) != 0 {
		t.Fatalf("copies made for an empty room")
	}
}

// deliver passes packets to the device as WireGuard would after decrypting.
func deliver(d *Device, pkts ...[]byte) {
	bufs := make([][]byte, len(pkts))
	for i, p := range pkts {
		bufs[i] = append(make([]byte, testOffset), p...)
	}
	d.Write(bufs, testOffset)
}

func TestInboundFilterAndDecapsulation(t *testing.T) {
	d, f := newDevice()
	unicast := packet("10.214.3.6", "10.214.3.5", 6, "hello")
	inner := packet("10.214.3.6", "255.255.255.255", 17, "lobby announcement")
	wrap := func(outerSrc string, in []byte) []byte {
		w := packet(outerSrc, "10.214.3.5", protoIPIP, string(in))
		return w
	}

	deliver(d,
		unicast,
		wrap("10.214.3.6", inner),
		packet("10.214.3.6", "192.168.1.20", 6, "another local address"), // not the virtual address
		packet("10.214.3.6", "255.255.255.255", 17, "raw broadcast"),     // must arrive encapsulated
		packet("172.16.0.9", "10.214.3.5", 6, "source outside the room"), // cannot happen through WireGuard, still refused
		packet("10.214.3.5", "10.214.3.5", 6, "claims to be from ourselves"),
		wrap("10.214.3.6", packet("10.214.3.7", "255.255.255.255", 17, "spoofed inner source")),
		wrap("10.214.3.6", packet("10.214.3.6", "10.214.3.5", 6, "unicast hidden in a wrapper")),
		wrap("10.214.3.6", packet("10.214.3.6", "192.168.1.20", 6, "wrapper aimed at another address")),
		wrap("10.214.3.6", []byte("not an IP packet at all")),
	)
	if len(f.in) != 2 {
		t.Fatalf("%d packets delivered, want 2", len(f.in))
	}
	if !bytes.Equal(f.in[0], unicast) {
		t.Fatalf("unicast was altered")
	}
	if !bytes.Equal(f.in[1], inner) {
		t.Fatalf("broadcast delivered as % x, want the original inner packet", f.in[1])
	}
	if st := d.Stats(); st.Delivered != 1 || st.Filtered != 8 {
		t.Fatalf("stats %+v", st)
	}
}

func TestBroadcastRoundTripBetweenTwoDevices(t *testing.T) {
	fa, fb := newFakeTUN(), newFakeTUN()
	a := Wrap(fa, selfIP, subnet)
	b := Wrap(fb, peerB, subnet)
	a.SetPeers([]netip.Addr{peerB})
	b.SetPeers([]netip.Addr{selfIP})

	orig := packet(selfIP.String(), "224.0.2.60", 17, "[MOTD]A Minecraft world[/MOTD][AD]25565[/AD]")
	fa.out <- orig
	copies := readAll(t, a, fa, 1)
	if len(copies) != 1 {
		t.Fatalf("%d copies", len(copies))
	}
	deliver(b, copies[0])
	if len(fb.in) != 1 || !bytes.Equal(fb.in[0], orig) {
		t.Fatalf("the peer's adapter did not receive the original multicast packet")
	}
}
