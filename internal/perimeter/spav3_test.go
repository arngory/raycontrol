package perimeter

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/spa"
)

func seal3(t *testing.T, snap *perimeterv1.Snapshot, k byte, now time.Time, dst string) []byte {
	t.Helper()
	p, err := paramsOf(snap.Spa)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := spa.SealRandom(p, [spa.KeySize]byte(key(k)), spa.Request{Time: now, Dst: netip.MustParseAddr(dst)})
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

// TestGateV3: a v3 packet opens only at the node's own addresses, the ones
// of the snapshot (1:1 NAT) or the one it came to; v2 as ever.
func TestGateV3(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}})
	snap.OwnAddrs = []string{"203.0.113.7", "2001:db8::7"}
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddr("198.51.100.20")
	wire := netip.MustParseAddr("10.0.0.5") // behind 1:1 NAT
	for _, ok := range []string{"203.0.113.7", "2001:db8::7", "10.0.0.5", "64:ff9b::cb00:7107"} {
		if _, err := g.Handle(src, wire, seal3(t, snap, 0x11, now, ok)); err != nil {
			t.Fatalf("to %s: %v", ok, err)
		}
	}
	if !fw.isOpen("198.51.100.20 tcp/443") {
		t.Fatalf("open = %v", fw.open)
	}
	other := netip.MustParseAddr("198.51.100.30")
	for _, bad := range []string{"198.51.100.99", "2001:db8::99", "64:ff9b::c633:6463"} {
		_, err := g.Handle(other, wire, seal3(t, snap, 0x11, now, bad))
		if !errors.Is(err, spa.ErrDst) {
			t.Fatalf("to %s: %v", bad, err)
		}
	}
	// Not knowing where it came to, only the snapshot's addresses count.
	if _, err := g.Handle(other, netip.Addr{}, seal3(t, snap, 0x11, now, "10.0.0.5")); !errors.Is(err, spa.ErrDst) {
		t.Fatalf("unknown wire: %v", err)
	}
	if fw.isOpen("198.51.100.30 tcp/443") {
		t.Fatalf("a packet for another address opened: %v", fw.open)
	}
	// v2 still opens, wherever it came to.
	if _, err := g.Handle(other, netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatal(err)
	}
	if !fw.isOpen("198.51.100.30 tcp/443") {
		t.Fatalf("v2 refused: %v", fw.open)
	}

	// An older rayd sends no own addresses: the wire address still counts.
	snap.OwnAddrs = nil
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Handle(src, wire, seal3(t, snap, 0x11, now, "203.0.113.7")); !errors.Is(err, spa.ErrDst) {
		t.Fatalf("own addresses kept: %v", err)
	}
	if _, err := g.Handle(src, wire, seal3(t, snap, 0x11, now, "10.0.0.5")); err != nil {
		t.Fatal(err)
	}
	// What is no address of a node is left out, the rest kept: the
	// snapshot itself goes in (it carries revocations too).
	snap.OwnAddrs = []string{"10.0.0.0/8", "fe80::1%eth0", "0.0.0.0", "::ffff:0.0.0.0", "224.0.0.1", "255.255.255.255", "203.0.113.7"}
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if len(g.own) != 1 || g.own[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("own %v", g.own)
	}
	many := make([]string, maxOwnAddrs+4)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}).String()
	}
	snap.OwnAddrs = many
	if err := g.Update(snap); err != nil || len(g.own) != maxOwnAddrs {
		t.Fatalf("own %d, %v", len(g.own), err)
	}
}

// TestTCPCarrierDst: the TCP carrier hands over the address the connection
// came to.
func TestTCPCarrierDst(t *testing.T) {
	got := make(chan netip.Addr, 1)
	c := &TCPCarrier{Handler: func(_, dst netip.Addr, _ []byte) { got <- dst }, LenMax: func() int { return 160 }, Log: quiet}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	c.Reconcile([]uint16{uint16(port)})
	defer c.Close()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write(make([]byte, 100))
	_ = conn.(*net.TCPConn).CloseWrite()
	select {
	case dst := <-got:
		if dst != netip.MustParseAddr("127.0.0.1") {
			t.Fatalf("dst = %v", dst)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no packet")
	}
	conn.Close()
}
