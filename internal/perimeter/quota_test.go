package perimeter

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// TestDeviceAddrs: a device holds grants from at most DeviceAddrs addresses
// at once; a grant from one more closes the one that ends first, not the
// new one: one who forwards a device's knocks from addresses of its own
// cannot shut it out. A grant another device holds stays open; a device
// the snapshot no longer has is forgotten (protocol review 2026-11).
func TestDeviceAddrs(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}},
		&perimeterv1.Device{Id: "bob", Key: key(0x22), Allowed: []uint32{1}})
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	addr := func(i int) netip.Addr {
		return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)})
	}
	open := func(i int) bool { return fw.isOpen(addr(i).String() + " tcp/443") }
	// bob holds a grant from alice's second address too.
	if _, err := g.Handle(addr(1), netip.Addr{}, seal(t, snap, 0x22, now)); err != nil {
		t.Fatal(err)
	}
	for i := range DeviceAddrs {
		if _, err := g.Handle(addr(i), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
			t.Fatalf("address %d: %v", i, err)
		}
		now = now.Add(time.Second) // the first ends first
	}
	if _, err := g.Handle(addr(DeviceAddrs), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatalf("one address more: %v", err)
	}
	if !open(DeviceAddrs) || open(0) || len(g.addrs["alice"]) != DeviceAddrs {
		t.Fatalf("one more: it open %v, the first open %v, %d held", open(DeviceAddrs), open(0), len(g.addrs["alice"]))
	}
	// Again: the second goes for alice, and stays open for bob.
	if _, err := g.Handle(addr(DeviceAddrs+1), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatal(err)
	}
	if _, held := g.addrs["alice"][addr(1)]; held || !open(1) {
		t.Fatalf("the second: alice holds it %v, open %v (bob holds it)", held, open(1))
	}
	if _, held := g.holders[grantKey{addr(1), Port{Proto: "tcp", Num: 443}}]["alice"]; held {
		t.Fatal("alice still among the holders of her second address")
	}
	// A device the snapshot no longer has is forgotten.
	snap.Devices = snap.Devices[1:]
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.addrs["alice"]; ok {
		t.Fatal("a revoked device's addresses kept")
	}
}

// TestCheckBudget: past the budget of checks, packets from sources without
// a grant are not checked (ErrFlood); a source that holds one is, and so
// renews its grant through a flood.
func TestCheckBudget(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}})
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if want := float64(verifyRateMax); g.budgetRate != want {
		t.Fatalf("one device: budget %v, want %v", g.budgetRate, want)
	}
	client := netip.MustParseAddr("2001:db8:7:7::1")
	if _, err := g.Handle(client, netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatal(err)
	}
	junk := make([]byte, 120)
	flooded := 0
	for i := range int(g.budgetRate) + 100 {
		src := netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})
		if _, err := g.Handle(src, netip.Addr{}, junk); errors.Is(err, ErrFlood) {
			flooded++
		}
	}
	if flooded < 99 || flooded > 101 {
		t.Fatalf("%d of the packets past the budget not checked, want 100", flooded)
	}
	// Another address of the client's /64 knocks again: checked, granted.
	if _, err := g.Handle(netip.MustParseAddr("2001:db8:7:7::2"), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatalf("a source with a grant, through the flood: %v", err)
	}
	if _, err := g.Handle(netip.MustParseAddr("2001:db8:7:8::1"), netip.Addr{}, seal(t, snap, 0x11, now)); !errors.Is(err, ErrFlood) {
		t.Fatalf("a new source through the flood: %v", err)
	}
	// A second later the budget has refilled.
	now = now.Add(time.Second)
	if _, err := g.Handle(netip.MustParseAddr("2001:db8:7:8::1"), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatalf("a new source a second later: %v", err)
	}
	// The budget falls with the devices: each costs every packet a check.
	if r := verifyRate(1000); r != float64(verifyShare)/float64(1000*verifyPerDevice) {
		t.Fatalf("1000 devices: %v", r)
	}
	if r := verifyRate(100000); r != verifyRateMin {
		t.Fatalf("100000 devices: %v", r)
	}
}
