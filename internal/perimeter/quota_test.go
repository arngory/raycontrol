package perimeter

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// TestDeviceAddrs: a device holds grants from at most DeviceAddrs addresses
// at once, the addresses of one /64 as any; another device still opens, and
// an address frees when its grant ends (protocol review 2026-11).
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
	for i := range DeviceAddrs {
		if _, err := g.Handle(addr(i), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
			t.Fatalf("address %d: %v", i, err)
		}
	}
	// Again from one it holds: that is no new address.
	if _, err := g.Handle(addr(0), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatalf("an address it holds: %v", err)
	}
	if _, err := g.Handle(addr(DeviceAddrs), netip.Addr{}, seal(t, snap, 0x11, now)); !errors.Is(err, ErrAddrs) {
		t.Fatalf("one address more: %v", err)
	}
	if fw.isOpen(addr(DeviceAddrs).String() + " tcp/443") {
		t.Fatal("the refused knock opened")
	}
	if _, err := g.Handle(addr(DeviceAddrs), netip.Addr{}, seal(t, snap, 0x22, now)); err != nil {
		t.Fatalf("another device: %v", err)
	}
	// The grants end (600 s, the snapshot's TTL): the addresses free.
	now = now.Add(601 * time.Second)
	if _, err := g.Tick(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Handle(addr(DeviceAddrs+1), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatalf("after the grants ended: %v", err)
	}
	if n := len(g.addrs["alice"]); n != 1 {
		t.Fatalf("alice holds %d addresses", n)
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
