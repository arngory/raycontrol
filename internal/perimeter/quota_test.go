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
// a grant are not checked (ErrFlood); a source that holds one is, against
// its own devices, and so renews its grant through a flood; so is the TCP
// carrier. What costs no decryption (length, a nonce seen) spends no
// budget; a revoked device's sources hold no grant.
func TestCheckBudget(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}},
		&perimeterv1.Device{Id: "bob", Key: key(0x22), Allowed: []uint32{1}})
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if want := verifyRate(2); g.budgetRate != want {
		t.Fatalf("two devices: budget %v, want %v", g.budgetRate, want)
	}
	client := netip.MustParseAddr("2001:db8:7:7::1")
	if _, err := g.Handle(client, netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatal(err)
	}
	bobAt := netip.MustParseAddr("198.51.100.200")
	if _, err := g.Handle(bobAt, netip.Addr{}, seal(t, snap, 0x22, now)); err != nil {
		t.Fatal(err)
	}
	// Free: a wrong length, a nonce seen.
	seen := seal(t, snap, 0x11, now)
	if _, err := g.Handle(netip.MustParseAddr("2001:db8:9::1"), netip.Addr{}, seen); err != nil {
		t.Fatal(err)
	}
	before := g.budget.tokens
	for range 100 {
		g.Handle(netip.MustParseAddr("203.0.113.1"), netip.Addr{}, []byte("short"))
		g.Handle(netip.MustParseAddr("203.0.113.1"), netip.Addr{}, seen)
	}
	if g.budget.tokens != before {
		t.Fatalf("free packets spent %v of the budget", before-g.budget.tokens)
	}
	junk := make([]byte, 120)
	flooded := 0
	for i := range int(g.budgetRate) + 100 {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		if _, err := g.Handle(src, netip.Addr{}, junk); errors.Is(err, ErrFlood) {
			flooded++
		}
	}
	if flooded < 99 || flooded > 103 {
		t.Fatalf("%d of the packets past the budget not checked, want 100", flooded)
	}
	// Another address of the client's /64 knocks again: checked, granted.
	if _, err := g.Handle(netip.MustParseAddr("2001:db8:7:7::2"), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatalf("a source with a grant, through the flood: %v", err)
	}
	if _, err := g.Handle(netip.MustParseAddr("2001:db8:7:8::1"), netip.Addr{}, seal(t, snap, 0x11, now)); !errors.Is(err, ErrFlood) {
		t.Fatalf("a new source through the flood: %v", err)
	}
	if _, err := g.HandleStream(netip.MustParseAddr("2001:db8:7:8::1"), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatalf("a new source over the TCP carrier, through the flood: %v", err)
	}
	// bob is revoked: his source holds no grant any more, and is checked
	// on the budget of the others without one.
	snap.Devices = snap.Devices[:1]
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if ks := g.known[knockSource(bobAt)]; ks != nil {
		t.Fatalf("a revoked device's source known: %v", ks.devices)
	}
	if _, err := g.Handle(bobAt, netip.Addr{}, junk); !errors.Is(err, ErrFlood) {
		t.Fatalf("a revoked device's source through the flood: %v", err)
	}
	// A second later the budget has refilled.
	now = now.Add(time.Second)
	if _, err := g.Handle(netip.MustParseAddr("2001:db8:7:9::1"), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatalf("a new source a second later: %v", err)
	}
	// The budget falls with the devices: each costs every packet a check.
	if r := verifyRate(1000); r != float64(verifyShare)/float64(1000*verifyPerDevice) {
		t.Fatalf("1000 devices: %v", r)
	}
	if r := verifyRate(100000); r != verifyRateMin {
		t.Fatalf("100000 devices: %v", r)
	}
	if r := verifyRate(1); r != verifyRateMax {
		t.Fatalf("one device: %v", r)
	}
}

// TestKnownSources: a source with a grant is tried against its own devices
// apart from both budgets, over UDP and the TCP carrier alike (third
// review: one shared budget for them, and the carrier's taken first, let
// a leaked invite's junk from its own sources, or a carrier flood, starve
// every renewal). One spoofing a client's source spends that source's
// share only: another's renewals pass; past it, the source's packets go
// to the budget of the others.
func TestKnownSources(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}},
		&perimeterv1.Device{Id: "bob", Key: key(0x22), Allowed: []uint32{1}},
		&perimeterv1.Device{Id: "carol", Key: key(0x33), Allowed: []uint32{1}})
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	alice, bob := netip.MustParseAddr("2001:db8:7:7::1"), netip.MustParseAddr("198.51.100.200")
	for k, src := range map[byte]netip.Addr{0x11: alice, 0x22: bob} {
		if _, err := g.Handle(src, netip.Addr{}, seal(t, snap, k, now)); err != nil {
			t.Fatal(err)
		}
	}
	// Both budgets flooded.
	junk := make([]byte, 120)
	for i := range int(g.budgetRate) + 10 {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		g.Handle(src, netip.Addr{}, junk)
		g.HandleStream(src, netip.Addr{}, junk)
	}
	if _, err := g.Handle(netip.MustParseAddr("203.0.113.9"), netip.Addr{}, seal(t, snap, 0x33, now)); !errors.Is(err, ErrFlood) {
		t.Fatalf("not flooded: %v", err)
	}
	if _, err := g.HandleStream(netip.MustParseAddr("203.0.113.9"), netip.Addr{}, seal(t, snap, 0x33, now)); !errors.Is(err, ErrFlood) {
		t.Fatalf("the carrier not flooded: %v", err)
	}
	if _, err := g.Handle(alice, netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatalf("alice renews over UDP through the floods: %v", err)
	}
	if _, err := g.HandleStream(alice, netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatalf("alice renews over the carrier through the floods: %v", err)
	}
	// carol behind alice's source (CGNAT) is not among its devices: the
	// budget of the others, flooded.
	if _, err := g.Handle(alice, netip.Addr{}, seal(t, snap, 0x33, now)); !errors.Is(err, ErrFlood) {
		t.Fatalf("carol from alice's source: %v", err)
	}
	// Junk from alice's /64 spends its share; bob renews all the same.
	for range knownSourceRate + 2 {
		g.Handle(netip.MustParseAddr("2001:db8:7:7::99"), netip.Addr{}, junk)
	}
	if _, err := g.Handle(alice, netip.Addr{}, seal(t, snap, 0x11, now)); !errors.Is(err, ErrFlood) {
		t.Fatalf("alice past her source's share, in the flood: %v", err)
	}
	if _, err := g.Handle(bob, netip.Addr{}, seal(t, snap, 0x22, now)); err != nil {
		t.Fatalf("bob's source untouched by the junk from alice's: %v", err)
	}
	// A second later both budgets and alice's share have refilled.
	now = now.Add(time.Second)
	if _, err := g.Handle(alice, netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatalf("alice a second later: %v", err)
	}
}

// TestDeviceMoves: past DeviceAddrs a device brings at most DeviceAddrs new
// addresses a minute (ErrAddrs): each closes a grant, one nft transaction
// for all its ports (third review: an nft removal costs 17 ms, a knock that
// evicted three ports 52 ms under the gate's lock). Knocks from an address
// it holds take none.
func TestDeviceMoves(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1, 2, 3}})
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	addr := func(i int) netip.Addr {
		return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 12: byte(i >> 8), 13: byte(i), 15: 1})
	}
	knock := func(i int) error {
		t.Helper()
		_, err := g.Handle(addr(i), netip.Addr{}, seal(t, snap, 0x11, now))
		return err
	}
	for i := range DeviceAddrs {
		if err := knock(i); err != nil {
			t.Fatalf("address %d: %v", i, err)
		}
	}
	denies := fw.denies
	for i := range DeviceAddrs {
		if err := knock(DeviceAddrs + i); err != nil {
			t.Fatalf("move %d: %v", i, err)
		}
	}
	// Three ports (tcp 443, udp 443, tcp 22) of each evicted address in one
	// transaction.
	if n := fw.denies - denies; n != DeviceAddrs {
		t.Fatalf("%d removals for %d evictions", n, DeviceAddrs)
	}
	if err := knock(2 * DeviceAddrs); !errors.Is(err, ErrAddrs) {
		t.Fatalf("one move more in the minute: %v", err)
	}
	if fw.isOpen(addr(2*DeviceAddrs).String() + " tcp/443") {
		t.Fatal("refused, yet opened")
	}
	if err := knock(2*DeviceAddrs - 1); err != nil {
		t.Fatalf("again from an address it holds: %v", err)
	}
	now = now.Add(time.Minute)
	if err := knock(2 * DeviceAddrs); err != nil {
		t.Fatalf("a minute later: %v", err)
	}
}
