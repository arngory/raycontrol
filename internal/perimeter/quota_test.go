package perimeter

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/spa"
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
	for i := range DeviceAddrs {
		if _, err := g.Handle(addr(i), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
			t.Fatalf("address %d: %v", i, err)
		}
		now = now.Add(time.Second) // the first ends first
	}
	// bob holds a grant from alice's second address too. Before her
	// knocks, his would have given hers from there his end (renewSlack).
	if _, err := g.Handle(addr(1), netip.Addr{}, seal(t, snap, 0x22, now)); err != nil {
		t.Fatal(err)
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
	if r := verifyRate(1); r != float64(verifyShare)/float64(verifyPerDevice) {
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

// TestDeviceChanges: a device changes the table with at most
// DeviceChanges knocks a minute, past as many at once (ErrChanges): new
// addresses, the evictions past DeviceAddrs, grants that grow (fourth
// review: a renewal is an nft removal, some 20 ms under the gate's lock,
// and a leaked invite knocking at its quota held it 83 ms a second). A
// knock that leaves the table as it is takes none.
func TestDeviceChanges(t *testing.T) {
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
	if err := knock(DeviceAddrs); !errors.Is(err, ErrChanges) {
		t.Fatalf("one change more at once: %v", err)
	}
	if fw.isOpen(addr(DeviceAddrs).String() + " tcp/443") {
		t.Fatal("refused, yet opened")
	}
	tx := fw.transactions
	if err := knock(DeviceAddrs - 1); err != nil || fw.transactions != tx {
		t.Fatalf("again from an address it holds: %d transactions, %v", fw.transactions-tx, err)
	}
	now = now.Add(time.Minute)
	denies := fw.denies
	for i := range DeviceChanges {
		if err := knock(DeviceAddrs + i); err != nil {
			t.Fatalf("move %d a minute later: %v", i, err)
		}
	}
	// Three ports (tcp 443, udp 443, tcp 22) of each evicted address in one
	// transaction.
	if n := fw.denies - denies; n != DeviceChanges {
		t.Fatalf("%d removals for %d evictions", n, DeviceChanges)
	}
	if err := knock(DeviceAddrs + DeviceChanges); !errors.Is(err, ErrChanges) {
		t.Fatalf("one move more in the minute: %v", err)
	}
	// Half a minute refills half the budget.
	now = now.Add(30 * time.Second)
	for i := range DeviceChanges / 2 {
		if err := knock(DeviceAddrs + DeviceChanges + i); err != nil {
			t.Fatalf("move %d half a minute later: %v", i, err)
		}
	}
	if err := knock(DeviceAddrs + DeviceChanges + DeviceChanges/2); !errors.Is(err, ErrChanges) {
		t.Fatalf("past half the budget: %v", err)
	}
}

// TestGrantUnchanged: a knock that changes no port's end by renewSlack or
// more leaves the table as it is, and the device holds what the table
// gives (fourth review: another device's longer grants from the source
// made a 1 s knock one nft transaction a distinct end, 200 ms for ten).
func TestGrantUnchanged(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{2, 3}},
		&perimeterv1.Device{Id: "bob", Key: key(0x22), Allowed: []uint32{2, 3}})
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	p, err := paramsOf(snap.Spa)
	if err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddr("198.51.100.9")
	knock := func(k byte, ttl time.Duration, scope ...uint16) error {
		t.Helper()
		pkt, err := spa.SealRandom(p, [spa.KeySize]byte(key(k)), spa.Request{Time: now, TTL: ttl, Scope: scope})
		if err != nil {
			t.Fatal(err)
		}
		_, err = g.Handle(src, netip.Addr{}, pkt)
		return err
	}
	tcp, udp := grantKey{src, Port{"tcp", 22}}, grantKey{src, Port{"udp", 443}}
	tx := func() int { fw.mu.Lock(); defer fw.mu.Unlock(); return fw.transactions }

	// bob holds tcp/22 an hour, udp/443 and tcp/443 ten minutes.
	if err := knock(0x22, time.Hour, 3); err != nil {
		t.Fatal(err)
	}
	if err := knock(0x22, 10*time.Minute, 2); err != nil {
		t.Fatal(err)
	}
	// alice's knock of a second from bob's address, every port: nothing
	// changes, no transaction; she holds them a second.
	before := tx()
	if err := knock(0x11, time.Second); err != nil || tx() != before {
		t.Fatalf("a knock under bob's grants: %d transactions, %v", tx()-before, err)
	}
	if u := g.holders[tcp]["alice"]; !u.Equal(now.Add(time.Second)) {
		t.Fatalf("alice holds tcp/22 until %v", u.Sub(now))
	}
	// Her knock of 10 min 20 s: the 443s would grow by 20 s, under the
	// slack: left as they are, and she holds them as long as bob's grant
	// lasts.
	if err := knock(0x11, 10*time.Minute+20*time.Second); err != nil || tx() != before {
		t.Fatalf("a knock under the slack: %d transactions, %v", tx()-before, err)
	}
	if u := g.holders[udp]["alice"]; !u.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("alice holds udp/443 until %v, not the grant's end", u.Sub(now))
	}
	// 20 minutes: one transaction for the two ports that grow, tcp/22 left.
	if err := knock(0x11, 20*time.Minute); err != nil || tx() != before+1 {
		t.Fatalf("a knock that grows a grant: %d transactions, %v", tx()-before, err)
	}
	if d, _ := fw.ttl(udp); d != 20*time.Minute {
		t.Fatalf("udp/443 for %v", d)
	}
	if d, _ := fw.ttl(tcp); d != time.Hour {
		t.Fatalf("tcp/22 for %v, bob's hour cut", d)
	}
	// The same knock again 29 s later: left as is, the grant lasts 19 min
	// 31 s still. At 31 s it grows.
	now = now.Add(29 * time.Second)
	if err := knock(0x11, 20*time.Minute); err != nil || tx() != before+1 {
		t.Fatalf("a renewal under the slack: %d transactions, %v", tx()-before, err)
	}
	now = now.Add(2 * time.Second)
	if err := knock(0x11, 20*time.Minute); err != nil || tx() != before+2 {
		t.Fatalf("a renewal past the slack: %d transactions, %v", tx()-before, err)
	}
	// A short TTL has a short slack: half of it.
	if renewSlack(4*time.Second) != 2*time.Second || renewSlack(time.Hour) != 30*time.Second {
		t.Fatal("slack")
	}
	// A grant whose change waits (a shortening the firewall refused) is
	// written again by a knock, whatever its end.
	g.regrant = map[grantKey]bool{udp: true}
	if err := knock(0x11, 20*time.Minute); err != nil || tx() != before+3 || g.regrant[udp] {
		t.Fatalf("a knock on a grant to set again: %d transactions, %v", tx()-before, err)
	}
}

// TestGrantTTLFloor: TTLs of 0 on the node give grants of a second, never
// an element without a timeout, which revocation could not close (fourth
// review: -spa-max-ttl 0).
func TestGrantTTLFloor(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}})
	snap.Spa.DefaultTtlS, snap.Spa.MaxTtlS = 0, 0
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddr("198.51.100.9")
	if _, err := g.Handle(src, netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatal(err)
	}
	if d, ok := fw.ttl(grantKey{src, Port{"tcp", 443}}); !ok || d != time.Second {
		t.Fatalf("a grant for %v (open %v)", d, ok)
	}
}

// TestKnownSourceMany: twenty devices behind one address (an office NAT)
// all renew through a flood: each tried is a check of the known sources'
// budget, up to knownTry (fourth review: eight tried at random, and a
// device of twenty failed three renewals in five).
func TestKnownSourceMany(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot()
	for i := range 20 {
		snap.Devices = append(snap.Devices, &perimeterv1.Device{Id: string(rune('a' + i)), Key: key(byte(0x40 + i)), Allowed: []uint32{1}})
	}
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	office := netip.MustParseAddr("198.51.100.20")
	for i := range 20 {
		if _, err := g.Handle(office, netip.Addr{}, seal(t, snap, byte(0x40+i), now)); err != nil {
			t.Fatalf("device %d: %v", i, err)
		}
	}
	junk := make([]byte, 120)
	flood := func() {
		for i := range int(g.budgetRate) + 10 {
			g.Handle(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), netip.Addr{}, junk)
		}
		if _, err := g.Handle(netip.MustParseAddr("203.0.113.1"), netip.Addr{}, seal(t, snap, 0x40, now)); !errors.Is(err, ErrFlood) {
			t.Fatalf("not flooded: %v", err)
		}
	}
	for round := range 5 {
		for i := range 20 {
			if i%knownSourceRate == 0 {
				now = now.Add(time.Second) // the source's own 8 a second
				flood()
			}
			if _, err := g.Handle(office, netip.Addr{}, seal(t, snap, byte(0x40+i), now)); err != nil {
				t.Fatalf("round %d, device %d through the flood: %v", round, i, err)
			}
		}
	}
}

// TestFlushBackoff: closings an eviction asks for that the firewall
// refuses are tried again less and less often (1 s doubling to 30 s), not
// every tick (fourth review: some 20 ms an address a second, unsaid).
func TestFlushBackoff(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}})
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}) }
	for i := range DeviceAddrs {
		if _, err := g.Handle(addr(i), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	fw.denyFails = 1000
	denies := fw.denies
	if _, err := g.Handle(addr(DeviceAddrs), netip.Addr{}, seal(t, snap, 0x11, now)); err != nil {
		t.Fatal(err)
	}
	if fw.denies != denies+1 || !fw.isOpen(addr(0).String()+" tcp/443") {
		t.Fatalf("the eviction: %d tries, open %v", fw.denies-denies, fw.isOpen(addr(0).String()+" tcp/443"))
	}
	// Ticks a quarter of a second apart for 20 s: tries at 1, 3, 7, 15 s.
	for range 80 {
		now = now.Add(250 * time.Millisecond)
		if _, err := g.Tick(); err != nil {
			t.Fatal(err)
		}
	}
	if n := fw.denies - denies; n != 5 {
		t.Fatalf("%d tries in 20 s, want 5", n)
	}
	fw.denyFails = 0
	for range 64 {
		now = now.Add(250 * time.Millisecond)
		g.Tick()
	}
	if fw.isOpen(addr(0).String()+" tcp/443") || len(g.revoking) != 0 {
		t.Fatal("the eviction never closed the grant")
	}
}
