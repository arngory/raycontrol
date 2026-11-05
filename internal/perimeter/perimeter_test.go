package perimeter

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/spa"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeFW struct {
	mu         sync.Mutex
	udp, tcp   []uint16
	public     []Port
	admin      []netip.Prefix
	adminPorts []Port
	relays     []netip.Prefix
	relayPorts []Port
	forward    []Port
	rot        map[uint16]uint16
	open       map[string]time.Duration // "addr port" -> ttl
	gone       bool                     // table removed behind the gate's back
	setups     int
	acmePort   uint16
	acmeTTL    time.Duration
	relaysSets int            // SetRelays calls
	adminFails int            // SetAdmin calls still to fail
	spaFails   int            // SetSPAPorts calls still to fail
	denyFails  int            // Deny calls still to fail
	allowFails int            // Allow calls still to fail
	allowCall  int            // Allow calls so far
	failAllow  int            // the Allow call that fails (1-based), 0: none
	denies     int            // Deny calls
	failing    map[string]int // SetPublic, SetRelays, SetForward, SetACME calls still to fail
	calls      []string       // Setup, SetAdmin, SetRelays, Allow, SetSPAPorts, in order
}

func (f *fakeFW) SetACME(port uint16, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails("SetACME") {
		return errors.New("nft: busy")
	}
	f.acmePort, f.acmeTTL = port, ttl
	return nil
}

func (f *fakeFW) Setup() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails("Setup") {
		return errors.New("nft: busy")
	}
	f.setups++
	f.gone = false
	f.calls = append(f.calls, "Setup")
	// A new table: nothing of the old one, grants included.
	f.udp, f.tcp, f.public, f.admin, f.adminPorts, f.rot, f.open = nil, nil, nil, nil, nil, nil, nil
	f.relays, f.relayPorts, f.forward = nil, nil, nil
	return nil
}
func (f *fakeFW) Present() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.gone, nil
}

// flush mimics "nft flush ruleset".
func (f *fakeFW) flush() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gone = true
	f.udp, f.tcp, f.public, f.admin, f.adminPorts, f.rot, f.open = nil, nil, nil, nil, nil, nil, nil
	f.relays, f.relayPorts, f.forward = nil, nil, nil
	f.acmePort, f.acmeTTL = 0, 0
}
func (f *fakeFW) Teardown() error { return nil }
func (f *fakeFW) SetSPAPorts(udp, tcp []uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "SetSPAPorts")
	if f.spaFails > 0 {
		f.spaFails--
		return errors.New("nft: busy")
	}
	f.udp, f.tcp = udp, tcp
	return nil
}
func (f *fakeFW) fails(name string) bool {
	if f.failing[name] > 0 {
		f.failing[name]--
		return true
	}
	return false
}
func (f *fakeFW) SetPublic(p []Port) error {
	if f.fails("SetPublic") {
		return errors.New("nft: no such port")
	}
	f.public = p
	return nil
}
func (f *fakeFW) SetRotation(udp map[uint16]uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rot = udp
	return nil
}
func (f *fakeFW) SetAdmin(p []netip.Prefix, ports []Port) error {
	f.calls = append(f.calls, "SetAdmin")
	if f.adminFails > 0 {
		f.adminFails--
		return errors.New("nft: busy")
	}
	f.admin, f.adminPorts = p, ports
	return nil
}
func (f *fakeFW) SetForward(ports []Port) error {
	if f.fails("SetForward") {
		return errors.New("nft: busy")
	}
	f.forward = ports
	return nil
}
func (f *fakeFW) SetRelays(p []netip.Prefix, ports []Port) error {
	if f.fails("SetRelays") {
		return errors.New("nft: busy")
	}
	f.relays, f.relayPorts = p, ports
	f.relaysSets++
	f.calls = append(f.calls, "SetRelays")
	return nil
}
func (f *fakeFW) Allow(a netip.Addr, ports []Port, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowCall++
	if f.allowFails > 0 || f.allowCall == f.failAllow {
		if f.allowFails > 0 {
			f.allowFails--
		}
		return errors.New("nft: busy")
	}
	if f.open == nil {
		f.open = map[string]time.Duration{}
	}
	for _, p := range ports {
		f.open[a.String()+" "+p.String()] = ttl
	}
	f.calls = append(f.calls, "Allow")
	return nil
}
func (f *fakeFW) Deny(a netip.Addr, ports []Port) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denies++
	if f.denyFails > 0 {
		f.denyFails--
		return errors.New("nft: busy")
	}
	for _, p := range ports {
		delete(f.open, a.String()+" "+p.String())
	}
	return nil
}
func (f *fakeFW) isOpen(k string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.open[k]
	return ok
}

func key(b byte) []byte { return slices.Repeat([]byte{b}, spa.KeySize) }

func testSnapshot(devices ...*perimeterv1.Device) *perimeterv1.Snapshot {
	return &perimeterv1.Snapshot{
		Spa: &perimeterv1.SPAParams{
			NodeId: slices.Repeat([]byte{0x33}, 16), EpochLenS: 86400, SlotLenS: 600,
			PortKey: key(0x44), PortBase: 40000, PortRange: 4096, LenMin: 96, LenMax: 160,
			DefaultTtlS: 600, MaxTtlS: 3600, TcpCarrier: true,
		},
		Devices: devices,
		Services: []*perimeterv1.Service{
			{Id: 1, Ports: []*perimeterv1.Port{{Proto: "tcp", Port: 443}}},
			{Id: 2, Ports: []*perimeterv1.Port{{Proto: "udp", Port: 443}, {Proto: "tcp", Port: 443}}},
			{Id: 3, Ports: []*perimeterv1.Port{{Proto: "tcp", Port: 22}}},
		},
		PublicPorts: []*perimeterv1.Port{{Proto: "udp", Port: 53}},
	}
}

func seal(t *testing.T, snap *perimeterv1.Snapshot, k byte, now time.Time, scope ...uint16) []byte {
	t.Helper()
	p, err := paramsOf(snap.Spa)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := spa.SealRandom(p, [spa.KeySize]byte(key(k)), spa.Request{Time: now, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func TestGate(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }

	if _, err := g.Handle(netip.MustParseAddr("192.0.2.1"), []byte("x")); !errors.Is(err, ErrNotReady) {
		t.Fatalf("before snapshot: %v", err)
	}

	alice := &perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1, 2}}
	bob := &perimeterv1.Device{Id: "bob", Key: key(0x12), Allowed: []uint32{1}}
	snap := testSnapshot(alice, bob)
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if len(fw.public) != 1 || fw.public[0] != (Port{"udp", 53}) {
		t.Fatalf("public = %v", fw.public)
	}
	if len(fw.udp) == 0 || !slices.Equal(fw.udp, fw.tcp) {
		t.Fatalf("spa ports udp=%v tcp=%v", fw.udp, fw.tcp)
	}

	nat := netip.MustParseAddr("203.0.113.9")
	if _, err := g.Handle(nat, seal(t, snap, 0x11, now, 2, 3)); err != nil {
		t.Fatal(err)
	}
	if !fw.isOpen("203.0.113.9 udp/443") || !fw.isOpen("203.0.113.9 tcp/443") || fw.isOpen("203.0.113.9 tcp/22") {
		t.Fatalf("after alice: %v", fw.open)
	}
	// Bob behind the same NAT also holds tcp/443.
	if _, err := g.Handle(nat, seal(t, snap, 0x12, now)); err != nil {
		t.Fatal(err)
	}

	// Alice loses service 2: udp/443 closes, tcp/443 stays for Bob.
	alice.Allowed = []uint32{1}
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if fw.isOpen("203.0.113.9 udp/443") || !fw.isOpen("203.0.113.9 tcp/443") {
		t.Fatalf("after alice lost service 2: %v", fw.open)
	}
	// Bob is revoked as well: now nobody holds tcp/443.
	snap.Devices = []*perimeterv1.Device{alice}
	alice.Allowed = nil
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if fw.isOpen("203.0.113.9 tcp/443") {
		t.Fatalf("after revocation: %v", fw.open)
	}

	// Slots move with time.
	before := slices.Clone(fw.udp)
	now = now.Add(time.Hour)
	if _, err := g.Tick(); err != nil {
		t.Fatal(err)
	}
	if slices.Equal(before, fw.udp) {
		t.Fatal("spa ports did not move after an hour")
	}
}

func TestGateForgetsExpired(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	alice := &perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}}
	snap := testSnapshot(alice)
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Handle(netip.MustParseAddr("192.0.2.7"), seal(t, snap, 0x11, now)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if _, err := g.Tick(); err != nil {
		t.Fatal(err)
	}
	if len(g.holders) != 0 {
		t.Fatalf("expired holders kept: %v", g.holders)
	}
}

func TestGateRestoresTable(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	alice := &perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{2}}
	snap := testSnapshot(alice)
	snap.AdminPrefixes = []string{"198.51.100.0/24"}
	snap.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 22}}
	snap.RelayPrefixes = []string{"192.0.2.44/32", "2001:db8::44/128"}
	snap.RelayPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 443}, {Proto: "udp", Port: 443}}
	snap.Services[1].Rotation = &perimeterv1.Rotation{PortKey: key(0x55), PortBase: 20000, PortRange: 1000, TargetPort: 443}
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Handle(netip.MustParseAddr("203.0.113.9"), seal(t, snap, 0x11, now)); err != nil {
		t.Fatal(err)
	}

	fw.flush()
	now = now.Add(2 * time.Minute)
	if _, err := g.Tick(); err != nil {
		t.Fatal(err)
	}
	if fw.setups != 1 || len(fw.public) != 1 || len(fw.admin) != 1 || len(fw.adminPorts) != 1 || len(fw.relays) != 2 || len(fw.relayPorts) != 2 {
		t.Fatalf("setups=%d public=%v admin=%v %v relays=%v %v", fw.setups, fw.public, fw.admin, fw.adminPorts, fw.relays, fw.relayPorts)
	}
	if len(fw.udp) == 0 || len(fw.tcp) == 0 || len(fw.rot) == 0 {
		t.Fatalf("slots not restored: udp=%v tcp=%v rot=%v", fw.udp, fw.tcp, fw.rot)
	}
	if ttl, ok := fw.open["203.0.113.9 udp/443"]; !ok || ttl != 8*time.Minute {
		t.Fatalf("grant not restored with its remaining time: %v", fw.open)
	}

	// Nothing to restore while the table is there.
	if _, err := g.Tick(); err != nil || fw.setups != 1 {
		t.Fatalf("setups=%d err=%v", fw.setups, err)
	}

	// A restore that fails halfway leaves a table, and is tried again, a
	// second later (then less and less often).
	fw.flush()
	fw.adminFails = 1
	if _, err := g.Tick(); err == nil {
		t.Fatal("a failed restore said nothing")
	}
	if ok, _ := fw.Present(); !ok || len(fw.relays) != 0 {
		t.Fatalf("after a failed restore: present %v, relays %v", ok, fw.relays)
	}
	if _, err := g.Tick(); !errors.Is(err, ErrNotReady) || fw.setups != 2 {
		t.Fatalf("tried again at once: setups=%d %v", fw.setups, err)
	}
	now = now.Add(time.Second)
	fw.calls = nil
	if _, err := g.Tick(); err != nil || fw.setups != 3 || len(fw.admin) != 1 || len(fw.relays) != 2 {
		t.Fatalf("restore again: setups=%d admin=%v relays=%v %v", fw.setups, fw.admin, fw.relays, err)
	}
	// relay_check last, with the grants back.
	if a, r := slices.Index(fw.calls, "Allow"), slices.Index(fw.calls, "SetRelays"); a < 0 || r < a {
		t.Fatalf("restore order %v", fw.calls)
	}
	if _, err := g.Tick(); err != nil || fw.setups != 3 {
		t.Fatalf("restored once: setups=%d %v", fw.setups, err)
	}
	// Not done before the slots are back either.
	fw.flush()
	fw.spaFails = 1
	if _, err := g.Tick(); err == nil {
		t.Fatal("a restore failing at the slots said nothing")
	}
	now = now.Add(time.Second)
	if _, err := g.Tick(); err != nil || fw.setups != 5 || len(fw.udp) == 0 {
		t.Fatalf("restore again after the slots: setups=%d udp=%v %v", fw.setups, fw.udp, err)
	}
}

// A snapshot the firewall took only in part is applied in full by Tick,
// without waiting for rayd to send another; one that comes while the
// table is being restored waits for the restore.
func TestGatePendingSnapshot(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{2}})
	snap.AdminPrefixes = []string{"198.51.100.0/24"}
	snap.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 22}}
	fw.adminFails = 1
	if err := g.Update(snap); !errors.Is(err, ErrPending) || len(fw.admin) != 0 {
		t.Fatalf("a failed update: admin %v, %v", fw.admin, err)
	}
	now = now.Add(time.Second)
	if _, err := g.Tick(); err != nil || len(fw.admin) != 1 || fw.relaysSets != 1 || g.pending != nil {
		t.Fatalf("pending snapshot: admin %v, SetRelays %d, pending %v, %v", fw.admin, fw.relaysSets, g.pending != nil, err)
	}

	// A snapshot that keeps failing: the slots move on all the same, and
	// the tries come less and less often.
	fw.adminFails = 1000
	snap.AdminPrefixes = []string{"198.51.100.0/25"}
	if err := g.Update(snap); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	slots := slices.Clone(fw.udp)
	tries := fw.adminFails
	for range 3 {
		now = now.Add(10 * time.Minute) // a slot
		ports, err := g.Tick()
		if ports == nil || err == nil || slices.Equal(fw.udp, slots) {
			t.Fatalf("slots stuck behind a failing snapshot: %v -> %v, ports %v, %v", slots, fw.udp, ports, err)
		}
		slots = slices.Clone(fw.udp)
	}
	if tries-fw.adminFails != 3 {
		t.Fatalf("%d tries in 3 ticks", tries-fw.adminFails)
	}
	for range 5 {
		now = now.Add(time.Second)
		g.Tick()
	}
	if tries-fw.adminFails > 6 || g.retryAt.Sub(now) < 2*time.Second {
		t.Fatalf("no backoff: %d tries, next in %v", tries-fw.adminFails, g.retryAt.Sub(now))
	}
	// A snapshot that goes through ends the backoff.
	fw.adminFails = 0
	if err := g.Update(snap); err != nil || g.failures != 0 || !g.retryAt.IsZero() {
		t.Fatalf("after a good update: failures %d, retry at %v, %v", g.failures, g.retryAt, err)
	}

	fw.flush()
	fw.adminFails = 1
	if _, err := g.Tick(); err == nil {
		t.Fatal("a failed restore said nothing")
	}
	snap.RelayPrefixes = []string{"192.0.2.44/32"}
	snap.RelayPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 443}}
	fw.calls = nil
	if err := g.Update(snap); err != nil || len(fw.relays) != 1 {
		t.Fatalf("update while restoring: relays %v, %v", fw.relays, err)
	}
	if len(fw.calls) == 0 || fw.calls[0] != "Setup" {
		t.Fatalf("an update wrote into a half-made table: %v", fw.calls)
	}
}

// Admin prefixes inside others go: an interval set refuses overlaps.
func TestMergePrefixes(t *testing.T) {
	var in []netip.Prefix
	for _, s := range []string{"198.51.100.7/32", "198.51.100.0/24", "2001:db8:1::/48", "198.51.100.9/24", "203.0.113.5/32", "2001:db8:1:2::/64"} {
		in = append(in, netip.MustParsePrefix(s))
	}
	got := mergePrefixes(in)
	want := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.5/32"), netip.MustParsePrefix("2001:db8:1::/48")}
	if !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
}

// relay_check goes on with the first snapshot, relays or none: it ends the
// flows of relays removed while rayspa was down.
func TestGateRelaysOnce(t *testing.T) {
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{2}})
	for range 2 {
		if err := g.Update(snap); err != nil {
			t.Fatal(err)
		}
	}
	if fw.relaysSets != 1 {
		t.Fatalf("SetRelays %d times", fw.relaysSets)
	}
}

func TestGateACME(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot()
	snap.Acme = &perimeterv1.AcmeWindow{Port: 18080, Until: now.Add(90 * time.Second).Unix()}
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if fw.acmePort != 18080 || fw.acmeTTL != 90*time.Second {
		t.Fatalf("window %d %v", fw.acmePort, fw.acmeTTL)
	}
	// Restored with the table, with the time it has left.
	fw.flush()
	now = now.Add(30 * time.Second)
	if _, err := g.Tick(); err != nil {
		t.Fatal(err)
	}
	if fw.acmePort != 18080 || fw.acmeTTL != 60*time.Second {
		t.Fatalf("restored window %d %v", fw.acmePort, fw.acmeTTL)
	}
	snap.Acme = nil
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if fw.acmePort != 0 {
		t.Fatalf("window still open: %d", fw.acmePort)
	}
	// A window that already ended is not opened.
	snap.Acme = &perimeterv1.AcmeWindow{Port: 18080, Until: now.Add(-time.Second).Unix()}
	if err := g.Update(snap); err != nil || fw.acmePort != 0 {
		t.Fatalf("past window: %d %v", fw.acmePort, err)
	}
}

func udpPacket(src netip.Addr, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	if src.Is4() {
		ip := make([]byte, 20)
		ip[0], ip[9] = 0x45, 17
		a := src.As4()
		copy(ip[12:16], a[:])
		return append(ip, udp...)
	}
	ip := make([]byte, 40)
	ip[0], ip[6] = 0x60, 17
	a := src.As16()
	copy(ip[8:24], a[:])
	return append(ip, udp...)
}

func TestParseUDP(t *testing.T) {
	for _, s := range []string{"198.51.100.4", "2001:db8::7"} {
		src := netip.MustParseAddr(s)
		got, payload, ok := parseUDP(udpPacket(src, []byte("hello")))
		if !ok || got != src || string(payload) != "hello" {
			t.Fatalf("%s: %v %q %v", s, got, payload, ok)
		}
	}
	tcp := udpPacket(netip.MustParseAddr("198.51.100.4"), []byte("x"))
	tcp[9] = 6
	for _, bad := range [][]byte{nil, {0x45}, tcp, udpPacket(netip.MustParseAddr("198.51.100.4"), nil)[:25]} {
		if _, _, ok := parseUDP(bad); ok {
			t.Fatalf("accepted %x", bad)
		}
	}
}

func TestTCPCarrier(t *testing.T) {
	got := make(chan []byte, 4)
	c := &TCPCarrier{
		Handler:     func(_ netip.Addr, pkt []byte) { got <- pkt },
		LenMax:      func() int { return 160 },
		Log:         quiet,
		ReadTimeout: time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	c.Reconcile([]uint16{port})
	defer c.Close()

	send := func(data []byte) {
		conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(port)))
		if err != nil {
			t.Fatal(err)
		}
		// Split writes, as a client fighting DPI may do.
		conn.Write(data[:10])
		conn.Write(data[10:])
		conn.Close()
	}
	pkt := slices.Repeat([]byte{7}, 120)
	send(pkt)
	select {
	case p := <-got:
		if !slices.Equal(p, pkt) {
			t.Fatalf("got %d bytes", len(p))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no packet")
	}
	send(slices.Repeat([]byte{7}, 300))
	select {
	case p := <-got:
		if len(p) != 161 {
			t.Fatalf("oversized read %d bytes, want 161 (limit+1)", len(p))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no oversized packet")
	}

	// A ClientHello carrier is read by its record length and handled at
	// once, while the client waits for an answer like a browser would.
	hello, err := spa.TLSCarrier(pkt)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(port)))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(hello[:7])
	conn.Write(hello[7:])
	select {
	case p := <-got:
		if !slices.Equal(p, pkt) {
			t.Fatalf("ClientHello carrier: got %d bytes", len(p))
		}
	case <-time.After(c.ReadTimeout / 2):
		t.Fatal("ClientHello carrier waited for the client to close")
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("connection after a ClientHello carrier: %v, want a reset", err)
	}
	conn.Close()
	// A record longer than the carrier bound is not read.
	conn, err = net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(port)))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte{0x16, 0x03, 0x01, 0xff, 0xff})
	conn.SetReadDeadline(time.Now().Add(c.ReadTimeout / 2))
	if _, err := conn.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("oversized record: %v, want a reset", err)
	}
	conn.Close()

	c.Reconcile(nil)
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), time.Second); err == nil {
		conn.Close()
		t.Fatal("listener still open after reconcile")
	}
}

func TestRuleset(t *testing.T) {
	rs := (&NFT{NflogGroup: 9, RateLimit: 5}).Ruleset()
	for _, want := range []string{"policy drop", "log group 9", "limit rate over 5/second", `iif "lo" accept`, "@allow6"} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
	if strings.Contains((&NFT{FilterLoopback: true}).Ruleset(), `iif "lo" accept`) {
		t.Error("loopback accepted in test mode")
	}
	set, elems := elements(netip.MustParseAddr("::ffff:192.0.2.1"), []Port{{"tcp", 443}}, 10*time.Minute)
	if set != "allow4" || elems != "192.0.2.1 . tcp . 443 timeout 600s" {
		t.Errorf("mapped v4: %s %s", set, elems)
	}
	set, _ = elements(netip.MustParseAddr("2001:db8::1"), []Port{{"udp", 443}}, 0)
	if set != "allow6" {
		t.Errorf("v6 set %s", set)
	}
}

// A relay is one address (relay-v1 §3): a wider prefix in the snapshot is
// refused, so a mistake cannot open the services to a network.
func TestGateRelayOneAddress(t *testing.T) {
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	snap := testSnapshot()
	snap.RelayPrefixes = []string{"192.0.2.0/24"}
	if err := g.Update(snap); err == nil || len(fw.relays) != 0 {
		t.Fatalf("relay network accepted: %v %v", err, fw.relays)
	}
}

// On a relay, its own SSH is a local service (relay-v1 §3.1): in the scope
// of the devices allowed SSH, never forwarded to the exit.
func TestGateLocalNotForwarded(t *testing.T) {
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	snap := testSnapshot()
	snap.Services[2].Local = true // tcp/22
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(fw.forward, Port{"tcp", 22}) || !slices.Contains(fw.forward, Port{"tcp", 443}) {
		t.Fatalf("forward %v", fw.forward)
	}
}

// A revocation the firewall refuses is tried again; one that comes while a
// restore keeps failing is not opened again by the restore.
func TestGateRevocations(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	alice := &perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{2}}
	snap := testSnapshot(alice)
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	knock := func() {
		t.Helper()
		if _, err := g.Handle(netip.MustParseAddr("203.0.113.9"), seal(t, snap, 0x11, now)); err != nil {
			t.Fatal(err)
		}
	}
	const grant = "203.0.113.9 udp/443"
	knock()
	alice.Allowed = nil
	fw.denyFails = 2 // both of alice's ports
	if err := g.Update(snap); !errors.Is(err, ErrPending) || !fw.isOpen(grant) {
		t.Fatalf("a refused revocation: open %v, %v", fw.isOpen(grant), err)
	}
	now = now.Add(time.Second)
	if _, err := g.Tick(); err != nil || fw.isOpen(grant) || len(g.revoking) != 0 {
		t.Fatalf("revocation tried again: open %v, %v", fw.isOpen(grant), err)
	}

	alice.Allowed = []uint32{2}
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	knock()
	fw.flush()
	fw.spaFails = 2 // the restore fails at the slots, after the grants, twice
	now = now.Add(time.Second)
	if _, err := g.Tick(); err == nil || !fw.isOpen(grant) {
		t.Fatalf("a failed restore: open %v, %v", fw.isOpen(grant), err)
	}
	alice.Allowed = nil
	if err := g.Update(snap); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	if fw.isOpen(grant) {
		t.Fatal("a restore opened again what the snapshot revokes")
	}

	// A grant still waiting to be closed, then held again by a new knock:
	// it stays open.
	now = now.Add(time.Minute)
	if _, err := g.Tick(); err != nil {
		t.Fatal(err)
	}
	alice.Allowed = []uint32{2}
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	knock()
	alice.Allowed = nil
	fw.denyFails = 1000
	if err := g.Update(snap); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	alice.Allowed = []uint32{2}
	if err := g.Update(snap); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	knock()
	fw.denyFails = 0
	now = now.Add(time.Minute)
	if _, err := g.Tick(); err != nil || !fw.isOpen(grant) {
		t.Fatalf("a grant held again was closed: %v", err)
	}
}

// One part the firewall keeps refusing does not hold back the others, and
// what it refused is applied when it takes it; admin prefixes come merged
// and unmapped.
func TestGatePartsApart(t *testing.T) {
	now := time.Unix(1767225600, 0)
	snap := func() *perimeterv1.Snapshot {
		s := testSnapshot()
		s.AdminPrefixes = []string{"198.51.100.7/32", "198.51.100.0/24", "::ffff:203.0.113.0/120"}
		s.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 22}}
		s.RelayPrefixes = []string{"192.0.2.44/32"}
		s.RelayPorts = []*perimeterv1.Port{{Proto: "udp", Port: 8443}}
		s.Acme = &perimeterv1.AcmeWindow{Port: 18080, Until: now.Add(time.Minute).Unix()}
		return s
	}
	admin := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
	applied := func(fw *fakeFW) map[string]bool {
		return map[string]bool{
			"SetPublic": len(fw.public) == 1, "SetRelays": len(fw.relays) == 1, "SetForward": len(fw.forward) > 0,
			"SetACME": fw.acmePort == 18080, "SetAdmin": slices.Equal(fw.admin, admin), "slots": len(fw.udp) > 0,
		}
	}
	for _, part := range []string{"SetPublic", "SetRelays", "SetForward", "SetACME"} {
		fw := &fakeFW{failing: map[string]int{part: 1}}
		g := NewGate(fw, quiet)
		g.now = func() time.Time { return now }
		if err := g.Update(snap()); !errors.Is(err, ErrPending) {
			t.Fatalf("%s refused: %v", part, err)
		}
		for name, ok := range applied(fw) {
			if ok == (name == part) {
				t.Errorf("%s refused: %s applied %v", part, name, ok)
			}
		}
		now = now.Add(time.Second)
		if _, err := g.Tick(); err != nil {
			t.Fatal(err)
		}
		for name, ok := range applied(fw) {
			if !ok {
				t.Errorf("%s refused, then taken: %s not applied", part, name)
			}
		}
	}
}

// A relay port that becomes public waits for the public ports: meanwhile
// relay_check would cut its flows.
func TestGateRelayPortBecomesPublic(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	s := testSnapshot()
	s.RelayPrefixes = []string{"192.0.2.44/32"}
	s.RelayPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 443}}
	if err := g.Update(s); err != nil {
		t.Fatal(err)
	}
	s.RelayPorts = nil
	s.PublicPorts = append(s.PublicPorts, &perimeterv1.Port{Proto: "tcp", Port: 443})
	fw.failing = map[string]int{"SetPublic": 1}
	if err := g.Update(s); !errors.Is(err, ErrPending) || len(fw.relayPorts) != 1 {
		t.Fatalf("relay ports went before the public ones: %v %v", fw.relayPorts, err)
	}
	now = now.Add(time.Second)
	if _, err := g.Tick(); err != nil || len(fw.relayPorts) != 0 || len(fw.public) != 2 {
		t.Fatalf("then: relay %v public %v %v", fw.relayPorts, fw.public, err)
	}
}

// Devices behind one address (CGNAT) share its grants: a grant lasts as
// long as its longest holder, and a revoked holder's time goes with it.
func TestGateSharedAddress(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	alice := &perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{2}}
	bob := &perimeterv1.Device{Id: "bob", Key: key(0x22), Allowed: []uint32{2}}
	snap := testSnapshot(alice, bob)
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	p, _ := paramsOf(snap.Spa)
	knock := func(k byte, ttl time.Duration) {
		t.Helper()
		pkt, err := spa.SealRandom(p, [spa.KeySize]byte(key(k)), spa.Request{Time: now, TTL: ttl})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Handle(netip.MustParseAddr("203.0.113.9"), pkt); err != nil {
			t.Fatal(err)
		}
	}
	const grant = "203.0.113.9 udp/443"
	ttl := func() time.Duration { fw.mu.Lock(); defer fw.mu.Unlock(); return fw.open[grant] }
	knock(0x11, time.Hour)
	knock(0x22, 5*time.Minute)
	if ttl() != time.Hour {
		t.Fatalf("a shorter knock cut the grant to %v", ttl())
	}
	alice.Allowed = nil
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if ttl() != 5*time.Minute {
		t.Fatalf("alice revoked, the grant still lasts %v", ttl())
	}
}

// The TCP carrier off: no ports, said as an empty list, so that the
// listeners close.
func TestGateCarrierOff(t *testing.T) {
	g := NewGate(&fakeFW{}, quiet)
	snap := testSnapshot()
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if ports, err := g.Tick(); err != nil || len(ports) == 0 {
		t.Fatalf("carrier on: %v %v", ports, err)
	}
	snap.Spa.TcpCarrier = false
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if ports, err := g.Tick(); err != nil || ports == nil || len(ports) != 0 {
		t.Fatalf("carrier off: %#v %v", ports, err)
	}
}

// More of the shared address: a device's own shorter knock is its own; a
// grant to shorten whose other holders went meanwhile is closed; a grant
// open in part is held in part.
func TestGateSharedAddressMore(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	alice := &perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{2}}
	bob := &perimeterv1.Device{Id: "bob", Key: key(0x22), Allowed: []uint32{2}}
	snap := testSnapshot(alice, bob)
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	p, _ := paramsOf(snap.Spa)
	knock := func(k byte, ttl time.Duration) error {
		t.Helper()
		pkt, err := spa.SealRandom(p, [spa.KeySize]byte(key(k)), spa.Request{Time: now, TTL: ttl})
		if err != nil {
			t.Fatal(err)
		}
		_, err = g.Handle(netip.MustParseAddr("203.0.113.9"), pkt)
		return err
	}
	const udp, tcp = "203.0.113.9 udp/443", "203.0.113.9 tcp/443"
	ttl := func(k string) (time.Duration, bool) {
		fw.mu.Lock()
		defer fw.mu.Unlock()
		d, ok := fw.open[k]
		return d, ok
	}

	// Alice's own shorter knock is hers to make.
	knock(0x11, time.Hour)
	knock(0x11, 5*time.Minute)
	if d, _ := ttl(udp); d != 5*time.Minute {
		t.Fatalf("own shorter knock: %v", d)
	}

	// Alice revoked, the shortening refused twice, bob gone meanwhile: the
	// grant is closed, not left with alice's hour.
	knock(0x11, time.Hour)
	knock(0x22, 2*time.Second)
	alice.Allowed = nil
	fw.allowFails = 4 // two ports, twice: bob expires and goes between the tries
	if err := g.Update(snap); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	for range 3 {
		now = now.Add(1500 * time.Millisecond)
		g.Tick()
	}
	now = now.Add(5 * time.Second)
	if _, err := g.Tick(); err != nil {
		t.Fatal(err)
	}
	if _, open := ttl(udp); open {
		t.Fatal("a revoked device's time stayed on the grant")
	}

	// A knock opened in part (the second Allow refused) is held in part:
	// revoking alice closes what did open.
	alice.Allowed = []uint32{2}
	bob.Allowed = []uint32{1} // tcp/443 only
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if err := knock(0x22, time.Hour); err != nil {
		t.Fatal(err)
	}
	fw.failAllow = fw.allowCall + 2
	if err := knock(0x11, 5*time.Minute); err == nil {
		t.Fatal("a knock opened in part said nothing")
	}
	alice.Allowed = nil
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if _, open := ttl(udp); open {
		t.Fatalf("a port opened for a revoked device stays open: %v", fw.open)
	}
	if d, _ := ttl(tcp); d != time.Hour {
		t.Fatalf("bob's grant: %v", d)
	}
}

// A grant that expired by itself is not closed again: on a full set, that
// alone could fail.
func TestGateExpiredNotDenied(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{2}})
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Handle(netip.MustParseAddr("203.0.113.9"), seal(t, snap, 0x11, now)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := g.Update(snap); err != nil || fw.denies != 0 {
		t.Fatalf("Deny %d times for what expired: %v", fw.denies, err)
	}
}

// Revocations reach a half-made table even while Setup keeps failing, and
// a relay removed goes even while its port becoming public waits.
func TestGateRevokeWhileRestoring(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	alice := &perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{2}}
	snap := testSnapshot(alice)
	snap.AdminPrefixes = []string{"198.51.100.0/24"}
	snap.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 22}}
	snap.RelayPrefixes = []string{"192.0.2.44/32"}
	snap.RelayPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 443}}
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	fw.flush()
	fw.adminFails = 1
	now = now.Add(time.Second)
	if _, err := g.Tick(); err == nil {
		t.Fatal("a failed restore said nothing")
	}
	if _, err := g.Handle(netip.MustParseAddr("203.0.113.9"), seal(t, snap, 0x11, now)); err != nil {
		t.Fatal(err)
	}
	fw.failing = map[string]int{"Setup": 100}
	alice.Allowed = nil
	if err := g.Update(snap); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	if fw.isOpen("203.0.113.9 udp/443") {
		t.Fatal("a revoked grant waits for a Setup that keeps failing")
	}

	// Shortened too: bob's 10 s, not alice's hour, while Setup keeps failing.
	fw.failing = nil
	fw.flush()
	fw.adminFails = 1
	alice.Allowed = []uint32{2}
	bob := &perimeterv1.Device{Id: "bob", Key: key(0x22), Allowed: []uint32{2}}
	snap.Devices = append(snap.Devices, bob)
	now = now.Add(time.Second)
	if err := g.Update(snap); err == nil {
		t.Fatal("a failed restore said nothing")
	}
	p, _ := paramsOf(snap.Spa)
	for k, ttl := range map[byte]time.Duration{0x11: time.Hour, 0x22: 10 * time.Second} {
		pkt, _ := spa.SealRandom(p, [spa.KeySize]byte(key(k)), spa.Request{Time: now, TTL: ttl})
		if _, err := g.Handle(netip.MustParseAddr("203.0.113.9"), pkt); err != nil {
			t.Fatal(err)
		}
	}
	fw.failing = map[string]int{"Setup": 100}
	alice.Allowed = nil
	if err := g.Update(snap); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	fw.mu.Lock()
	ttl := fw.open["203.0.113.9 udp/443"]
	fw.mu.Unlock()
	if ttl > 10*time.Second {
		t.Fatalf("a revoked holder's time stays while Setup fails: %v", ttl)
	}

	fw = &fakeFW{}
	g = NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	snap = testSnapshot()
	snap.RelayPrefixes = []string{"192.0.2.44/32"}
	snap.RelayPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 443}}
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	snap.RelayPrefixes, snap.RelayPorts = nil, nil
	snap.PublicPorts = append(snap.PublicPorts, &perimeterv1.Port{Proto: "tcp", Port: 443})
	fw.failing = map[string]int{"SetPublic": 100}
	if err := g.Update(snap); !errors.Is(err, ErrPending) || len(fw.relays) != 0 || len(fw.relayPorts) != 1 {
		t.Fatalf("a relay removed while its port waits: relays %v ports %v %v", fw.relays, fw.relayPorts, err)
	}
}
