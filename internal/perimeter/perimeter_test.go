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
	rot        map[uint16]uint16
	open       map[string]time.Duration // "addr port" -> ttl
	gone       bool                     // table removed behind the gate's back
	setups     int
}

func (f *fakeFW) Setup() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setups++
	f.gone = false
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
}
func (f *fakeFW) Teardown() error { return nil }
func (f *fakeFW) SetSPAPorts(udp, tcp []uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.udp, f.tcp = udp, tcp
	return nil
}
func (f *fakeFW) SetPublic(p []Port) error { f.public = p; return nil }
func (f *fakeFW) SetRotation(udp map[uint16]uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rot = udp
	return nil
}
func (f *fakeFW) SetAdmin(p []netip.Prefix, ports []Port) error {
	f.admin, f.adminPorts = p, ports
	return nil
}
func (f *fakeFW) Allow(a netip.Addr, ports []Port, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.open == nil {
		f.open = map[string]time.Duration{}
	}
	for _, p := range ports {
		f.open[a.String()+" "+p.String()] = ttl
	}
	return nil
}
func (f *fakeFW) Deny(a netip.Addr, ports []Port) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	if fw.setups != 1 || len(fw.public) != 1 || len(fw.admin) != 1 || len(fw.adminPorts) != 1 {
		t.Fatalf("setups=%d public=%v admin=%v %v", fw.setups, fw.public, fw.admin, fw.adminPorts)
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
