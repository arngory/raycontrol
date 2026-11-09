package perimeter

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"golang.org/x/sys/unix"
)

// guardGate is a gate with a guard on a stand-in table, a fake clock and
// the reports it made.
type guardGate struct {
	g       *Gate
	fw      *fakeFW
	now     time.Time
	count   uint64
	max     uint64
	mu      sync.Mutex
	reports []GuardState
	log     *bytes.Buffer
}

func newGuardGate(t *testing.T) *guardGate {
	t.Helper()
	gg := &guardGate{fw: &fakeFW{}, now: time.Unix(1_700_000_000, 0), max: 1000, log: &bytes.Buffer{}}
	gg.g = NewGate(gg.fw, slog.New(slog.NewTextHandler(gg.log, nil)))
	gg.g.now = func() time.Time { return gg.now }
	gg.g.EnableGuard(&Guard{
		Read: func() (uint64, uint64, error) { return gg.count, gg.max, nil },
		Report: func(st GuardState) {
			gg.mu.Lock()
			defer gg.mu.Unlock()
			gg.reports = append(gg.reports, st)
		},
	})
	if err := gg.g.Update(testSnapshot()); err != nil {
		t.Fatal(err)
	}
	return gg
}

func (gg *guardGate) tick(t *testing.T, d time.Duration) {
	t.Helper()
	gg.now = gg.now.Add(d)
	if _, err := gg.g.Tick(); err != nil {
		t.Fatal(err)
	}
}

// The guard switches on at 85 % of the stand-in max, off at 70 % but not
// before two minutes; the table follows, a restore puts it back; it
// reports each switch and once a minute; its warnings come a line in ten
// minutes at most, the next telling the switches between; switches only
// counted get their line once the ten minutes are past, with no switch
// of their own.
func TestGuardSwitches(t *testing.T) {
	gg := newGuardGate(t)
	gg.count = 849
	gg.tick(t, time.Second)
	if gg.fw.guard || gg.g.GuardOn() {
		t.Fatal("on under 85 %")
	}
	gg.count = 850
	gg.tick(t, time.Second)
	if !gg.fw.guard || !gg.g.GuardOn() {
		t.Fatal("off at 85 %")
	}
	onAt := gg.now
	// Down to 70 %: stays on for two minutes.
	gg.count = 700
	gg.tick(t, time.Minute)
	if !gg.fw.guard {
		t.Fatal("off within two minutes")
	}
	// "flush ruleset": the restore makes the chain empty, the tick puts the
	// rule back.
	gg.fw.flush()
	gg.tick(t, time.Second)
	if !gg.fw.guard {
		t.Fatal("not back after a restore")
	}
	gg.count = 701
	gg.tick(t, time.Minute)
	if !gg.fw.guard {
		t.Fatal("off above 70 %")
	}
	gg.count = 700
	gg.tick(t, time.Second)
	if gg.fw.guard || gg.g.GuardOn() {
		t.Fatal("still on at 70 % after two minutes")
	}
	gg.mu.Lock()
	reports := append([]GuardState(nil), gg.reports...)
	gg.mu.Unlock()
	last := reports[len(reports)-1]
	if last.On || last.Switches != 2 || !last.LastOn.Equal(onAt) || !last.Since.Equal(gg.now) {
		t.Fatalf("last report %+v", last)
	}
	if len(reports) < 4 { // the first tick, two switches, a minute's
		t.Fatalf("reports %d", len(reports))
	}
	// Flapping within ten minutes of the first line: the off above, this on
	// and off are not logged; the on after ten minutes says there were 3.
	gg.count = 900
	gg.tick(t, time.Second)
	gg.count = 0
	gg.tick(t, 3*time.Minute)
	gg.count = 900
	gg.tick(t, 10*time.Minute)
	out := gg.log.String()
	if n := strings.Count(out, "conntrack guard on"); n != 2 {
		t.Errorf("guard on logged %d times:\n%s", n, out)
	}
	if !strings.Contains(out, "switches_since_last_line=3") || strings.Contains(out, "conntrack guard off") {
		t.Errorf("the switches between not told:\n%s", out)
	}
	// Ten minutes on, the off line: with its numbers.
	gg.count = 650
	gg.tick(t, 11*time.Minute)
	if out := gg.log.String(); !strings.Contains(out, "conntrack guard off") || !strings.Contains(out, "was_on=11m0s") ||
		!strings.Contains(out, "entries=650") || !strings.Contains(out, "refused=") {
		t.Errorf("the off line lacks numbers:\n%s", out)
	}
	// On and off again within ten minutes of that line: only counted; the
	// first tick past the ten minutes tells the guard is off.
	gg.log.Reset()
	gg.count = 900
	gg.tick(t, time.Minute)
	gg.count = 600
	gg.tick(t, 2*time.Minute)
	gg.tick(t, time.Minute)
	if out := gg.log.String(); out != "" {
		t.Errorf("logged within ten minutes:\n%s", out)
	}
	gg.tick(t, 7*time.Minute)
	out = gg.log.String()
	if strings.Count(out, "conntrack guard off") != 1 || !strings.Contains(out, "switches_since_last_line=2") ||
		!strings.Contains(out, "was_on=2m0s") || !strings.Contains(out, "entries=600") {
		t.Errorf("the off line after the ten minutes:\n%s", out)
	}
	gg.log.Reset()
	gg.tick(t, 11*time.Minute)
	if out := gg.log.String(); out != "" {
		t.Errorf("a line with nothing new:\n%s", out)
	}
}

// As rayspa ends, the guard's refusal leaves the table: a stopped rayspa
// would never turn it off. A tick racing the exit (the snapshot watcher's)
// does not put it back.
func TestGuardRelease(t *testing.T) {
	gg := newGuardGate(t)
	gg.count = 900
	gg.tick(t, time.Second)
	if !gg.fw.guard {
		t.Fatal("not on")
	}
	if err := gg.g.ReleaseGuard(); err != nil {
		t.Fatal(err)
	}
	if gg.fw.guard {
		t.Fatal("the refusal left in the table")
	}
	gg.tick(t, time.Second)
	if gg.fw.guard {
		t.Fatal("a tick after the release put the refusal back")
	}
	// No guard (a relay): nothing.
	g := NewGate(&fakeFW{}, slog.New(slog.DiscardHandler))
	if err := g.ReleaseGuard(); err != nil {
		t.Fatal(err)
	}
}

// A switch the firewall refuses is tried again at the next tick; no table
// size (no conntrack) does nothing.
func TestGuardRetry(t *testing.T) {
	gg := newGuardGate(t)
	gg.fw.failing = map[string]int{"SetGuard": 1}
	gg.count = 950
	gg.tick(t, time.Second)
	if gg.fw.guard {
		t.Fatal("refused, yet on")
	}
	gg.tick(t, time.Second)
	if !gg.fw.guard {
		t.Fatal("not tried again")
	}
	gg.max = 0
	gg.count = 0
	gg.tick(t, 5*time.Minute)
	if !gg.fw.guard {
		t.Fatal("switched without a size")
	}
}

// The sweep runs while the table is 70 % full or more, once a minute and
// one at a time; what it removed goes into the reports.
func TestGuardSweeps(t *testing.T) {
	gg := newGuardGate(t)
	var mu sync.Mutex
	sweeps := 0
	gg.g.guard.Sweep = func(context.Context) (SweepResult, error) {
		mu.Lock()
		defer mu.Unlock()
		sweeps++
		return SweepResult{UDP: 2, TCPOut: 1, TCPIn: 1}, nil
	}
	n := func() int { mu.Lock(); defer mu.Unlock(); return sweeps }
	gg.count = 690
	gg.tick(t, time.Second)
	time.Sleep(50 * time.Millisecond)
	if n() != 0 {
		t.Fatal("swept under 70 %")
	}
	gg.count = 700
	gg.tick(t, time.Second)
	waitFor(t, func() bool { return n() == 1 })
	gg.tick(t, 30*time.Second)
	time.Sleep(50 * time.Millisecond)
	if n() != 1 {
		t.Fatal("swept twice within a minute")
	}
	gg.tick(t, 31*time.Second)
	waitFor(t, func() bool { return n() == 2 })
	waitFor(t, func() bool {
		gg.g.mu.Lock()
		defer gg.g.mu.Unlock()
		st := gg.g.guardStateLocked()
		return st.SweptUDP == 4 && st.SweptTCPOut == 2 && st.SweptTCPIn == 2
	})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(end) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The per-address limit follows the snapshot (absent: on), also after a
// restore; a gate without it never touches the table's.
func TestGateInLimit(t *testing.T) {
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	snap := testSnapshot()
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	for _, c := range fw.calls {
		if strings.HasPrefix(c, "SetInLimit") {
			t.Fatalf("on as a new table has it, yet %s", c)
		}
	}
	snap.ConnLimitOff = true
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	if !fw.inLimitOff {
		t.Fatal("not off")
	}
	fw.flush()
	if _, err := g.Tick(); err != nil {
		t.Fatal(err)
	}
	if !fw.inLimitOff {
		t.Fatal("on again after a restore")
	}
	snap.ConnLimitOff = false
	fw.failing = map[string]int{"SetInLimit": 1}
	if err := g.Update(snap); err == nil {
		t.Fatal("a refusal not told")
	}
	g.now = func() time.Time { return time.Now().Add(time.Minute) } // past the backoff
	if _, err := g.Tick(); err != nil {
		t.Fatal(err)
	}
	if fw.inLimitOff {
		t.Fatal("not tried again")
	}
}

// The scripts: the per-address limit in in_rate (and a relay's
// in_rate_fwd), the guard's one rule, notrack for the DNS ports.
func TestConnLimitScripts(t *testing.T) {
	on := InLimitScript(true, false)
	for _, want := range []string{"flush chain inet raycontrol in_rate\n", `limit rate over 50/second burst 1000 packets } counter drop comment "in-rate"`,
		"ip6 saddr & ffff:ffff:ffff:: limit rate over 800/second burst 16000", `limit rate over 20/second burst 200 packets } counter drop comment "in-rate-udp"`,
		"ip6 saddr & ffff:ffff:ffff:: limit rate over 320/second burst 3200"} {
		if !strings.Contains(on, want) {
			t.Errorf("in-limit lacks %q:\n%s", want, on)
		}
	}
	if strings.Contains(on, "in_rate_fwd") || strings.Count(InLimitScript(false, false), "\n") != 1 {
		t.Errorf("off, or not a relay:\n%s", InLimitScript(false, false))
	}
	if relay := InLimitScript(true, true); !strings.Contains(relay, `in_rate_fwd tcp flags syn update @in4`) || !strings.Contains(relay, `"relay-in-rate"`) {
		t.Errorf("relay:\n%s", relay)
	}
	if g := GuardScript(true); !strings.Contains(g, `counter name "conn_guard" reject with icmpx no-route`) || GuardScript(false) != "flush chain inet raycontrol conn_guard\n" {
		t.Errorf("guard: %q", g)
	}
	rs := (&NFT{NflogGroup: 7}).Ruleset()
	for _, want := range []string{
		`iif != "lo" udp dport @dns_ports fib daddr type local notrack`,
		`oif != "lo" udp sport @dns_ports meta skuid 9100 notrack`,
		"meta l4proto . th dport @public jump in_limit",
		"ip saddr . meta l4proto . th dport @allow4 jump in_limit",
		"ip saddr @admin4 accept\n\t\tip6 saddr @admin6 accept\n\t\tct state untracked accept\n\t\tjump in_rate",
		"meta skuid 9100-9179 ct state new ct mark set ct mark | 0x00800000",
		`oif != "lo" meta skuid @egress_uid meta skuid != 0 ct state new jump conn_guard`,
		"counter conn_guard { }",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
	relay := (&NFT{NflogGroup: 7, RelayTo: netip.MustParseAddr("192.0.2.9")}).Ruleset()
	if strings.Contains(relay, "ct mark set ct mark | 0x00800000") || !strings.Contains(relay, "@allow4 jump in_limit_fwd") {
		t.Errorf("relay ruleset:\n%s", relay)
	}
	if got := DNSPorts([]Port{{"udp", 53}, {"tcp", 443}, {"udp", 5353}, {"udp", 53}}); len(got) != 2 || got[0] != 53 || got[1] != 5353 {
		t.Errorf("DNS ports %v", got)
	}
}

// /proc/net's sockets, IPv4 and IPv6 (a mapped address is IPv4).
func TestReadSockets(t *testing.T) {
	socks := sockets{udpPorts: map[uint16]bool{}, tcpPorts: map[uint16]bool{}, tcpQuads: map[[2]netip.AddrPort]bool{}}
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:9C40 0200A8C0:0050 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0000000000000000
`
	tcp6 := `  sl  local_address                         remote_address                        st
   0: 0000000000000000FFFF00000100007F:01BB 0000000000000000FFFF00000500000A:D431 01 00000000:00000000
   1: B80D0120000000000000000001000000:1F90 B80D0120000000000000000002000000:C350 01 00000000:00000000
`
	udp := `  sl  local_address rem_address   st
  12: 00000000:B26F 00000000:0000 07 00000000:00000000
`
	if err := readSockets(strings.NewReader(tcp), true, socks); err != nil {
		t.Fatal(err)
	}
	if err := readSockets(strings.NewReader(tcp6), true, socks); err != nil {
		t.Fatal(err)
	}
	if err := readSockets(strings.NewReader(udp), false, socks); err != nil {
		t.Fatal(err)
	}
	for _, p := range []uint16{443, 40000, 8080} {
		if !socks.tcpPorts[p] {
			t.Errorf("tcp port %d missing", p)
		}
	}
	if !socks.udpPorts[45679] {
		t.Errorf("udp ports %v", socks.udpPorts)
	}
	for _, q := range [][2]string{{"127.0.0.1:40000", "192.168.0.2:80"}, {"127.0.0.1:443", "10.0.0.5:54321"}, {"[2001:db8::1]:8080", "[2001:db8::2]:50000"}} {
		if !socks.tcpQuads[[2]netip.AddrPort{netip.MustParseAddrPort(q[0]), netip.MustParseAddrPort(q[1])}] {
			t.Errorf("quad %v missing: %v", q, socks.tcpQuads)
		}
	}
	if socks.tcpQuads[[2]netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:443"), netip.MustParseAddrPort("0.0.0.0:0")}] {
		t.Error("a listener as a quad")
	}
}

// Which entries are orphans: by mark, protocol, state, socket and address;
// NATed ones never.
func TestOrphan(t *testing.T) {
	local := map[netip.Addr]bool{netip.MustParseAddr("192.0.2.10"): true, netip.MustParseAddr("127.0.0.1"): true}
	socks := sockets{udpPorts: map[uint16]bool{40001: true}, tcpPorts: map[uint16]bool{40002: true, 443: true},
		tcpQuads: map[[2]netip.AddrPort]bool{{netip.MustParseAddrPort("192.0.2.10:443"), netip.MustParseAddrPort("198.51.100.7:5000")}: true}}
	out := func(sport uint16, dst string) ctTuple {
		return ctTuple{Src: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), sport), Dst: netip.MustParseAddrPort(dst)}
	}
	in := func(src string) ctTuple {
		return ctTuple{Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort("192.0.2.10:443"), Proto: unix.IPPROTO_TCP}
	}
	udp := func(t ctTuple) ctTuple { t.Proto = unix.IPPROTO_UDP; return t }
	tcpT := func(t ctTuple) ctTuple { t.Proto = unix.IPPROTO_TCP; return t }
	for _, c := range []struct {
		name string
		e    ctEntry
		want string
	}{
		{"udp, no socket", ctEntry{Orig: udp(out(40000, "198.51.100.1:53")), Mark: dataPlaneMarkBit}, "udp"},
		{"udp, live socket", ctEntry{Orig: udp(out(40001, "198.51.100.1:53")), Mark: dataPlaneMarkBit}, ""},
		{"udp, not the data plane", ctEntry{Orig: udp(out(40000, "198.51.100.1:53"))}, ""},
		{"udp, dnat", ctEntry{Orig: udp(out(40000, "198.51.100.1:53")), Mark: dataPlaneMarkBit, Status: ipsDstNAT}, ""},
		{"tcp out, close, no socket", ctEntry{Orig: tcpT(out(40000, "198.51.100.1:443")), Mark: dataPlaneMarkBit, TCPState: tcpClose, hasState: true}, "tcp-out"},
		{"tcp out, time_wait socket", ctEntry{Orig: tcpT(out(40002, "198.51.100.1:443")), Mark: dataPlaneMarkBit, TCPState: tcpTimeWait, hasState: true}, ""},
		{"tcp out, established", ctEntry{Orig: tcpT(out(40000, "198.51.100.1:443")), Mark: dataPlaneMarkBit, TCPState: tcpEstablished, hasState: true}, ""},
		{"tcp out, snat", ctEntry{Orig: tcpT(out(40000, "198.51.100.1:443")), Mark: dataPlaneMarkBit, TCPState: tcpClose, hasState: true, Status: ipsSrcNAT}, ""},
		{"tcp in, close, no socket", ctEntry{Orig: in("198.51.100.7:5001"), TCPState: tcpClose, hasState: true}, "tcp-in"},
		{"tcp in, fin_wait, its socket", ctEntry{Orig: in("198.51.100.7:5000"), TCPState: tcpFinWait, hasState: true}, ""},
		{"tcp in, established", ctEntry{Orig: in("198.51.100.7:5001"), TCPState: tcpEstablished, hasState: true}, ""},
		{"tcp in, from the node itself", ctEntry{Orig: in("127.0.0.1:5001"), TCPState: tcpClose, hasState: true}, ""},
		{"tcp in, dnat (a relay, ACME)", ctEntry{Orig: in("198.51.100.7:5001"), TCPState: tcpClose, hasState: true, Status: ipsDstNAT}, ""},
		{"tcp through, not to the node", ctEntry{Orig: ctTuple{Src: netip.MustParseAddrPort("198.51.100.7:1"), Dst: netip.MustParseAddrPort("203.0.113.1:443"), Proto: unix.IPPROTO_TCP}, TCPState: tcpClose, hasState: true}, ""},
	} {
		if got := orphan(c.e, socks, local); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// A snapshot of the node carries conn_limit_off; an older rayd's (absent)
// means on.
func TestSnapshotConnLimitDefault(t *testing.T) {
	if (&perimeterv1.Snapshot{}).GetConnLimitOff() {
		t.Fatal("absent reads as off")
	}
}
