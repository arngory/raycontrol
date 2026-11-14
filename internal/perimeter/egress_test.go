package perimeter

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// The output chain enters the egress policy for the data plane after the
// guard of the node's own addresses, and for the extra UIDs by their set;
// the policy's chains start empty.
func TestRulesetEgress(t *testing.T) {
	for _, guard := range []string{"", "9100-9101"} {
		rs := (&NFT{GuardUIDs: guard}).Ruleset()
		if guard == "" {
			guard = DataPlaneUIDs
		}
		jump := "meta skuid " + guard + " jump egress"
		last := strings.LastIndex(rs, "jump to_node")
		if i := strings.Index(rs, jump); i < 0 || i < last {
			t.Errorf("guard %s: %q missing or before the guard of the node's addresses", guard, jump)
		}
		for _, want := range []string{"set egress_uid { type uid; }", "meta skuid @egress_uid jump egress",
			"chain egress {\n\t}", "chain bt_tracker {\n\t}", "chain bt_utp {\n\t}", "chain bt_dht {\n\t}"} {
			if !strings.Contains(rs, want) {
				t.Errorf("ruleset lacks %q", want)
			}
		}
	}
}

func TestEgressScript(t *testing.T) {
	flushes := []string{"flush set inet raycontrol egress_uid\n", "flush chain inet raycontrol egress\n",
		"flush chain inet raycontrol bt_tracker\n", "flush chain inet raycontrol bt_utp\n", "flush chain inet raycontrol bt_dht\n"}
	for _, c := range []struct {
		name    string
		e       Egress
		doff    bool
		want    []string
		without []string
	}{
		{"off", Egress{}, false, nil, []string{"add "}},
		{"smtp", Egress{SMTP: true}, false,
			[]string{`add rule inet raycontrol egress tcp dport 25 counter reject with tcp reset comment "smtp"`},
			[]string{"bittorrent", "egress_uid {"}},
		{"bittorrent", Egress{BitTorrent: true}, false, []string{
			`add rule inet raycontrol egress meta l4proto tcp @ih,0,8 0x13 @ih,8,128 0x426974546f7272656e742070726f746f @ih,136,24 0x636f6c counter reject with tcp reset comment "bittorrent-tcp"`,
			"add rule inet raycontrol egress meta l4proto udp @th,64,8 vmap { 0x00 : jump bt_tracker, 0x41 : jump bt_utp, 0x64 : jump bt_dht }",
			`add rule inet raycontrol bt_tracker @th,64,64 0x41727101980 @th,128,32 0 counter drop comment "bittorrent-tracker"`,
			`add rule inet raycontrol bt_utp udp length 28 @th,72,8 0 @th,128,32 0 counter drop comment "bittorrent-utp"`,
			`add rule inet raycontrol bt_utp udp length 38 @th,72,8 2 @th,128,32 0 @th,224,16 8 counter drop comment "bittorrent-utp"`,
			`add rule inet raycontrol bt_dht @th,64,96 0x64313a6164323a696432303a counter drop comment "bittorrent-dht"`,
		}, []string{"dport 25", "doff"}},
		{"bittorrent by tcp doff", Egress{BitTorrent: true}, true, []string{
			`tcp doff 5 @th,160,8 0x13 @th,168,128 0x426974546f7272656e742070726f746f @th,296,24 0x636f6c counter reject with tcp reset comment "bittorrent-tcp"`,
			`tcp doff 8 @th,256,8 0x13 @th,264,128 0x426974546f7272656e742070726f746f @th,392,24 0x636f6c counter reject with tcp reset comment "bittorrent-tcp"`,
		}, []string{"@ih"}},
		{"supervised", Egress{SMTP: true, UIDs: []uint32{0, 4242}}, false,
			[]string{"add element inet raycontrol egress_uid { 0, 4242 }\n"}, []string{"egress_local meta", "egress_local ip"}},
		{"local", Egress{Local: true, Loopback: []Port{{"tcp", 8443}, {"udp", 8443}}}, false, []string{
			"flush chain inet raycontrol egress_local\n" +
				"add rule inet raycontrol egress_local meta l4proto { tcp, udp } ip daddr { 127.0.0.53, 127.0.0.54 } th dport 53 return\n" +
				"add rule inet raycontrol egress_local ip daddr 127.0.0.1 meta l4proto . th dport { tcp . 8443, udp . 8443 } return\n" +
				`add rule inet raycontrol egress_local ip daddr @local4 meta l4proto tcp counter reject with tcp reset comment "local"` + "\n" +
				`add rule inet raycontrol egress_local ip daddr @local4 counter reject with icmpx admin-prohibited comment "local"` + "\n" +
				`add rule inet raycontrol egress_local ip6 daddr @local6 meta l4proto tcp counter reject with tcp reset comment "local"` + "\n" +
				`add rule inet raycontrol egress_local ip6 daddr @local6 counter reject with icmpx admin-prohibited comment "local"` + "\n",
		}, []string{"dport 25", "bittorrent"}},
		{"local, no probe", Egress{Local: true}, false, []string{"@local4", "@local6", "127.0.0.53"}, []string{"127.0.0.1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := EgressScript(c.e, c.doff)
			for _, f := range flushes {
				if !strings.HasPrefix(s, flushes[0]) || !strings.Contains(s, f) {
					t.Errorf("lacks %q, or not first:\n%s", f, s)
				}
			}
			for _, w := range c.want {
				if !strings.Contains(s, w) {
					t.Errorf("lacks %q:\n%s", w, s)
				}
			}
			for _, w := range append(c.without, " log", "flush ruleset", "chain inet raycontrol output", "to_node") {
				if strings.Contains(s, w) {
					t.Errorf("has %q:\n%s", w, s)
				}
			}
		})
	}
}

func TestEgressOf(t *testing.T) {
	if e := egressOf(nil); !e.Equal(Egress{}) {
		t.Errorf("an older rayd's snapshot: %+v", e)
	}
	e := egressOf(&perimeterv1.Egress{Smtp: true, Uids: []uint32{9190, 0, 9190}})
	if !e.SMTP || e.BitTorrent || !slices.Equal(e.UIDs, []uint32{0, 9190}) {
		t.Errorf("%+v", e)
	}
	if e.Equal(Egress{SMTP: true, UIDs: []uint32{0}}) || !e.Equal(Egress{SMTP: true, UIDs: []uint32{0, 9190}}) {
		t.Error("Equal")
	}
	// The local networks (R4-38): refused unless allowed; a rayd from
	// before them sends no Local, and gets the policy it had.
	if e.Local {
		t.Error("an older rayd's snapshot refuses the local networks")
	}
	e = egressOf(&perimeterv1.Egress{Local: &perimeterv1.Local{Loopback: []*perimeterv1.Port{
		{Proto: "udp", Port: 8443}, {Proto: "tcp", Port: 8443}, {Proto: "tcp", Port: 8443}, {Proto: "sctp", Port: 1}, {Proto: "tcp"}}}})
	if !e.Local || !slices.Equal(e.Loopback, []Port{{"tcp", 8443}, {"udp", 8443}}) {
		t.Errorf("local: %+v", e)
	}
	if e.Equal(Egress{Local: true}) {
		t.Error("Equal without the probe's ports")
	}
	if e = egressOf(&perimeterv1.Egress{Local: &perimeterv1.Local{Allow: true, Loopback: []*perimeterv1.Port{{Proto: "tcp", Port: 8443}}}}); e.Local || e.Loopback != nil {
		t.Errorf("allowed: %+v", e)
	}
}

// The table's part of R4-38: the sets of LocalNets, and the output
// chain's jump for the data plane's new flows, after the guards of the
// node's own addresses and before the rest of the policy; the extra UIDs
// (rayd's, supervised) do not take it.
func TestRulesetLocal(t *testing.T) {
	rs := (&NFT{}).Ruleset()
	for _, want := range []string{
		"set local4 { type ipv4_addr; flags interval; elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, " +
			"172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }; }",
		"set local6 { type ipv6_addr; flags interval; elements = { ::/96, fc00::/7, fe80::/10, ff00::/8, 64:ff9b::/96, 64:ff9b:1::/48, 2002::/16 }; }",
		"chain egress_local {\n\t}",
		"\t\tmeta skuid " + DataPlaneUIDs + " ct state new,untracked jump egress_local\n\t\tmeta skuid " + DataPlaneUIDs + " jump egress\n\t\tmeta skuid @egress_uid jump egress\n",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
	if strings.Index(rs, "jump egress_local") < strings.LastIndex(rs, "jump to_node") {
		t.Error("egress_local before the guards of the node's own addresses")
	}
	if strings.Contains(rs, "@egress_uid ct state new,untracked jump egress_local") {
		t.Error("the extra UIDs take the local part")
	}
	for _, n := range LocalNets {
		if _, err := netip.ParsePrefix(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	// The metadata address, in both of its spellings.
	for _, a := range []string{"169.254.169.254", "64:ff9b::a9fe:a9fe", "fd00:ec2::254", "127.0.0.1", "::1", "100.64.0.1", "255.255.255.255"} {
		if !slices.ContainsFunc(LocalNets, func(n string) bool { return netip.MustParsePrefix(n).Contains(netip.MustParseAddr(a)) }) {
			t.Errorf("%s is not local", a)
		}
	}
	for _, a := range []string{"1.1.1.1", "2606:4700:4700::1111", "200::1", "198.51.100.1"} {
		if slices.ContainsFunc(LocalNets, func(n string) bool { return netip.MustParsePrefix(n).Contains(netip.MustParseAddr(a)) }) {
			t.Errorf("%s is local", a)
		}
	}
}

// A relay has no data plane: its policy is none, whatever it is given.
func TestEgressNotOnRelay(t *testing.T) {
	relay := &NFT{RelayTo: netip.MustParseAddr("192.0.2.1"), Bin: "/nonexistent/nft"}
	if err := relay.SetEgress(Egress{SMTP: true, BitTorrent: true}); err != nil {
		t.Fatal(err)
	}
}

// CheckEgress: the kernel's dry run, the whole table first; with no @ih the
// TCP rule by tcp doff; a refusal says why, both ways.
func TestCheckEgress(t *testing.T) {
	both := Egress{SMTP: true, BitTorrent: true}
	var scripts []string
	run := func(refuse func(string) bool) func(string) ([]byte, error) {
		scripts = nil
		return func(s string) ([]byte, error) {
			scripts = append(scripts, s)
			if refuse(s) {
				return []byte("Error: Could not process rule: Operation not supported\nadd rule ...\n"), errors.New("exit status 1")
			}
			return nil, nil
		}
	}
	if doff, err := CheckEgress(both, run(func(string) bool { return false })); err != nil || doff || len(scripts) != 1 ||
		!strings.HasPrefix(scripts[0], (&NFT{NflogGroup: 7}).Ruleset()) || !strings.HasSuffix(scripts[0], EgressScript(both, false)) {
		t.Fatalf("a kernel that takes it: doff %v, %v, %d runs", doff, err, len(scripts))
	}
	noIH := func(s string) bool { return strings.Contains(s, "@ih") }
	if doff, err := CheckEgress(both, run(noIH)); err != nil || !doff || len(scripts) != 2 {
		t.Fatalf("no @ih: doff %v, %v", doff, err)
	}
	if _, err := CheckEgress(Egress{SMTP: true}, run(noIH)); err != nil || len(scripts) != 1 {
		t.Fatalf("smtp alone needs no @ih: %v", err)
	}
	_, err := CheckEgress(both, run(func(string) bool { return true }))
	if err == nil || !strings.Contains(err.Error(), "Operation not supported") || !strings.Contains(err.Error(), "with tcp doff") ||
		strings.Contains(err.Error(), "\n") {
		t.Fatalf("a refusal: %v", err)
	}
	if _, err := CheckEgress(Egress{SMTP: true}, run(func(string) bool { return true })); err == nil || len(scripts) != 1 {
		t.Fatalf("smtp refused: %v, %d runs", err, len(scripts))
	}
}

// The gate puts the snapshot's policy in force once, again after a
// restore of the table; a policy the kernel refuses holds back neither the
// rest of the snapshot nor a restore, and is tried again on its own.
func TestGateEgress(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	sets := func() int { return strings.Count(strings.Join(fw.calls, " "), "SetEgress") }
	if _, err := g.Tick(); !errors.Is(err, ErrNotReady) || sets() != 0 {
		t.Fatalf("before a snapshot: %d calls, %v", sets(), err)
	}

	// An older rayd's snapshot: nothing blocked, in force all the same (the
	// chains of a table made before are emptied).
	snap := testSnapshot()
	if err := g.Update(snap); err != nil || fw.egress == nil || !fw.egress.Equal(Egress{}) {
		t.Fatalf("no policy: %+v %v", fw.egress, err)
	}
	snap.Egress = &perimeterv1.Egress{Smtp: true, Uids: []uint32{0}}
	if err := g.Update(snap); err != nil || !fw.egress.Equal(Egress{SMTP: true, UIDs: []uint32{0}}) {
		t.Fatalf("smtp: %+v %v", fw.egress, err)
	}
	n := sets()
	snap.DebugUntil = 1 // a snapshot that changes something else
	if err := g.Update(snap); err != nil || sets() != n {
		t.Fatalf("the same policy written again: %d calls, %v", sets()-n, err)
	}
	g.Tick()
	if sets() != n {
		t.Fatal("written again by Tick")
	}

	// Back with the table.
	fw.flush()
	if _, err := g.Tick(); err != nil || fw.egress == nil || !fw.egress.SMTP || fw.setups != 1 {
		t.Fatalf("after flush ruleset: %+v setups %d, %v", fw.egress, fw.setups, err)
	}
	if fw.calls[len(fw.calls)-1] != "SetEgress" {
		t.Fatalf("the policy not after the restore: %v", fw.calls)
	}

	// Refused: the rest of the snapshot goes in, no ErrPending; tried
	// again less and less often.
	fw.failing = map[string]int{"SetEgress": 1000}
	snap.Egress = &perimeterv1.Egress{Smtp: true, Bittorrent: true}
	snap.AdminPrefixes = []string{"198.51.100.0/24"}
	snap.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 22}}
	if err := g.Update(snap); err != nil || len(fw.admin) != 1 || fw.egress.BitTorrent {
		t.Fatalf("a refused policy: admin %v, egress %+v, %v", fw.admin, fw.egress, err)
	}
	n = sets()
	for range 10 {
		now = now.Add(time.Second)
		if ports, err := g.Tick(); err != nil || ports == nil {
			t.Fatalf("the slots behind a refused policy: %v %v", ports, err)
		}
	}
	if tries := sets() - n; tries < 2 || tries > 4 {
		t.Fatalf("%d tries in 10 s", tries)
	}
	// Nor a restore: the table is back at once, with the policy's own
	// backoff started anew.
	fw.flush()
	setups := fw.setups
	if _, err := g.Tick(); err != nil || fw.setups != setups+1 || len(fw.admin) != 1 || len(fw.udp) == 0 {
		t.Fatalf("restore behind a refused policy: setups %d, admin %v, slots %v, %v", fw.setups-setups, fw.admin, fw.udp, err)
	}
	if g.egressOn || g.egressFailures != 1 {
		t.Fatalf("after the restore: on %v, failures %d", g.egressOn, g.egressFailures)
	}
	// A new policy is tried at once, whatever the backoff.
	fw.failing = nil
	snap.Egress = &perimeterv1.Egress{Bittorrent: true}
	if err := g.Update(snap); err != nil || !fw.egress.Equal(Egress{BitTorrent: true}) || !g.egressOn {
		t.Fatalf("a new policy: %+v %v", fw.egress, err)
	}
}
