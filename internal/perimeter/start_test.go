package perimeter

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// rayspa's start (R4-40): the gate makes its table only with a snapshot.
// Before one it leaves the kernel alone: no empty table that would shut
// the administrator out, whether a table is there (a restart) or not (a
// boot without a saved snapshot).
func TestGateSetupAtFirstSnapshot(t *testing.T) {
	now := time.Unix(1767225600, 0)
	for _, leftOver := range []bool{true, false} {
		fw := &fakeFW{gone: !leftOver}
		g := NewGate(fw, quiet)
		g.now = func() time.Time { return now }
		g.SetupAtFirstSnapshot()
		for range 3 {
			if _, err := g.Tick(); !errors.Is(err, ErrNotReady) {
				t.Fatalf("left over %v: tick before a snapshot: %v", leftOver, err)
			}
		}
		if fw.setups != 0 || g.Up() {
			t.Fatalf("left over %v: %d setups before a snapshot, up %v", leftOver, fw.setups, g.Up())
		}
		if err := g.ReleaseGuard(); err != nil {
			t.Fatalf("left over %v: release with no table of its own: %v", leftOver, err)
		}

		snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{3}})
		snap.AdminPrefixes = []string{"198.51.100.0/24"}
		snap.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 22}}
		snap.Egress = &perimeterv1.Egress{Smtp: true}
		g2 := NewGate(fw, quiet)
		g2.now = func() time.Time { return now }
		g2.SetupAtFirstSnapshot()
		if err := g2.Update(snap); err != nil {
			t.Fatal(err)
		}
		// One table, made first, then the snapshot in it: the admin
		// addresses, the public ports, the slots and the egress policy.
		if fw.setups != 1 || fw.calls[0] != "Setup" || len(fw.admin) != 1 || len(fw.public) != 1 || len(fw.udp) == 0 ||
			fw.egress == nil || !fw.egress.SMTP || !g2.Up() {
			t.Fatalf("left over %v: after the first snapshot: setups %d calls %v admin %v public %v udp %v egress %v up %v",
				leftOver, fw.setups, fw.calls, fw.admin, fw.public, fw.udp, fw.egress, g2.Up())
		}
		if _, err := g2.Tick(); err != nil || fw.setups != 1 {
			t.Fatalf("left over %v: a tick after: %v, %d setups", leftOver, err, fw.setups)
		}
	}
}

// A first snapshot the firewall refuses in part (Setup itself, a kernel
// that does not take the table) leaves the gate down, and Tick tries again.
func TestGateFirstSetupFails(t *testing.T) {
	now := time.Unix(1767225600, 0)
	fw := &fakeFW{gone: true, failing: map[string]int{"Setup": 1}}
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return now }
	g.SetupAtFirstSnapshot()
	if err := g.Update(testSnapshot()); !errors.Is(err, ErrPending) || g.Up() {
		t.Fatalf("a refused setup: %v, up %v", err, g.Up())
	}
	now = now.Add(2 * time.Second)
	if _, err := g.Tick(); err != nil || !g.Up() || fw.setups != 1 {
		t.Fatalf("the next tick: %v, up %v, setups %d", err, g.Up(), fw.setups)
	}
}

// A snapshot that does not apply (from a later version, damaged) changes
// nothing in the kernel: the gate stays without a table.
func TestGateBadFirstSnapshot(t *testing.T) {
	fw := &fakeFW{gone: true}
	g := NewGate(fw, quiet)
	g.SetupAtFirstSnapshot()
	bad := testSnapshot()
	bad.Spa.PortKey = []byte{1, 2, 3}
	if err := g.Update(bad); err == nil || errors.Is(err, ErrPending) {
		t.Fatalf("a bad snapshot: %v", err)
	}
	if _, err := g.Tick(); !errors.Is(err, ErrNotReady) || fw.setups != 0 || g.Up() {
		t.Fatalf("after a bad snapshot: %v, setups %d, up %v", err, fw.setups, g.Up())
	}
}

// The relay's table until its first snapshot: forwarded packets dropped,
// nothing else; no input chain, so it shuts nobody out.
func TestHoldForwardScript(t *testing.T) {
	want := `table inet raycontrol {
	chain relay_forward {
		type filter hook forward priority 0; policy drop;
		ct state established,related accept
	}
}
`
	if got := HoldForwardScript(); got != want {
		t.Fatalf("hold:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(HoldForwardScript(), "hook input") {
		t.Fatal("the hold filters input")
	}
	// Setup replaces it with the whole table: the same name, the
	// relay_forward chain its own.
	rs := (&NFT{RelayTo: netip.MustParseAddr("203.0.113.7")}).Ruleset()
	if !strings.HasPrefix(rs, "table inet raycontrol {}\ndelete table inet raycontrol\n") || !strings.Contains(rs, "chain relay_forward {\n\t\ttype filter hook forward priority 0; policy drop;") {
		t.Fatal("the relay's table does not replace the hold")
	}
}
