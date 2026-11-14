//go:build linux

package perimeter

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// TestNetnsStart is rayspa's start in the kernel (R4-40), in a fresh
// network namespace as TestNetns:
//   - before a snapshot the gate makes no table, nor restores one;
//   - a relay's hold forwards nothing and has no input chain;
//   - the first snapshot's table replaces the hold, in one transaction;
//   - a table an earlier rayspa left stays until the first snapshot.
func TestNetnsStart(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	loUp(t)
	list := func() string {
		out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
		if err != nil {
			t.Fatalf("nft list ruleset: %v: %s", err, out)
		}
		return string(out)
	}

	fw := &NFT{NflogGroup: 7, FilterLoopback: true, RelayTo: netip.MustParseAddr("203.0.113.7")}
	defer fw.Teardown()
	g := NewGate(fw, quiet)
	g.SetupAtFirstSnapshot()
	for range 2 {
		if _, err := g.Tick(); err == nil {
			t.Fatal("a tick before a snapshot said nothing")
		}
	}
	if rs := list(); strings.Contains(rs, "table inet "+Table) {
		t.Fatalf("a table before a snapshot:\n%s", rs)
	}

	if err := fw.HoldForward(); err != nil {
		t.Fatal(err)
	}
	rs := list()
	if !strings.Contains(rs, "chain relay_forward") || !strings.Contains(rs, "policy drop") || strings.Contains(rs, "hook input") {
		t.Fatalf("the hold:\n%s", rs)
	}
	// Twice: the table is there, the hold leaves it.
	if err := fw.HoldForward(); err != nil {
		t.Fatal(err)
	}

	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}})
	snap.AdminPrefixes = []string{"198.51.100.0/24"}
	snap.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 22}}
	if err := g.Update(snap); err != nil {
		t.Fatal(err)
	}
	rs = list()
	if !g.Up() || !strings.Contains(rs, "hook input") || !strings.Contains(rs, "198.51.100.0/24") || !strings.Contains(rs, "chain relay_dnat") {
		t.Fatalf("after the first snapshot (up %v):\n%s", g.Up(), rs)
	}

	// A restart: the next rayspa finds this table and keeps it until its
	// own first snapshot, the admin addresses in force meanwhile.
	g2 := NewGate(&NFT{NflogGroup: 7, FilterLoopback: true}, quiet)
	g2.SetupAtFirstSnapshot()
	if _, err := g2.Tick(); err == nil {
		t.Fatal("a tick before a snapshot said nothing")
	}
	if rs := list(); !strings.Contains(rs, "198.51.100.0/24") {
		t.Fatalf("the earlier table went before a snapshot:\n%s", rs)
	}
}
