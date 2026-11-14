//go:build linux

package perimeter

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

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

// TestNetnsFirstTableWhole: the first table goes in with its admin
// addresses, public ports and slots in one transaction (R4-40), and the
// gate is up only once all of it is in. An nft that refuses any
// transaction adding to admin4 (a wrapper, while a file exists) stands
// for a kernel that refuses a part: with the parts one exec each, the gate
// said up with the input chain at policy drop and admin4 empty, the
// administrator shut out. Now nothing goes in: the table an earlier rayspa
// left stays with its admin addresses, or there is none; and the next
// tick after the refusal ends puts the whole table in.
func TestNetnsFirstTableWhole(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	loUp(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fail := dir + "/fail"
	wrapper := dir + "/nft"
	script := "#!/bin/sh\nin=$(cat)\n" +
		"if [ -e " + fail + " ] && printf '%s\\n' \"$in\" | grep -q 'add element inet " + Table + " admin4'; then\n" +
		"  echo 'Error: refused (test)' >&2; exit 1\nfi\n" +
		"printf '%s\\n' \"$in\" | exec " + nft + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable
		t.Fatal(err)
	}
	list := func() string {
		out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
		if err != nil {
			t.Fatalf("nft list ruleset: %v: %s", err, out)
		}
		return string(out)
	}
	defer (&NFT{}).Teardown()
	snap := func(admin string) *perimeterv1.Snapshot {
		s := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}})
		s.AdminPrefixes = []string{admin}
		s.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 22}}
		return s
	}

	for _, leftOver := range []bool{false, true} {
		_ = (&NFT{}).Teardown()
		if leftOver {
			// An earlier rayspa's table, with its admin addresses.
			g0 := NewGate(&NFT{NflogGroup: 7, FilterLoopback: true}, quiet)
			g0.SetupAtFirstSnapshot()
			if err := g0.Update(snap("198.51.100.0/24")); err != nil || !g0.Up() {
				t.Fatalf("the earlier table: %v, up %v", err, g0.Up())
			}
		}
		if err := os.WriteFile(fail, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		fw := &NFT{NflogGroup: 7, FilterLoopback: true, Bin: wrapper}
		g := NewGate(fw, quiet)
		g.SetupAtFirstSnapshot()
		err := g.Update(snap("203.0.113.0/24"))
		rs := list()
		if !errors.Is(err, ErrPending) || g.Up() || g.State() != GateNotIn || strings.Contains(rs, "203.0.113.0/24") {
			t.Fatalf("left over %v, admin4 refused: %v, up %v, state %v:\n%s", leftOver, err, g.Up(), g.State(), rs)
		}
		if leftOver != strings.Contains(rs, "198.51.100.0/24") || leftOver != strings.Contains(rs, "table inet "+Table) {
			t.Fatalf("left over %v: the kernel changed under a refused first table:\n%s", leftOver, rs)
		}
		// Ticks while it is refused: still nothing, still not up.
		if _, err := g.Tick(); err == nil || g.Up() {
			t.Fatalf("left over %v: a tick with the refusal: %v, up %v", leftOver, err, g.Up())
		}

		if err := os.Remove(fail); err != nil {
			t.Fatal(err)
		}
		// Past the backoff of the failures so far (1 s, then 2 s).
		for i := 0; i < 4 && !g.Up(); i++ {
			time.Sleep(time.Second)
			_, _ = g.Tick()
		}
		rs = list()
		if !g.Up() || !strings.Contains(rs, "203.0.113.0/24") || strings.Contains(rs, "198.51.100.0/24") ||
			!strings.Contains(rs, "policy drop") || !strings.Contains(rs, "udp . 53") {
			t.Fatalf("left over %v, after the refusal: up %v:\n%s", leftOver, g.Up(), rs)
		}
	}
}
