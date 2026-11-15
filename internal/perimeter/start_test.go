package perimeter

import (
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// txFW is fakeFW with SetupWith (TableSetup), as NFT has it, the gate's
// production path: the table and all its contents in one transaction,
// taken whole or refused whole (a part the kernel would refuse, Setup's
// or the admin addresses', refuses it all, and nothing changes). txs are
// the transactions taken.
type txFW struct {
	*fakeFW
	txs []TableContents
}

func (f *txFW) SetupWith(c TableContents) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "SetupWith")
	refused := f.fails("Setup") || f.fails("SetupWith")
	if len(c.Admin) > 0 && f.adminFails > 0 {
		f.adminFails--
		refused = true
	}
	if refused {
		return errors.New("nft: transaction refused")
	}
	f.setups++
	f.gone = false
	f.udp, f.tcp, f.public, f.admin, f.adminPorts, f.forward, f.rot = c.SPAUDP, c.SPATCP, c.Public, c.Admin, c.AdminPorts, c.Forward, c.Rotation
	f.relays, f.relayPorts = nil, nil
	if c.Relayed {
		f.relays, f.relayPorts = c.Relays, c.RelayPorts
		f.relaysSets++
	}
	f.open = map[string]time.Duration{}
	for _, g := range c.Grants {
		f.open[g.Addr.String()+" "+g.Port.String()] = g.TTL
	}
	f.acmePort, f.acmeTTL = c.ACMEPort, c.ACMETTL
	f.inLimitOff, f.egress, f.guard = c.InLimitOff, nil, false
	f.txs = append(f.txs, c)
	return nil
}

// gateFirewalls runs a test on both ways the gate makes its table: one
// transaction (SetupWith, NFT's, as rayspa runs) and part by part (a
// firewall without it, restoreSteps). base is the fake's state at the
// start; tx is nil on the second.
func gateFirewalls(t *testing.T, base *fakeFW, test func(t *testing.T, fw Firewall, f *fakeFW, tx *txFW)) {
	for _, name := range []string{"one transaction", "part by part"} {
		t.Run(name, func(t *testing.T) {
			f := &fakeFW{gone: base.gone, adminFails: base.adminFails, failing: maps.Clone(base.failing)}
			if name == "part by part" {
				test(t, f, f, nil)
				return
			}
			tx := &txFW{fakeFW: f}
			test(t, tx, f, tx)
		})
	}
}

// rayspa's start (R4-40): the gate makes its table only with a snapshot.
// Before one it leaves the kernel alone: no empty table that would shut
// the administrator out, whether a table is there (a restart) or not (a
// boot without a saved snapshot).
func TestGateSetupAtFirstSnapshot(t *testing.T) {
	now := time.Unix(1767225600, 0)
	for _, leftOver := range []bool{true, false} {
		t.Run(map[bool]string{true: "a table left over", false: "no table"}[leftOver], func(t *testing.T) {
			gateFirewalls(t, &fakeFW{gone: !leftOver}, func(t *testing.T, fw Firewall, f *fakeFW, tx *txFW) {
				g := NewGate(fw, quiet)
				g.now = func() time.Time { return now }
				g.SetupAtFirstSnapshot()
				for range 3 {
					if _, err := g.Tick(); !errors.Is(err, ErrNotReady) {
						t.Fatalf("left over %v: tick before a snapshot: %v", leftOver, err)
					}
				}
				if f.setups != 0 || g.Up() || len(f.calls) != 0 {
					t.Fatalf("left over %v: %d setups before a snapshot, up %v, calls %v", leftOver, f.setups, g.Up(), f.calls)
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
				if f.setups != 1 || len(f.admin) != 1 || len(f.public) != 1 || len(f.udp) == 0 ||
					f.egress == nil || !f.egress.SMTP || !g2.Up() {
					t.Fatalf("left over %v: after the first snapshot: setups %d calls %v admin %v public %v udp %v egress %v up %v",
						leftOver, f.setups, f.calls, f.admin, f.public, f.udp, f.egress, g2.Up())
				}
				// In one transaction the table comes with the admin addresses,
				// the public ports and the slots in it (no table without them,
				// not for a packet); the egress policy follows. Part by part,
				// the table first.
				switch {
				case tx != nil && (len(tx.txs) != 1 || len(tx.txs[0].Admin) != 1 || len(tx.txs[0].AdminPorts) != 1 ||
					len(tx.txs[0].Public) != 1 || len(tx.txs[0].SPAUDP) == 0 || f.calls[0] != "SetupWith" || slices.Contains(f.calls, "Setup") ||
					slices.Contains(f.calls, "SetAdmin") || slices.Index(f.calls, "SetEgress") < 1):
					t.Fatalf("left over %v: the transaction %+v, calls %v", leftOver, tx.txs, f.calls)
				case tx == nil && f.calls[0] != "Setup":
					t.Fatalf("left over %v: calls %v", leftOver, f.calls)
				}
				if _, err := g2.Tick(); err != nil || f.setups != 1 {
					t.Fatalf("left over %v: a tick after: %v, %d setups", leftOver, err, f.setups)
				}
			})
		})
	}
}

// A first snapshot the firewall refuses in part (Setup itself, a kernel
// that does not take the table) leaves the gate down, and Tick tries again.
func TestGateFirstSetupFails(t *testing.T) {
	gateFirewalls(t, &fakeFW{gone: true, failing: map[string]int{"Setup": 1}}, func(t *testing.T, fw Firewall, f *fakeFW, tx *txFW) {
		now := time.Unix(1767225600, 0)
		g := NewGate(fw, quiet)
		g.now = func() time.Time { return now }
		g.SetupAtFirstSnapshot()
		if err := g.Update(testSnapshot()); !errors.Is(err, ErrPending) || g.Up() || f.setups != 0 || !f.gone {
			t.Fatalf("a refused setup: %v, up %v, %d setups, gone %v", err, g.Up(), f.setups, f.gone)
		}
		now = now.Add(2 * time.Second)
		if _, err := g.Tick(); err != nil || !g.Up() || f.setups != 1 {
			t.Fatalf("the next tick: %v, up %v, setups %d", err, g.Up(), f.setups)
		}
		if tx != nil && len(tx.txs) != 1 {
			t.Fatalf("transactions %d", len(tx.txs))
		}
	})
}

// The first table is up only with all of its snapshot: a firewall that
// takes the table and refuses the admin addresses leaves the gate down
// (GateNotIn), not up with an empty admin set; in one transaction the
// refusal takes the whole table, and the kernel stays as it was. A later
// snapshot taken in part leaves it behind (GateBehind), the table in, not
// up.
func TestGateUpOnlyWhole(t *testing.T) {
	gateFirewalls(t, &fakeFW{gone: true, adminFails: 1}, func(t *testing.T, fw Firewall, f *fakeFW, tx *txFW) {
		now := time.Unix(1767225600, 0)
		g := NewGate(fw, quiet)
		g.now = func() time.Time { return now }
		g.SetupAtFirstSnapshot()
		snap := testSnapshot()
		snap.AdminPrefixes = []string{"198.51.100.0/24"}
		snap.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 22}}
		if err := g.Update(snap); !errors.Is(err, ErrPending) || g.Up() || g.State() != GateNotIn {
			t.Fatalf("admin refused in the first table: %v, up %v, state %v", err, g.Up(), g.State())
		}
		if tx != nil && (!f.gone || f.setups != 0 || len(tx.txs) != 0) {
			t.Fatalf("a refused transaction changed the kernel: gone %v, setups %d, %+v", f.gone, f.setups, tx.txs)
		}
		now = now.Add(2 * time.Second)
		if _, err := g.Tick(); err != nil || !g.Up() || len(f.admin) != 1 {
			t.Fatalf("the next tick: %v, up %v, admin %v", err, g.Up(), f.admin)
		}
		next := testSnapshot()
		next.AdminPrefixes = []string{"203.0.113.0/24"}
		next.AdminPorts = snap.AdminPorts
		f.adminFails = 1
		if err := g.Update(next); !errors.Is(err, ErrPending) || g.State() != GateBehind || g.Up() {
			t.Fatalf("a later snapshot in part: %v, state %v", err, g.State())
		}
		now = now.Add(2 * time.Second)
		if _, err := g.Tick(); err != nil || !g.Up() || f.admin[0].String() != "203.0.113.0/24" {
			t.Fatalf("caught up: %v, up %v, admin %v", err, g.Up(), f.admin)
		}
		// The table stayed: the later snapshot went in through the setters.
		if tx != nil && len(tx.txs) != 1 {
			t.Fatalf("transactions %d", len(tx.txs))
		}
	})
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
