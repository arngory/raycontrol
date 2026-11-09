package perimeter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeTable is a conntrack table of entries by family and mark; onDump runs
// as a dump is made (a socket made meanwhile), and delete fails with
// failWith.
type fakeTable struct {
	entries  []ctEntry
	onDump   func()
	deleted  []ctEntry
	failWith error
	dumps    []dumpArgs
}

type dumpArgs struct {
	family      uint8
	value, mask uint32
	proto       uint8
}

func (f *fakeTable) dump(family uint8, value, mask uint32, proto uint8) ([]ctEntry, error) {
	f.dumps = append(f.dumps, dumpArgs{family, value, mask, proto})
	if f.onDump != nil {
		f.onDump()
	}
	var out []ctEntry
	for _, e := range f.entries {
		if e.Family == family && e.Mark&mask == value && (proto == 0 || e.Orig.Proto == proto) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeTable) delete(e ctEntry) error {
	if f.failWith != nil {
		return f.failWith
	}
	f.deleted = append(f.deleted, e)
	return nil
}

func (f *fakeTable) Close() error { return nil }

// procNet writes /proc/net's four socket tables into dir: UDP sockets on
// the ports given, no TCP.
func procNet(t *testing.T, dir string, udpPorts ...uint16) {
	t.Helper()
	udp := "  sl  local_address rem_address   st\n"
	for i, p := range udpPorts {
		udp += fmt.Sprintf("  %d: 0A00020C:%04X 00000000:0000 07 00000000:00000000\n", i, p)
	}
	head := "  sl  local_address rem_address   st\n"
	for name, body := range map[string]string{"udp": udp, "udp6": head, "tcp": head, "tcp6": head} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func udpOut(port uint16) ctEntry {
	return ctEntry{Family: unix.AF_INET, Mark: dataPlaneMarkBit, ID: uint32(port), Orig: ctTuple{
		Src: netip.AddrPortFrom(netip.MustParseAddr("10.0.2.12"), port), Dst: netip.MustParseAddrPort("198.51.100.1:443"), Proto: unix.IPPROTO_UDP}}
}

func sweeperOn(dir string, table *fakeTable) *Sweeper {
	return &Sweeper{Net: dir, table: func() (ctTable, error) { return table, nil },
		Local: func() (map[netip.Addr]bool, error) {
			return map[netip.Addr]bool{netip.MustParseAddr("10.0.2.12"): true}, nil
		}}
}

// The sockets are read after the dump: a socket made while the sweep ran,
// before the dump returned, keeps its entry (spec/conn-limit-v1.md §6.3:
// the sweep never touches a live connection); a socket gone is swept.
func TestSweepSocketsAfterDump(t *testing.T) {
	dir := t.TempDir()
	procNet(t, dir) // no socket yet
	table := &fakeTable{entries: []ctEntry{udpOut(40000), udpOut(40001)}}
	// The socket of 40000 comes as the dump is made.
	table.onDump = func() { procNet(t, dir, 40000) }
	r, err := sweeperOn(dir, table).Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.UDP != 1 || len(table.deleted) != 1 || table.deleted[0].Orig.Src.Port() != 40001 {
		t.Fatalf("swept %+v: %+v", r, table.deleted)
	}
}

// Failed deletions are counted, with the first error: not one line of
// every failure.
func TestSweepDeleteFailures(t *testing.T) {
	dir := t.TempDir()
	procNet(t, dir)
	table := &fakeTable{failWith: errors.New("netlink receive: operation not permitted")}
	for p := range uint16(500) {
		table.entries = append(table.entries, udpOut(40000+p))
	}
	r, err := sweeperOn(dir, table).Sweep(context.Background())
	if err == nil || r.UDP != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if msg := err.Error(); len(msg) > 200 || !strings.Contains(msg, "500") || strings.Count(msg, "not permitted") != 1 {
		t.Fatalf("the error: %q", msg)
	}
}

// The unmarked dumps ask the kernel for TCP alone: only inbound TCP may be
// swept there. The marked ones take every protocol (UDP and TCP out).
func TestSweepDumps(t *testing.T) {
	dir := t.TempDir()
	procNet(t, dir)
	table := &fakeTable{}
	if _, err := sweeperOn(dir, table).Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []dumpArgs{
		{unix.AF_INET, dataPlaneMarkBit, dataPlaneMarkBit, 0}, {unix.AF_INET, 0, dataPlaneMarkBit, unix.IPPROTO_TCP},
		{unix.AF_INET6, dataPlaneMarkBit, dataPlaneMarkBit, 0}, {unix.AF_INET6, 0, dataPlaneMarkBit, unix.IPPROTO_TCP},
	}
	if !slices.Equal(table.dumps, want) {
		t.Fatalf("dumps %+v, want %+v", table.dumps, want)
	}
}
