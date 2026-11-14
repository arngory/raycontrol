package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/perimeter"
)

// countingFW is a firewall that takes everything and counts the tables
// made.
type countingFW struct {
	setups int
	admin  []netip.Prefix
}

func (f *countingFW) Setup() error                                            { f.setups++; f.admin = nil; return nil }
func (f *countingFW) Present() (bool, error)                                  { return f.setups > 0, nil }
func (f *countingFW) SetSPAPorts(_, _ []uint16) error                         { return nil }
func (f *countingFW) SetPublic([]perimeter.Port) error                        { return nil }
func (f *countingFW) SetAdmin(p []netip.Prefix, _ []perimeter.Port) error     { f.admin = p; return nil }
func (f *countingFW) SetForward([]perimeter.Port) error                       { return nil }
func (f *countingFW) SetRelays([]netip.Prefix, []perimeter.Port) error        { return nil }
func (f *countingFW) SetRotation(map[uint16]uint16) error                     { return nil }
func (f *countingFW) SetACME(uint16, time.Duration) error                     { return nil }
func (f *countingFW) SetEgress(perimeter.Egress) error                        { return nil }
func (f *countingFW) SetInLimit(bool) error                                   { return nil }
func (f *countingFW) SetGuard(bool) error                                     { return nil }
func (f *countingFW) Allow(netip.Addr, []perimeter.Port, time.Duration) error { return nil }
func (f *countingFW) Deny(netip.Addr, []perimeter.Port) error                 { return nil }
func (f *countingFW) Teardown() error                                         { return nil }

func savedSnapshot() *perimeterv1.Snapshot {
	return &perimeterv1.Snapshot{
		Spa: &perimeterv1.SPAParams{NodeId: slices.Repeat([]byte{0x33}, 16), EpochLenS: 86400, SlotLenS: 600,
			PortKey: bytes.Repeat([]byte{0x44}, 32), PortBase: 40000, PortRange: 4096, LenMin: 96, LenMax: 160,
			DefaultTtlS: 600, MaxTtlS: 3600},
		AdminPrefixes: []string{"198.51.100.0/24"},
		AdminPorts:    []*perimeterv1.Port{{Proto: "tcp", Port: 22}},
	}
}

// The start from the saved snapshot (R4-40): one that applies makes the
// table with the admin addresses in it; none, a damaged one, or one that
// does not apply leaves the kernel alone (no empty table that shuts the
// administrator out); one from a later version, with fields this one does
// not know, applies.
func TestRestoreAtStart(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	good, err := proto.Marshal(savedSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	bad := savedSnapshot()
	bad.Spa.PortKey = []byte{1}
	badBytes, _ := proto.Marshal(bad)
	later := protowire.AppendVarint(protowire.AppendTag(slices.Clone(good), 99, protowire.VarintType), 7)
	for name, c := range map[string]struct {
		content []byte // nil: no file
		up      bool
	}{
		"saved":          {good, true},
		"none":           {nil, false},
		"damaged":        {[]byte("\xff\xff\xff not a snapshot"), false},
		"does not apply": {badBytes, false},
		"later version":  {later, true},
	} {
		file := filepath.Join(t.TempDir(), "snapshot.pb")
		if c.content != nil {
			os.WriteFile(file, c.content, 0o600)
		}
		fw := &countingFW{}
		g := perimeter.NewGate(fw, log)
		g.SetupAtFirstSnapshot()
		restore(file, g, &perimeter.TCPCarrier{}, log)
		if g.Up() != c.up || (fw.setups == 1) != c.up || c.up && len(fw.admin) != 1 {
			t.Errorf("%s: up %v, %d setups, admin %v", name, g.Up(), fw.setups, fw.admin)
		}
	}
}
