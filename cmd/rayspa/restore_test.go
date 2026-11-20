package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
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
func (f *countingFW) SetInteg([]netip.Prefix, []perimeter.Port) error         { return nil }
func (f *countingFW) SetForward([]perimeter.Port) error                       { return nil }
func (f *countingFW) SetRelays([]netip.Prefix, []perimeter.Port) error        { return nil }
func (f *countingFW) SetRotation(map[uint16]uint16) error                     { return nil }
func (f *countingFW) SetACME(uint16, time.Duration) error                     { return nil }
func (f *countingFW) SetACMEForward(time.Duration) error                      { return nil }
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

// chanFeed is a feed whose snapshots the test hands over one at a time;
// took says the one before was processed (the next Receive came).
type chanFeed struct {
	in   chan *perimeterv1.Snapshot
	took chan struct{}
	cur  *perimeterv1.Snapshot
}

func (f *chanFeed) Receive() bool {
	if f.cur != nil {
		f.took <- struct{}{}
	}
	s, ok := <-f.in
	f.cur = s
	return ok
}
func (f *chanFeed) Snapshot() *perimeterv1.Snapshot { return f.cur }
func (f *chanFeed) Err() error                      { return nil }
func (f *chanFeed) Close() error                    { return nil }

// rayd learns when rayspa refuses the feed's newest snapshot (refused, in
// ReportGate): set by a snapshot that does not apply, while an earlier one
// stays in force, cleared by the next that does; from_rayd stays as it was.
func TestWatchRefused(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := perimeter.NewGate(&countingFW{}, log)
	g.SetupAtFirstSnapshot()
	feed := &chanFeed{in: make(chan *perimeterv1.Snapshot), took: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	opened := false
	open := func(ctx context.Context) (snapshots, error) {
		if !opened {
			opened = true
			return feed, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var fromRayd, refused atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch(ctx, open, "", g, &perimeter.TCPCarrier{}, nil, &fromRayd, &refused, make(chan struct{}, 1), log)
	}()
	bad := savedSnapshot()
	bad.Spa.PortKey = []byte{1}
	for i, c := range []struct {
		snap               *perimeterv1.Snapshot
		fromRayd, refusing bool
	}{{bad, false, true}, {savedSnapshot(), true, false}, {bad, true, true}, {savedSnapshot(), true, false}} {
		feed.in <- c.snap
		<-feed.took
		if fromRayd.Load() != c.fromRayd || refused.Load() != c.refusing || !g.Up() != (i == 0) {
			t.Errorf("snapshot %d: from rayd %v, refused %v, up %v", i, fromRayd.Load(), refused.Load(), g.Up())
		}
	}
	cancel()
	close(feed.in)
	<-done
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
