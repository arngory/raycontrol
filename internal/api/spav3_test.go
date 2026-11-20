package api

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/node"
)

func TestOwnAddrs(t *testing.T) {
	var calls atomic.Int32
	answer := []netip.Addr{netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("::ffff:203.0.113.7"),
		netip.MustParseAddr("127.0.1.1"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("203.0.113.7")}
	var fail atomic.Bool
	old := ownLookup
	t.Cleanup(func() { ownLookup = old })
	ownLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		if fail.Load() || host != "n.example.com" {
			return nil, errors.New("no answer")
		}
		return answer, nil
	}
	ctx := context.Background()
	now := time.Unix(1767225600, 0)
	var o ownAddrs
	if got := o.get(ctx, "198.51.100.4", now); !slices.Equal(got, []string{"198.51.100.4"}) || calls.Load() != 0 {
		t.Fatalf("an address: %v, %d lookups", got, calls.Load())
	}
	if got := o.get(ctx, "", now); got != nil {
		t.Fatalf("no host: %v", got)
	}
	// A name: resolved at once, loopback and link-local left out.
	want := []string{"2001:db8::7", "203.0.113.7"}
	if got := o.get(ctx, "n.example.com", now); !slices.Equal(got, want) || calls.Load() != 1 {
		t.Fatalf("name: %v, %d lookups", got, calls.Load())
	}
	// Within the TTL: no lookup.
	if got := o.get(ctx, "n.example.com", now.Add(ownAddrsTTL-time.Second)); !slices.Equal(got, want) || calls.Load() != 1 {
		t.Fatalf("cached: %v, %d lookups", got, calls.Load())
	}
	// Past it, a failing lookup in the background keeps what was there.
	fail.Store(true)
	later := now.Add(ownAddrsTTL)
	if got := o.get(ctx, "n.example.com", later); !slices.Equal(got, want) {
		t.Fatalf("stale: %v", got)
	}
	waitFor(t, func() bool { o.mu.Lock(); defer o.mu.Unlock(); return !o.running })
	if calls.Load() != 2 || !slices.Equal(o.get(ctx, "n.example.com", later.Add(time.Second)), want) {
		t.Fatalf("after a failure: %d lookups", calls.Load())
	}
	// A failure is tried again a minute later, not every snapshot.
	if calls.Load() != 2 {
		t.Fatalf("retried at once: %d", calls.Load())
	}
	// Another host: what the old one had is gone.
	if got := o.get(ctx, "other.example.com", later); got != nil {
		t.Fatalf("other host: %v", got)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for range 200 {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestRelaySPA(t *testing.T) {
	r := &Remote{}
	if r.RelaySPA("r1") != nil {
		t.Fatal("unknown relay has versions")
	}
	r.setRelaySPA("r1", []uint32{3, 2, 3, 9})
	if got := r.RelaySPA("r1"); !slices.Equal(got, []int{2, 3}) {
		t.Fatalf("got %v", got)
	}
	// An older rayspa after a rollback: v2 only, listed as none.
	r.setRelaySPA("r1", nil)
	if got := r.RelaySPA("r1"); got != nil {
		t.Fatalf("after rollback %v", got)
	}
	r.setRelaySPA("r1", []uint32{2})
	if got := r.RelaySPA("r1"); got != nil {
		t.Fatalf("v2 only %v", got)
	}
}

// TestSnapshotOwnAddrs: the node's snapshot names its -host address; a
// relay's names the relay's own.
func TestSnapshotOwnAddrs(t *testing.T) {
	srv, _, _ := startServer(t)
	ctx := context.Background()
	p := &PerimeterServer{Server: srv, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour}
	// The test node's -host is a name nothing resolves.
	if snap, err := p.snapshot(ctx); err != nil || len(snap.OwnAddrs) != 0 {
		t.Fatalf("name: %v %v", snap.GetOwnAddrs(), err)
	}
	if _, err := node.Init(ctx, srv.Store, "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	if snap, err := p.snapshot(ctx); err != nil || !slices.Equal(snap.OwnAddrs, []string{"203.0.113.7"}) {
		t.Fatalf("address: %v %v", snap.GetOwnAddrs(), err)
	}
	if _, err := srv.Store.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if snap, err := p.RelaySnapshot(ctx, "r1"); err != nil || !slices.Equal(snap.OwnAddrs, []string{"198.51.100.20"}) {
		t.Fatalf("relay: %v %v", snap.GetOwnAddrs(), err)
	}
	// The bundle offers v3.
	if sp := srv.nodeSPA(ctx); !slices.Equal(sp.Versions, []int{2, 3}) {
		t.Fatalf("bundle versions %v", sp.Versions)
	}
}

// TestSPAVersionsOffered: v3 only where a v3 packet to the node's public
// address can pass (spa-v3 §5).
func TestSPAVersionsOffered(t *testing.T) {
	srv, _, _ := startServer(t)
	ctx := context.Background()
	old := ownLookup
	t.Cleanup(func() { ownLookup = old })
	answers := map[string][]netip.Addr{
		"public.example.com": {netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("203.0.113.7")},
		"split.example.com":  {netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("fd00::5"), netip.MustParseAddr("100.64.1.2")},
	}
	ownLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, ok := answers[host]; ok {
			return a, nil
		}
		return nil, errors.New("no answer")
	}
	for _, c := range []struct {
		host string
		v3   bool
	}{
		{"203.0.113.7", true},
		{"2001:db8::7", true},
		{"public.example.com", true},
		{"split.example.com", false}, // behind 1:1 NAT, split-horizon: no public address known
		{"nothing.example.com", false},
		{"0.0.0.0", false},
		{"10.0.0.5", false}, // a private -host: no public address either
	} {
		if _, err := node.Init(ctx, srv.Store, c.host); err != nil {
			t.Fatal(err)
		}
		got := srv.SPAVersions(ctx)
		if c.v3 != slices.Equal(got, []int{2, 3}) || !c.v3 && got != nil {
			t.Errorf("%s: %v", c.host, got)
		}
	}
	// The snapshot keeps private own addresses (they are where packets
	// come to behind NAT) but drops an unspecified one.
	if _, err := node.Init(ctx, srv.Store, "0.0.0.0"); err != nil {
		t.Fatal(err)
	}
	p := &PerimeterServer{Server: srv, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour}
	if snap, err := p.snapshot(ctx); err != nil || snap.OwnAddrs != nil {
		t.Fatalf("0.0.0.0 → %v %v", snap.GetOwnAddrs(), err)
	}
}
