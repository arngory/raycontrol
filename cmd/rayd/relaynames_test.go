package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/testca"
)

// fakeResolver answers names from its table, never the network.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	asked   int
}

func (f *fakeResolver) lookup(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked++
	if network != "ip" {
		return nil, errors.New("not both families")
	}
	a, ok := f.answers[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return a, nil
}

func (f *fakeResolver) set(host string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[host] = nil
	for _, a := range addrs {
		f.answers[host] = append(f.answers[host], netip.MustParseAddr(a))
	}
}

// relay-names-v1 §4, §5: a relay's name is ready once the certificate of
// its service's site covers it and it resolves to the relay's address
// alone; the wildcard's answer (the exit's address) or an answer with it
// is not, nor a name the certificate does not cover. A name that goes
// leaves the state.
func TestRelayNamesReady(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"reality", "naive"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: kind, Name: kind, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRelayCertPin(ctx, "r1", "pin"); err != nil {
		t.Fatal(err)
	}
	names, err := provision.RelayNames(ctx, st)
	if err != nil || len(names) != 2 {
		t.Fatalf("names %v %v", names, err)
	}
	reality, naive := names[0].Name, names[1].Name
	cert := func(names ...string) {
		t.Helper()
		c, err := testca.New(names, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		site, _ := st.ServiceByName(ctx, "site")
		if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{provision.SecretTLSChain: c.ChainPEM}}); err != nil {
			t.Fatal(err)
		}
	}
	res := &fakeResolver{answers: map[string][]netip.Addr{}}
	c := newRelayNameCheck(st, res.lookup)
	if ready, why := c.Status(reality); ready || why != "not checked yet" {
		t.Fatalf("before a check: %v %q", ready, why)
	}
	check := func() {
		t.Helper()
		if err := c.check(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// A certificate of listed names, without them (no DNS provider: stage
	// 2 puts them in): not ready, whatever they resolve to.
	site, _ := st.ServiceByName(ctx, "site")
	cert(provision.SiteName(site))
	res.set(reality, "198.51.100.20")
	check()
	if ready, why := c.Status(reality); ready || !strings.Contains(why, "does not cover it") {
		t.Fatalf("no wildcard: %v %q", ready, why)
	}

	// The wildcard: ready where the name resolves to the relay alone.
	cert("*.example.com")
	res.set(naive, "203.0.113.7") // the wildcard's answer, before the record
	check()
	if !c.Ready(reality) || !c.Ready(strings.ToUpper(reality)+".") {
		t.Fatalf("reality's name: %v", c.Ready(reality))
	}
	if ready, why := c.Status(naive); ready || !strings.Contains(why, "resolves to 203.0.113.7, not to the relay's 198.51.100.20") {
		t.Fatalf("naive's name, the exit's address: %v %q", ready, why)
	}
	res.set(naive, "198.51.100.20", "203.0.113.7")
	check()
	if c.Ready(naive) {
		t.Fatal("naive's name with the exit's address beside the relay's")
	}
	// A stray AAAA (the wildcard's, of an exit with IPv6): not ready.
	res.set(naive, "198.51.100.20", "2001:db8::7")
	check()
	if ready, why := c.Status(naive); ready || !strings.Contains(why, "2001:db8::7") {
		t.Fatalf("naive's name with an AAAA beside the relay's address: %v %q", ready, why)
	}
	res.set(naive, "198.51.100.20")
	check()
	if !c.Ready(naive) {
		t.Fatal("naive's name, the relay's address alone")
	}
	delete(res.answers, naive)
	check()
	if ready, why := c.Status(naive); ready || !strings.Contains(why, "does not resolve") {
		t.Fatalf("naive's name, no answer: %v %q", ready, why)
	}

	// The relay gone: its names leave the state.
	if err := st.DeleteRelay(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	check()
	if ready, why := c.Status(reality); ready || why != "not checked yet" {
		t.Fatalf("after the relay: %v %q", ready, why)
	}
}

// The loop checks at its start, after a change and when the DNS sync
// woke it.
func TestRelayNamesRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRelayCertPin(ctx, "r1", "pin"); err != nil {
		t.Fatal(err)
	}
	res := &fakeResolver{answers: map[string][]netip.Addr{}}
	c := newRelayNameCheck(st, res.lookup)
	changed := make(chan struct{})
	var mu sync.Mutex
	changes := func() <-chan struct{} { mu.Lock(); defer mu.Unlock(); return changed }
	change := func() { mu.Lock(); defer mu.Unlock(); close(changed); changed = make(chan struct{}) }
	cert, err := testca.New([]string{"*.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	site, _ := st.ServiceByName(ctx, "site")
	if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{provision.SecretTLSChain: cert.ChainPEM}}); err != nil {
		t.Fatal(err)
	}
	go c.run(ctx, changes, slog.New(slog.NewTextHandler(io.Discard, nil)))
	asked := func(n int) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			res.mu.Lock()
			got := res.asked
			res.mu.Unlock()
			if got >= n {
				return
			}
		}
		t.Fatalf("lookups: fewer than %d", n)
	}
	asked(1)
	change()
	asked(2)
	c.Wake()
	asked(3)
}
