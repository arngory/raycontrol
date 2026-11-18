package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// rayctl client min (client-min-v1 §2) against a real rayd API: what a
// flag does not say stays, -unknown refuse takes -yes, none takes one
// product's minimum away and no flags.
func TestClientCommands(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	params, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{Store: st, Params: params, Version: "test"}
	sock := filepath.Join(dir, "rayd.sock")
	served := make(chan error, 1)
	go func() { served <- srv.ServeUnix(ctx, sock, api.PeerPolicy{}) }()
	t.Cleanup(func() {
		cancel()
		<-served
		st.Close()
	})
	for range 100 {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	c := &cli{c: api.NewUnixClient(sock)}
	run := func(args ...string) (string, error) {
		t.Helper()
		return captured(t, func() error { return c.run(ctx, args) })
	}
	policy := func() (map[string]string, int64, bool) {
		t.Helper()
		p, err := node.ClientPolicy(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		return p.Min, p.From, p.RefuseUnknown
	}

	if out, err := run("client"); err != nil || !strings.Contains(out, "none") {
		t.Fatalf("no policy: %q %v", out, err)
	}
	if _, err := run("client", "min", "niko", "1.59.0", "-unknown", "refuse"); err == nil || !strings.Contains(err.Error(), "-yes") {
		t.Fatalf("refuse without -yes: %v", err)
	}
	if min, _, _ := policy(); len(min) != 0 {
		t.Fatalf("refused command set %v", min)
	}
	if _, err := run("client", "min", "niko", "1.59.0", "-from", "2027-01-15", "-unknown", "refuse", "-yes"); err != nil {
		t.Fatal(err)
	}
	from := time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC).Unix()
	if min, f, ru := policy(); min["niko"] != "1.59.0" || f != from || !ru {
		t.Fatalf("set: %v %d %v", min, f, ru)
	}
	// A new version alone keeps the start and the rule for unknown clients.
	if _, err := run("client", "min", "niko", "1.60.0"); err != nil {
		t.Fatal(err)
	}
	if min, f, ru := policy(); min["niko"] != "1.60.0" || f != from || !ru {
		t.Fatalf("bumped: %v %d %v", min, f, ru)
	}
	// Another product joins; the start is shared and said to move.
	out, err := run("client", "min", "other", "2.0.0", "-from", "now")
	if min, f, _ := policy(); err != nil || min["niko"] != "1.60.0" || min["other"] != "2.0.0" || f != 0 || !strings.Contains(out, "moved") {
		t.Fatalf("second product: %v %d %q %v", min, f, out, err)
	}
	if _, err := run("client", "min", "other", "none", "-yes"); err == nil {
		t.Fatal("none with a flag")
	}
	if _, err := run("client", "min", "Niko", "none"); err == nil {
		t.Fatal("an invalid product")
	}
	if _, err := run("client", "min", "other", "none"); err != nil {
		t.Fatal(err)
	}
	if min, _, ru := policy(); len(min) != 1 || min["niko"] != "1.60.0" || !ru {
		t.Fatalf("one taken away: %v %v", min, ru)
	}
	if _, err := run("client", "min", "niko", "none"); err != nil {
		t.Fatal(err)
	}
	if min, f, ru := policy(); len(min) != 0 || f != 0 || ru {
		t.Fatalf("all taken away: %v %d %v", min, f, ru)
	}
	if _, err := run("client", "min", "niko", "none"); err == nil {
		t.Fatal("none for a product without a minimum")
	}
}
