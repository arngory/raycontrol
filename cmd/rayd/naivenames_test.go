package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// rayctl status's naive-names line (docs/research/naive-sni-rotation.md §8.4): a published next name
// that the rendered front does not route is reported; one it routes, and
// a node without published names, are not; a node without naive has no
// line at all.
func TestNaiveServed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	front := filepath.Join(dir, "front.json")
	if naive, err := naiveServed(ctx, st, front); naive || err != nil {
		t.Fatalf("no naive: %v %v", naive, err)
	}
	provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true})
	nv, err := provision.CreateService(ctx, st, store.Service{Kind: "naive", Name: "nv", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if naive, err := naiveServed(ctx, st, front); !naive || err != nil {
		t.Fatalf("nothing published: %v %v", naive, err)
	}
	ns := provision.ParseNaiveState(nv)
	settings := strings.Replace(nv.Settings, "{", `{"next_from":`+strconv.FormatInt(time.Now().Add(72*time.Hour).Unix(), 10)+",", 1)
	if err := st.UpdateService(ctx, nv.ID, store.ServiceUpdate{Settings: settings}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		front string
		bad   bool
	}{
		{"", true}, // no front config at all
		{`{"tcp":{"routes":[{"sni":["` + ns.SNI + `"],"backend":"nv"}]}}`, true},
		{`{"tcp":{"routes":[{"sni":["` + ns.SNINext + `"],"backend":"r"}]}}`, true},
		{`{"tcp":{"routes":[{"sni":["` + ns.SNI + `","` + strings.ToUpper(ns.SNINext) + `"],"backend":"nv"}]}}`, false},
	} {
		os.Remove(front)
		if c.front != "" {
			os.WriteFile(front, []byte(c.front), 0o600)
		}
		_, err := naiveServed(ctx, st, front)
		if (err != nil) != c.bad || c.bad && !strings.Contains(err.Error(), ns.SNINext) {
			t.Errorf("front %s: %v", c.front, err)
		}
	}
	os.WriteFile(front, []byte("{"), 0o600)
	if _, err := naiveServed(ctx, st, front); err == nil {
		t.Error("a broken front config passed")
	}
}

// -naive-sni-period shorter than the lead and the preparation cannot work.
func TestNaiveEpochCheck(t *testing.T) {
	day := 24 * time.Hour
	e := provision.RealityEpoch{Period: 90 * day, Lead: 3 * day, Prepare: day, NaivePeriod: 90 * day}
	if err := e.Check(); err != nil {
		t.Fatal(err)
	}
	e.NaivePeriod = 4 * day
	if err := e.Check(); err == nil {
		t.Fatal("a naive period within the lead and preparation passed")
	}
	e.NaivePeriod = 0 // only by command
	if err := e.Check(); err != nil {
		t.Fatal(err)
	}
}
