package main

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// The processes rayd reads the refusals of (spec/conn-limit-v1.md §7):
// every enabled naive, Hysteria2 and Xray service (the inner stage of the
// DNS tunnels too), none of the others; Xray's runs told apart by their
// start (traffic.SameBoot), the others' by their boot. Not running here,
// each read fails, which the monitor takes as nothing new.
func TestConnLimitSources(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, svc := range []store.Service{
		{Kind: "dnstt", Name: "dns", Enabled: true},
		{Kind: "reality", Name: "r", Enabled: true},
		{Kind: "naive", Name: "nv", Enabled: true},
		{Kind: "hy2-obfs", Name: "ho", Enabled: true},
		{Kind: "hy2-masq", Name: "hm", Enabled: false},
		{Kind: "yggdrasil", Name: "ygg", Enabled: true},
	} {
		if _, err := provision.CreateService(ctx, st, svc); err != nil {
			t.Fatal(err)
		}
	}
	paths := render.Paths{Rendered: t.TempDir(), Run: t.TempDir()}
	sources, err := connLimitSources(st, paths)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names, xray []string
	for _, s := range sources {
		names = append(names, s.Service)
		if s.SameRun != nil {
			xray = append(xray, s.Service)
		}
		if _, err := s.Read(ctx); err == nil {
			t.Errorf("%s: read with nothing running", s.Service)
		}
	}
	slices.Sort(names)
	slices.Sort(xray)
	if !slices.Equal(names, []string{"ho", "inner", "nv", "r"}) || !slices.Equal(xray, []string{"inner", "r"}) {
		t.Fatalf("sources %v, Xray %v", names, xray)
	}
}
