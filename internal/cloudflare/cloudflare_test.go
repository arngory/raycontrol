package cloudflare_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/cloudflare"
	"github.com/arngory/raycontrol/internal/cloudflare/cftest"
)

func TestVerifyAndZone(t *testing.T) {
	ctx := context.Background()
	_, c := cftest.New(t)
	if err := c.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if z, err := c.ZoneFor(ctx, "node.example.com"); err != nil || z.ID != "z1" {
		t.Fatalf("zone %+v %v", z, err)
	}
	if _, err := c.ZoneFor(ctx, "example.org"); err == nil {
		t.Fatal("a zone the token cannot see")
	}
	bad := *c
	bad.Token = "bad"
	if err := bad.Verify(ctx); err == nil || !strings.Contains(err.Error(), "Invalid API Token") {
		t.Fatalf("bad token: %v", err)
	}
}

func TestSync(t *testing.T) {
	ctx := context.Background()
	f, c := cftest.New(t)
	f.Add(cloudflare.Record{Type: "MX", Name: "example.com", Content: "mail.example.com"}) // the owner's own records stay
	desired := []cloudflare.Record{
		{Type: "A", Name: "*.example.com", Content: "203.0.113.7"},
		{Type: "A", Name: "k3f.example.com", Content: "203.0.113.7"},
		{Type: "NS", Name: "t1.example.com", Content: "k3f.example.com"},
	}
	changes, conflicts, err := cloudflare.Sync(ctx, c, "z1", desired)
	if err != nil || len(changes) != 3 || len(conflicts) != 0 {
		t.Fatalf("first sync: %v %v %v", changes, conflicts, err)
	}
	want := []string{
		"A *.example.com 203.0.113.7 proxied=false ours=true",
		"A k3f.example.com 203.0.113.7 proxied=false ours=true",
		"MX example.com mail.example.com proxied=false ours=false",
		"NS t1.example.com k3f.example.com proxied=false ours=true",
	}
	if got := f.List(); !slices.Equal(got, want) {
		t.Fatalf("records:\n%s", strings.Join(got, "\n"))
	}
	if changes, _, _ := cloudflare.Sync(ctx, c, "z1", desired); len(changes) != 0 {
		t.Fatalf("second sync changed %v", changes)
	}

	// The node moved; a tunnel zone is gone.
	desired = []cloudflare.Record{{Type: "A", Name: "*.example.com", Content: "198.51.100.9"}, {Type: "A", Name: "k3f.example.com", Content: "198.51.100.9"}}
	changes, _, err = cloudflare.Sync(ctx, c, "z1", desired)
	if err != nil || !slices.Equal(changes, []string{"updated A *.example.com", "updated A k3f.example.com", "removed NS t1.example.com"}) {
		t.Fatalf("move: %v %v", changes, err)
	}

	if removed, err := cloudflare.RemoveOwn(ctx, c, "z1"); err != nil || len(removed) != 2 {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if got := f.List(); !slices.Equal(got, []string{"MX example.com mail.example.com proxied=false ours=false"}) {
		t.Fatalf("after remove: %v", got)
	}
}

func TestSyncConflicts(t *testing.T) {
	ctx := context.Background()
	f, c := cftest.New(t)
	on := true
	f.Add(cloudflare.Record{Type: "A", Name: "*.example.com", Content: "104.16.0.1", Proxied: &on})
	f.Add(cloudflare.Record{Type: "A", Name: "k3f.example.com", Content: "203.0.113.7"}) // already right: serves
	f.Add(cloudflare.Record{Type: "CNAME", Name: "t1.example.com", Content: "elsewhere.example.net"})
	changes, conflicts, err := cloudflare.Sync(ctx, c, "z1", []cloudflare.Record{
		{Type: "A", Name: "*.example.com", Content: "203.0.113.7"},
		{Type: "A", Name: "k3f.example.com", Content: "203.0.113.7"},
		{Type: "NS", Name: "t1.example.com", Content: "k3f.example.com"},
	})
	if err != nil || len(changes) != 0 || len(conflicts) != 2 || !strings.Contains(conflicts[0], "proxied") {
		t.Fatalf("changes %v conflicts %v err %v", changes, conflicts, err)
	}
	if len(f.List()) != 3 {
		t.Fatalf("records touched: %v", f.List())
	}
}

func TestSolver(t *testing.T) {
	ctx := context.Background()
	f, c := cftest.New(t)
	s := &cloudflare.Solver{Client: c, Zone: cloudflare.Zone{ID: "z1"}, Poll: 1, LookupTXT: func(_ context.Context, fqdn string) ([]string, error) {
		var out []string
		for _, r := range f.Snapshot() {
			if r.Type == "TXT" && r.Name == fqdn {
				out = append(out, r.Content)
			}
		}
		return out, nil
	}}
	if err := s.Present(ctx, "_acme-challenge.example.com", "v1"); err != nil {
		t.Fatal(err)
	}
	if got := f.List(); !slices.Equal(got, []string{"TXT _acme-challenge.example.com v1 proxied=false ours=true"}) {
		t.Fatalf("records %v", got)
	}
	if err := s.CleanUp(ctx, "_acme-challenge.example.com", "v1"); err != nil || len(f.List()) != 0 {
		t.Fatalf("cleanup: %v %v", err, f.List())
	}
}
