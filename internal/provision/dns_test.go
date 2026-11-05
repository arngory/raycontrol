package provision

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/cloudflare"
	"github.com/arngory/raycontrol/internal/cloudflare/cftest"
	"github.com/arngory/raycontrol/internal/store"
)

func TestCloudflareDNS(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	api, c := cftest.New(t)
	old := CloudflareAPI
	CloudflareAPI = c.BaseURL
	defer func() { CloudflareAPI = old }()

	if cl, _, err := Cloudflare(ctx, st); cl != nil || err != nil {
		t.Fatalf("no provider yet: %v %v", cl, err)
	}
	if _, err := SetCloudflare(ctx, st, "bad"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad token: %v", err)
	}
	zone, err := SetCloudflare(ctx, st, " good\n")
	if err != nil || zone.ID != "z1" {
		t.Fatalf("zone %+v %v", zone, err)
	}

	// Without DNS tunnels: the wildcard only.
	changes, problems, err := SyncDNS(ctx, st)
	if err != nil || len(problems) != 0 || !slices.Equal(changes, []string{"created A *.example.com"}) {
		t.Fatalf("sync: %v %v %v", changes, problems, err)
	}
	// A DNS tunnel: a name server name and the delegation of its zone.
	dns, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	changes, _, err = SyncDNS(ctx, st)
	if err != nil || len(changes) != 2 {
		t.Fatalf("tunnel: %v %v", changes, err)
	}
	ns, _ := st.GetSetting(ctx, settingNSName)
	got := strings.Join(api.List(), "\n")
	for _, want := range []string{
		"A *.example.com 203.0.113.7 proxied=false ours=true",
		"A " + string(ns) + " 203.0.113.7 proxied=false ours=true",
		"NS " + Zone(dns) + " " + string(ns) + " proxied=false ours=true",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}

	// The tunnel goes, its delegation with it; then the provider.
	st.DeleteService(ctx, "dns")
	if changes, _, _ = SyncDNS(ctx, st); len(changes) != 2 {
		t.Fatalf("after the tunnel: %v", changes)
	}
	removed, err := RemoveDNS(ctx, st, false)
	if err != nil || len(removed) != 1 || len(api.List()) != 0 {
		t.Fatalf("remove: %v %v %v", removed, err, api.List())
	}
	if cl, _, _ := Cloudflare(ctx, st); cl != nil {
		t.Fatal("provider kept after remove")
	}
}

// NSName is the name the delegation asks for, chosen once whoever asks
// first, and none when the node asks for no delegation (no DNS tunnel, or
// a host that is a name: the operator delegates on their own).
func TestNSName(t *testing.T) {
	ctx := context.Background()
	open := func(host string) *store.Store {
		st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if _, err := Init(ctx, st, Options{Host: host, Domain: "example.com"}); err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := open("203.0.113.7")
	if ns, err := NSName(ctx, st); ns != "" || err != nil {
		t.Fatalf("without a DNS tunnel: %q %v", ns, err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	ns, err := NSName(ctx, st)
	if err != nil || !strings.HasSuffix(ns, ".example.com") {
		t.Fatalf("NS name %q %v", ns, err)
	}
	records, _, _ := DNSRecords(ctx, st)
	if !slices.ContainsFunc(records, func(r cloudflare.Record) bool { return r.Type == "NS" && r.Content == ns }) {
		t.Fatalf("records ask for another name than %s: %+v", ns, records)
	}
	if again, _ := NSName(ctx, st); again != ns {
		t.Fatalf("NS name changed: %s, then %s", ns, again)
	}

	named := open("node.example.com")
	if _, err := CreateService(ctx, named, store.Service{Kind: "dnstt", Name: "dns", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if ns, err := NSName(ctx, named); ns != "" || err != nil {
		t.Fatalf("host a name: %q %v", ns, err)
	}
}
