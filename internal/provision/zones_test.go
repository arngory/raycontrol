package provision

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// Spare zones of a DNS tunnel (spec/dnszones-v1.md §4, §5): a number of
// zones made up in the node's domain, or the operator's own; none twice or
// nested; a spare becomes the main zone; each is delegated and checked as
// the main one.
func TestSpareZones(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	dns, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true, Settings: `{"zone":"t.example.com"}`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "masterdns", Name: "mdns", Enabled: true, Settings: `{"zone":"m.example.com"}`}); err != nil {
		t.Fatal(err)
	}
	if got := SpareZones(dns); len(got) != 0 || !slices.Equal(Zones(dns), []string{"t.example.com"}) {
		t.Fatalf("a new service's zones: %v %v", got, Zones(dns))
	}
	set := func(name, key, value string) (store.Service, error) {
		t.Helper()
		return SetServiceOption(ctx, st, name, key, value)
	}

	// Two made up: in the node's domain, apart from every other zone.
	svc, err := set("dns", "spare_zones", "2")
	spares := SpareZones(svc)
	if err != nil || len(spares) != 2 || spares[0] == spares[1] {
		t.Fatalf("spare_zones=2: %v %v", spares, err)
	}
	for _, z := range spares {
		if !strings.HasSuffix(z, ".example.com") || strings.Count(z, ".") != 2 || zonesClash(z, "t.example.com") || zonesClash(z, "m.example.com") {
			t.Fatalf("made-up spare %q", z)
		}
	}
	// Three keep the two; one keeps the first.
	if svc, err = set("dns", "spare_zones", "3"); err != nil || len(SpareZones(svc)) != 3 || !slices.Equal(SpareZones(svc)[:2], spares) {
		t.Fatalf("spare_zones=3: %v %v", SpareZones(svc), err)
	}
	if svc, err = set("dns", "spare_zones", "1"); err != nil || !slices.Equal(SpareZones(svc), spares[:1]) {
		t.Fatalf("spare_zones=1: %v %v", SpareZones(svc), err)
	}
	// The operator's own, canonical.
	if svc, err = set("dns", "spare_zones", "A.Example.NET., b.example.org"); err != nil ||
		!slices.Equal(Zones(svc), []string{"t.example.com", "a.example.net", "b.example.org"}) {
		t.Fatalf("own spares: %v %v", Zones(svc), err)
	}
	ns, _ := NSName(ctx, st)
	for _, bad := range []string{
		"5", "-1", "bad name", "a.example.net,a.example.net", "t.example.com", "x.t.example.com", "example.com",
		"m.example.com", "x.m.example.com", ns, "a.ex.com,b.ex.com,c.ex.com,d.ex.com,e.ex.com", strings.Repeat("a.", 126) + "com",
	} {
		if _, err := set("dns", "spare_zones", bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("spare_zones=%s: %v", bad, err)
		}
	}
	// Another service may not take them either.
	if _, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns2", Enabled: true, Settings: `{"zone":"x.a.example.net"}`}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("a zone within another service's spare: %v", err)
	}
	if _, err := set("mdns", "spare_zones", "b.example.org"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("a spare of another service: %v", err)
	}

	// Delegated and checked as the main one, the spares by name.
	records, _, err := DNSRecords(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	var delegated []string
	for _, r := range records {
		if r.Type == "NS" {
			delegated = append(delegated, r.Name+">"+r.Content)
		}
	}
	slices.Sort(delegated)
	want := []string{"a.example.net>" + ns, "b.example.org>" + ns, "m.example.com>" + ns, "t.example.com>" + ns}
	if !slices.Equal(delegated, want) {
		t.Fatalf("NS records %v, want %v", delegated, want)
	}
	targets, err := DNSCheckTargets(ctx, st)
	if err != nil || len(targets) != 4 {
		t.Fatalf("targets %+v %v", targets, err)
	}
	for _, z := range targets[:3] {
		main := targets[0]
		if z.Service != "dns" || z.Spare != (z.Name != "t.example.com") || string(z.ProbeKey) != string(main.ProbeKey) ||
			string(z.AuthKey) != string(main.AuthKey) || z.Auth != main.Auth || z.NS != ns {
			t.Fatalf("target %+v", z)
		}
	}
	if targets[1].Name != "a.example.net" || targets[2].Name != "b.example.org" || targets[3].Service != "mdns" || targets[3].Spare {
		t.Fatalf("targets %+v", targets)
	}

	// A spare becomes the main zone; the main one leaves. Only a spare:
	// clients must have a zone before it is the main one.
	if _, err := set("dns", "zone", "c.example.net"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("zone= not a spare: %v", err)
	}
	if svc, err = set("dns", "zone", "B.example.org."); err != nil || !slices.Equal(Zones(svc), []string{"b.example.org", "a.example.net"}) {
		t.Fatalf("promoted: %v %v", Zones(svc), err)
	}
	if svc, err = set("dns", "zone", "a.example.net"); err != nil || !slices.Equal(Zones(svc), []string{"a.example.net"}) ||
		strings.Contains(svc.Settings, "spare_zones") {
		t.Fatalf("the last spare promoted: %v %s %v", Zones(svc), svc.Settings, err)
	}
	// none removes them.
	if _, err = set("dns", "spare_zones", "q.example.net"); err != nil {
		t.Fatal(err)
	}
	if svc, err = set("dns", "spare_zones", "none"); err != nil || len(SpareZones(svc)) != 0 || strings.Contains(svc.Settings, "spare_zones") {
		t.Fatalf("none: %s %v", svc.Settings, err)
	}

	// At creation: a number or the zones, as service set takes them.
	c, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns3", Enabled: true, Settings: `{"spare_zones":2}`})
	if err != nil || len(SpareZones(c)) != 2 || len(Zones(c)) != 3 {
		t.Fatalf("created with 2 spares: %v %v", Zones(c), err)
	}
	c, err = CreateService(ctx, st, store.Service{Kind: "masterdns", Name: "mdns2", Enabled: true, Settings: `{"zone":"n.example.com","spare_zones":["S.example.info."]}`})
	if err != nil || !slices.Equal(Zones(c), []string{"n.example.com", "s.example.info"}) {
		t.Fatalf("created with own spares: %v %v", Zones(c), err)
	}
	for i, bad := range []string{`{"spare_zones":"2"}`, `{"spare_zones":[1]}`, `{"zone":"o.example.com","spare_zones":["x.o.example.com"]}`} {
		if _, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "badspare" + string(rune('a'+i)), Enabled: true, Settings: bad}); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// Review 13: a zone may not take the node's own names (its domain, the
// name the zones are delegated to, a service's server name); a zone stored
// at the domain before (v0.13 took it) makes the search for a free name
// fail, not spin.
func TestZonesAndNodeNames(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "n.example.com"}); err != nil {
		t.Fatal(err)
	}
	site, err := CreateService(ctx, st, store.Service{Kind: "site", Name: "site", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	dns, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ns, err := NSName(ctx, st)
	if err != nil || ns == "" {
		t.Fatalf("ns %q %v", ns, err)
	}
	for i, bad := range []string{"n.example.com", "example.com", ns, SiteName(site)} {
		if _, err := CreateService(ctx, st, store.Service{Kind: "masterdns", Name: "m" + string(rune('a'+i)), Enabled: true,
			Settings: `{"zone":"` + bad + `"}`}); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("zone %s: %v", bad, err)
		}
		if _, err := SetServiceOption(ctx, st, "dns", "spare_zones", bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("spare zone %s: %v", bad, err)
		}
	}
	// A zone under a server name takes nothing from it.
	if _, err := CreateService(ctx, st, store.Service{Kind: "masterdns", Name: "under", Enabled: true,
		Settings: `{"zone":"t.` + SiteName(site) + `"}`}); err != nil {
		t.Fatalf("a zone under the site's name: %v", err)
	}
	_ = dns

	// A zone at the domain, stored as v0.13 took it: no free name, an
	// error in time.
	if _, err := st.CreateService(ctx, store.Service{Kind: "masterdns", Name: "old", Enabled: true, Settings: `{"zone":"n.example.com"}`}); err != nil {
		t.Fatal(err)
	}
	all, err := st.ListServices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := newZone(ctx, st, all); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, store.ErrInvalid) || !strings.Contains(err.Error(), "the zone of old holds the domain") {
			t.Fatalf("no free name: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the search for a free zone does not end")
	}
}

// Two creates at once with one zone: one of them only (review 13: each
// checked the zone against a list without the other's).
func TestCreateServiceZoneRace(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	for _, name := range []string{"a", "b"} {
		go func() {
			_, err := CreateService(ctx, st, store.Service{Kind: "masterdns", Name: name, Enabled: true, Settings: `{"zone":"race.example.net"}`})
			errs <- err
		}()
	}
	ok := 0
	for range 2 {
		if err := <-errs; err == nil {
			ok++
		} else if !errors.Is(err, store.ErrInvalid) {
			t.Fatal(err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d creates took the zone", ok)
	}
}
