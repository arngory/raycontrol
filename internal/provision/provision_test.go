package provision

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/arngory/raycontrol/internal/store"
)

func TestInit(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// DNS tunnels need a domain.
	p, err := Init(ctx, st, Options{Host: "203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("dnstt without domain: %v", err)
	}

	k1, err := LoadNodeKeys(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Init(ctx, st, Options{Domain: "Example.COM"}); err != nil {
		t.Fatal(err)
	}
	k2, _ := LoadNodeKeys(ctx, st)
	if k1.PublicJSON()["ed25519"] != k2.PublicJSON()["ed25519"] || k1.PublicJSON()["mldsa65"] != k2.PublicJSON()["mldsa65"] {
		t.Fatal("node keys changed on repeated init")
	}
	if d, _ := Domain(ctx, st); d != "example.com" {
		t.Fatalf("domain %q", d)
	}

	svc, err := st.ServiceByName(ctx, SubscriptionService)
	if err != nil {
		t.Fatal(err)
	}
	ports, _ := svc.Ports()
	if len(ports) != 1 || ports[0].Proto != "tcp" || (ports[0].Num >= p.PortBase && ports[0].Num < p.PortBase+p.PortRange) {
		t.Fatalf("subscription port %v vs SPA range %d+%d", ports, p.PortBase, p.PortRange)
	}
	secrets, _ := st.ServiceSecrets(ctx, svc.ID)
	if pin, err := SPKIPin(secrets[SecretTLSCert]); err != nil || len(pin) != 43 {
		t.Fatalf("pin %q %v", pin, err)
	}

	a, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := CreateService(ctx, st, store.Service{Kind: "masterdns", Name: "mdns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if Zone(a) == Zone(b) || Zone(a) == "" {
		t.Fatalf("zones %q %q", Zone(a), Zone(b))
	}
	var settings map[string]any
	json.Unmarshal([]byte(b.Settings), &settings)
	if settings["encryption_method"].(float64) != 5 {
		t.Fatalf("masterdns settings %v", settings)
	}
	all, _ := st.ListServices(ctx)
	inner := 0
	for _, s := range all {
		if s.Kind == "inner" {
			inner++
			sec, _ := st.ServiceSecrets(ctx, s.ID)
			if len(sec[SecretMLKEMSeed]) != 64 || s.UID == 0 {
				t.Fatalf("inner %+v secrets %d", s, len(sec[SecretMLKEMSeed]))
			}
		}
	}
	if inner != 1 {
		t.Fatalf("%d inner services", inner)
	}
	if a.UID == b.UID || a.UID < store.FirstServiceUID {
		t.Fatalf("uids %d %d", a.UID, b.UID)
	}

	// UDP services get non-overlapping port schedules outside the SPA range.
	var spans [][2]int
	for _, name := range []string{"hy2a", "hy2b", "hy2c"} {
		s, err := CreateService(ctx, st, store.Service{Kind: "hy2-masq", Name: name, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		rot, ok := ServiceRotation(s)
		sec, _ := st.ServiceSecrets(ctx, s.ID)
		if !ok || len(sec[SecretPortKey]) != 32 || rot.Range < 1024 {
			t.Fatalf("%s rotation %+v key %d", name, rot, len(sec[SecretPortKey]))
		}
		spans = append(spans, [2]int{int(rot.Base), int(rot.Base) + int(rot.Range)})
	}
	spans = append(spans, [2]int{int(p.PortBase), int(p.PortBase) + int(p.PortRange)})
	for i := range spans {
		for j := range spans {
			if i != j && spans[i][0] < spans[j][1] && spans[j][0] < spans[i][1] {
				t.Fatalf("ranges overlap: %v", spans)
			}
		}
	}
	if _, ok := ServiceRotation(a); ok {
		t.Fatal("dnstt must not rotate")
	}
}

func TestACMEPort(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := ACMEPort(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ACMEPort(ctx, st)
	if a != b || a < 20000 || (a >= p.PortBase && int(a) < int(p.PortBase)+int(p.PortRange)) {
		t.Fatalf("acme port %d then %d, SPA %d+%d", a, b, p.PortBase, p.PortRange)
	}
	// Rotation ranges keep clear of it.
	svc, err := CreateService(ctx, st, store.Service{Kind: "hy2-masq", Name: "hy2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := ServiceRotation(svc); ok && a >= r.Base && int(a) < int(r.Base)+int(r.Range) {
		t.Fatalf("rotation %d+%d covers the acme port %d", r.Base, r.Range, a)
	}
}
