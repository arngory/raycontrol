package provision

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
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

func TestSiteAnswer(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com"})
	if _, err := CreateService(ctx, st, store.Service{Kind: "site", Name: "bad", Enabled: true, Settings: `{"answer":"teapot"}`}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("unknown answer: %v", err)
	}
	svc, err := CreateService(ctx, st, store.Service{Kind: "site", Name: "site", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if SiteAnswer(svc) != "404" || !strings.Contains(svc.Settings, `"answer":"404"`) {
		t.Fatalf("default answer: %s", svc.Settings)
	}
	if svc, err = SetServiceOption(ctx, st, "site", "answer", "silent"); err != nil || SiteAnswer(svc) != "silent" {
		t.Fatalf("set answer: %v %s", err, svc.Settings)
	}
	for _, kv := range [][2]string{{"answer", "teapot"}, {"sni", "x.example.com"}, {"rotate_sni", "false"}} {
		if _, err := SetServiceOption(ctx, st, "site", kv[0], kv[1]); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("site %s=%s: %v", kv[0], kv[1], err)
		}
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	r, err := SetServiceOption(ctx, st, "r", "rotate_sni", "false")
	if err != nil || ParseRealityState(r).RotateSNI == nil || *ParseRealityState(r).RotateSNI {
		t.Fatalf("rotate_sni: %v %s", err, r.Settings)
	}
	if r, err = SetServiceOption(ctx, st, "r", "rotate_sni", "true"); err != nil || !*ParseRealityState(r).RotateSNI {
		t.Fatalf("rotate_sni back on: %v %s", err, r.Settings)
	}
}

func TestHysteriaServices(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, _ := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com"})
	masq, err := CreateService(ctx, st, store.Service{Kind: "hy2-masq", Name: "hy2-masq", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	obfs, err := CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2-obfs", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal("no site created for Hysteria2's certificate")
	}
	// Both on UDP 443: the front tells them apart (udpmux, R3-4); each has
	// its own port schedule.
	mp, _ := masq.Ports()
	op, _ := obfs.Ports()
	if len(mp) != 1 || mp[0] != (store.Port{Proto: "udp", Num: 443}) || len(op) != 1 || op[0] != (store.Port{Proto: "udp", Num: 443}) {
		t.Fatalf("ports: masq %v, obfs %v", mp, op)
	}
	rm, ok1 := ServiceRotation(masq)
	ro, ok2 := ServiceRotation(obfs)
	if !ok1 || !ok2 || (rm.Base < ro.Base+ro.Range && ro.Base < rm.Base+rm.Range) ||
		(rm.Base < p.PortBase+p.PortRange && p.PortBase < rm.Base+rm.Range) {
		t.Fatalf("rotations: masq %+v, obfs %+v, SPA %d+%d", rm, ro, p.PortBase, p.PortRange)
	}
	// hy2-masq: under the site's certificate. hy2-obfs: its own, self-signed,
	// with a name that is in no DNS.
	all, _ := st.ListServices(ctx)
	names, _ := SiteNames(site, all)
	var sni struct{ SNI string }
	json.Unmarshal([]byte(masq.Settings), &sni)
	if SiteOf(masq) != "site" || !strings.HasSuffix(sni.SNI, ".example.com") || !slices.Contains(names, sni.SNI) {
		t.Fatalf("masq: name %q, site certificate %v", sni.SNI, names)
	}
	json.Unmarshal([]byte(obfs.Settings), &sni)
	secrets, _ := st.ServiceSecrets(ctx, obfs.ID)
	cert, err := x509.ParseCertificate(secrets[SecretTLSCert])
	if SiteOf(obfs) != "" || !strings.HasSuffix(sni.SNI, ".invalid") || slices.Contains(names, sni.SNI) || err != nil ||
		cert.VerifyHostname(sni.SNI) != nil || len(secrets[SecretTLSKey]) == 0 {
		t.Fatalf("obfs: name %q, certificate %v", sni.SNI, err)
	}
	if len(secrets[SecretObfsPassword]) < 32 {
		t.Fatalf("salamander password %q", secrets[SecretObfsPassword])
	}
}

// DoH rides on REALITY's TCP 443 through the node's site (R3-2).
func TestDoHService(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com"})
	if _, err := CreateService(ctx, st, store.Service{Kind: "doh", Name: "doh", Enabled: true}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("DoH without REALITY: %v", err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	d, err := CreateService(ctx, st, store.Service{Kind: "doh", Name: "doh", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ports, _ := d.Ports()
	site, _ := st.ServiceByName(ctx, "site")
	all, _ := st.ListServices(ctx)
	names, _ := SiteNames(site, all)
	var sni struct{ SNI string }
	json.Unmarshal([]byte(d.Settings), &sni)
	// TCP 443 and UDP 443 (DoH3), both behind the front.
	if SiteOf(d) != "site" || !slices.Equal(ports, []store.Port{{Proto: "tcp", Num: 443}, {Proto: "udp", Num: 443}}) || !slices.Contains(names, sni.SNI) {
		t.Fatalf("doh: %s, ports %v, site names %v", d.Settings, ports, names)
	}
	// A schedule only with a UDP port: DoH and naive on UDP 443 too (DoH3,
	// naive-quic) have one, like Hysteria2; a TCP-only service would not.
	n, err := CreateService(ctx, st, store.Service{Kind: "naive", Name: "naive", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	tcpOnly, err := CreateService(ctx, st, store.Service{Kind: "naive", Name: "naive2", Enabled: true, Settings: `{"ports":["tcp/443"]}`})
	if err != nil {
		t.Fatal(err)
	}
	h, err := CreateService(ctx, st, store.Service{Kind: "hy2-masq", Name: "hy2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, svc := range []store.Service{d, n, h} {
		if _, ok := ServiceRotation(svc); !ok {
			t.Errorf("%s has no UDP schedule: %s", svc.Kind, svc.Settings)
		}
	}
	if _, ok := ServiceRotation(tcpOnly); ok || strings.Contains(tcpOnly.Settings, "udp_rotation") || len(tcpOnly.Secrets[SecretPortKey]) != 0 {
		t.Errorf("a TCP-only service has a UDP schedule: %s", tcpOnly.Settings)
	}
}
