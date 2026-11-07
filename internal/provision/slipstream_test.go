package provision

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

func slipStore(t *testing.T, domain string) (context.Context, *store.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: domain}); err != nil {
		t.Fatal(err)
	}
	return ctx, st
}

// A new slipstream service (spec/slipstream-v1.md §3): a short zone under
// the node's domain, a random ALPN and server name, a self-signed P-256
// certificate for the name whose key clients pin, the inner stage with it,
// and dnsauth-v2 required, which no option changes.
func TestSlipstreamService(t *testing.T) {
	ctx, st := slipStore(t, "example.com")
	svc, err := CreateService(ctx, st, store.Service{Kind: "slipstream", Name: "slip", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ss, err := ParseSlipstream(svc)
	if err != nil {
		t.Fatalf("settings %s: %v", svc.Settings, err)
	}
	if !strings.HasSuffix(ss.Zone, ".example.com") || len(ss.Zone) > MaxSlipstreamZone {
		t.Errorf("zone %q", ss.Zone)
	}
	if Zone(svc) != ss.Zone || len(Zones(svc)) != 1 {
		t.Errorf("Zone %q, Zones %v", Zone(svc), Zones(svc))
	}
	if ss.ALPN == "picoquic_sample" || ss.SNI == "test.example.com" || strings.Contains(ss.SNI, "example.com") {
		t.Errorf("ALPN %q, server name %q", ss.ALPN, ss.SNI)
	}
	secrets, err := st.ServiceSecrets(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(secrets[SecretTLSCert])
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || len(cert.DNSNames) != 1 || cert.DNSNames[0] != ss.SNI {
		t.Errorf("certificate: %T %v", cert.PublicKey, cert.DNSNames)
	}
	key, err := x509.ParsePKCS8PrivateKey(secrets[SecretTLSKey])
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := key.(*ecdsa.PrivateKey); !ok || !k.PublicKey.Equal(pub) {
		t.Error("the key is not the certificate's")
	}
	if pin, err := SPKIPin(secrets[SecretTLSCert]); err != nil || len(pin) != 43 {
		t.Errorf("pin %q %v", pin, err)
	}
	if _, err := st.ServiceByName(ctx, "inner"); err != nil {
		t.Errorf("no inner stage: %v", err)
	}
	if DNSAuthMode(svc) != "required" || DNSAuthHint(svc) != "required" || DNSSealMode(svc) != "off" {
		t.Errorf("modes %s %s %s", DNSAuthMode(svc), DNSAuthHint(svc), DNSSealMode(svc))
	}
	// Each service its own marks: nothing shared but the form.
	other, err := CreateService(ctx, st, store.Service{Kind: "slipstream", Name: "slip2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	os, _ := ParseSlipstream(other)
	if os.Zone == ss.Zone || os.ALPN == ss.ALPN {
		t.Errorf("two services share %+v", os)
	}
	for _, kv := range [][2]string{{"zone", "x.example.com"}, {"auth", "off"}, {"auth_hint", "optional"}, {"seal", "required"}, {"spare_zones", "1"}} {
		if _, err := SetServiceOption(ctx, st, "slip", kv[0], kv[1]); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("set %s=%s: %v", kv[0], kv[1], err)
		}
	}
	if err := RequestRealityRotation(ctx, st, "slip", time.Now(), time.Hour, false); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Errorf("rotate: %v", err)
	}
}

func TestSlipstreamZones(t *testing.T) {
	ctx, st := slipStore(t, "example.com")
	create := func(name string, settings map[string]any) (store.Service, error) {
		b, _ := json.Marshal(settings)
		return CreateService(ctx, st, store.Service{Kind: "slipstream", Name: name, Enabled: true, Settings: string(b)})
	}
	// A zone of its own, as clients write it: kept canonical.
	svc, err := create("a", map[string]any{"zone": "S.Example.NET."})
	if err != nil {
		t.Fatal(err)
	}
	if Zone(svc) != "s.example.net" {
		t.Errorf("zone %q", Zone(svc))
	}
	for _, tc := range []struct {
		name     string
		settings map[string]any
	}{
		{"long", map[string]any{"zone": "abcdefghij.example.net"}}, // 22: no room for a QUIC Initial
		{"label", map[string]any{"zone": "example"}},
		{"type", map[string]any{"zone": 7}},
		{"same", map[string]any{"zone": "s.example.net"}},
		{"nested", map[string]any{"zone": "x.s.example.net"}},
		{"above", map[string]any{"zone": "example.net"}},
		{"domain", map[string]any{"zone": "example.com"}},
		{"auth", map[string]any{"auth": "optional"}},
		{"hint", map[string]any{"auth_hint": "off"}},
		{"seal", map[string]any{"seal": "required"}},
		{"spare", map[string]any{"spare_zones": 1}},
		{"alpn", map[string]any{"quic_alpn": "picoquicsample"}},
		{"sni", map[string]any{"quic_sni": "test.example.com"}},
	} {
		if _, err := create(tc.name, tc.settings); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s %v: %v", tc.name, tc.settings, err)
		}
	}
	// A dnstt zone nested with it is refused the other way too.
	if _, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true,
		Settings: `{"zone":"t.s.example.net"}`}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("dnstt under the slipstream zone: %v", err)
	}

	// A domain with no room for a zone under it: the service asks for one.
	ctx2, st2 := slipStore(t, "a-rather-long-domain.example")
	if _, err := CreateService(ctx2, st2, store.Service{Kind: "slipstream", Name: "slip", Enabled: true}); err == nil ||
		!strings.Contains(err.Error(), "zone=") {
		t.Errorf("long domain: %v", err)
	}
}

// A client signs one dnsauth version for all of a user's tunnels, and
// slipstream takes v2 only: no tunnel beside it takes v1 only.
func TestSlipstreamAuthHint(t *testing.T) {
	ctx, st := slipStore(t, "example.com")
	if _, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := SetServiceOption(ctx, st, "dns", "auth_hint", "off"); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "slipstream", Name: "slip", Enabled: true}); !errors.Is(err, store.ErrInvalid) ||
		!strings.Contains(err.Error(), "auth_hint off") {
		t.Fatalf("beside auth_hint off: %v", err)
	}
	if _, err := SetServiceOption(ctx, st, "dns", "auth_hint", "optional"); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "slipstream", Name: "slip", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := SetServiceOption(ctx, st, "dns", "auth_hint", "off"); !errors.Is(err, store.ErrInvalid) || !strings.Contains(err.Error(), "slip") {
		t.Errorf("auth_hint off beside slipstream: %v", err)
	}
}

// The node checks a slipstream zone at the front as a dnstt one (apex and
// probes, the front's own), without a poll: the server is a QUIC
// handshake away.
func TestSlipstreamCheckTarget(t *testing.T) {
	ctx, st := slipStore(t, "example.com")
	svc, err := CreateService(ctx, st, store.Service{Kind: "slipstream", Name: "slip", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ns, err := NSName(ctx, st)
	if err != nil || ns == "" {
		t.Fatalf("NS name %q %v", ns, err)
	}
	zones, err := DNSCheckTargets(ctx, st)
	if err != nil || len(zones) != 1 {
		t.Fatalf("%v %v", zones, err)
	}
	z := zones[0]
	if z.Kind != "slipstream" || z.Name != Zone(svc) || z.NS != ns || len(z.ProbeKey) != 32 || z.Auth != "" || len(z.AuthKey) != 0 ||
		z.Seal != "" || z.SvcID != uint16(svc.ID) {
		t.Errorf("target %+v", z)
	}
	records, warnings, err := DNSRecords(ctx, st)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("records: %v, warnings %v", err, warnings)
	}
	delegated := false
	for _, r := range records {
		delegated = delegated || (r.Type == "NS" && r.Name == Zone(svc))
	}
	if !delegated {
		t.Errorf("no NS record for %s in %+v", Zone(svc), records)
	}
}
