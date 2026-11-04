package api

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// TestOlderDatabaseLimits opens a database written before the S-3 checks:
// admin prefixes wider than the limits and a public service on SSH's port.
// The perimeter drops the wide prefixes and gives the broken service no
// port, while the rest keeps working.
func TestOlderDatabaseLimits(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	params, err := provision.Init(ctx, st, provision.Options{Host: "n.example.com", Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, svc := range []store.Service{
		{Kind: "ssh", Name: "ssh", Enabled: true},
		{Kind: "dnstt", Name: "dns", Enabled: true},
		{Kind: "reality", Name: "reality", Enabled: true, Settings: `{"target":"www.example.org:443"}`},
	} {
		if _, err := provision.CreateService(ctx, st, svc); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()

	// What v0.9 accepted and v0.10 refuses on write.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO settings (key, value) VALUES ('admin_access', '["0.0.0.0/0","2001:db8::/32","198.51.100.7/32","2001:db8:1::/48"]')
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		`UPDATE services SET settings_json = json_set(settings_json, '$.ports', json('["udp/53","tcp/22"]')) WHERE name = 'dns'`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	st, err = store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := &Server{Store: st, Params: params}
	snap, err := (&PerimeterServer{Server: srv}).snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot of an older database: %v", err)
	}
	if !slices.Equal(snap.AdminPrefixes, []string{"198.51.100.7/32", "2001:db8:1::/48"}) {
		t.Fatalf("admin prefixes %v", snap.AdminPrefixes)
	}
	for _, p := range snap.PublicPorts {
		if p.Proto == "tcp" {
			t.Fatalf("public %v: the broken DNS service's tcp/22 went public", snap.PublicPorts)
		}
	}
	if len(snap.AdminPorts) != 1 || snap.AdminPorts[0].Port != 22 {
		t.Fatalf("admin ports %v", snap.AdminPorts)
	}
	if !slices.ContainsFunc(snap.Services, func(s *perimeterv1.Service) bool { return len(s.Ports) == 1 && s.Ports[0].Port == 443 }) {
		t.Fatalf("REALITY lost its port: %v", snap.Services)
	}
	if _, _, err := srv.hostPorts(ctx); err != nil {
		t.Fatalf("host ports of an older database: %v", err)
	}
}
