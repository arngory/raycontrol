package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// The update to v0.21.0 (egress-policy-v1 §1, §9): a node with Xray
// services (inner, reality, enabled or not) keeps BitTorrent blocked, now in
// the kernel; any other node, and a new one, has nothing blocked. A value
// the operator set before the migration is kept.
func TestEgressMigration(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name     string
		services []Service
		before   string // egress_bittorrent before the migration
		want     bool
	}{
		{"new node", nil, "", false},
		{"REALITY", []Service{{Kind: "reality", Name: "reality", Enabled: true}}, "", true},
		{"inner for a DNS tunnel", []Service{{Kind: "dnstt", Name: "dns", Enabled: true}, {Kind: "inner", Name: "inner", Enabled: true}}, "", true},
		{"REALITY disabled", []Service{{Kind: "reality", Name: "reality"}}, "", true},
		{"Hysteria2 and naive only", []Service{{Kind: "hy2-masq", Name: "hy2"}, {Kind: "naive", Name: "naive", Enabled: true}}, "", false},
		{"set before", []Service{{Kind: "reality", Name: "reality", Enabled: true}}, "off", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rayd.db")
			s, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			// A node from before v0.21.0: its services, no policy yet.
			if _, err := s.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 11`); err != nil {
				t.Fatal(err)
			}
			for _, svc := range c.services {
				if _, err := s.CreateService(ctx, svc); err != nil {
					t.Fatal(err)
				}
			}
			if c.before != "" {
				s.SetSetting(ctx, settingEgressBitTorrent, []byte(c.before))
			}
			s.Close()
			if s, err = Open(ctx, path); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			e, err := s.Egress(ctx)
			if err != nil || e.BitTorrent != c.want || e.SMTP {
				t.Fatalf("after the update: %+v %v, want bittorrent %v", e, err, c.want)
			}
		})
	}
}

func TestSetEgress(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	on, off := true, false
	for _, c := range []struct {
		bittorrent, smtp *bool
		want             Egress
	}{
		{&on, nil, Egress{BitTorrent: true}},
		{nil, &on, Egress{BitTorrent: true, SMTP: true}},
		{&off, nil, Egress{SMTP: true}},
		{nil, nil, Egress{SMTP: true}},
		{&on, &off, Egress{BitTorrent: true}},
	} {
		got, err := s.SetEgress(ctx, c.bittorrent, c.smtp)
		if err != nil || got != c.want {
			t.Fatalf("set %v %v: %+v %v, want %+v", c.bittorrent, c.smtp, got, err, c.want)
		}
		if stored, _ := s.Egress(ctx); stored != c.want {
			t.Fatalf("stored %+v, want %+v", stored, c.want)
		}
	}
	// Allowed is no setting at all, blocked is "on".
	if _, err := s.GetSetting(ctx, settingEgressSMTP); !errors.Is(err, ErrNotFound) {
		t.Fatalf("smtp allowed: %v", err)
	}
	if v, _ := s.GetSetting(ctx, settingEgressBitTorrent); string(v) != "on" {
		t.Fatalf("bittorrent blocked: %q", v)
	}
}
