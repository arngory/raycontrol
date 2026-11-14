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
			if err != nil || e.BitTorrent != c.want || e.SMTP || !e.Local {
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
	// A node has its own and local networks blocked from the start (R4-38).
	if e, err := s.Egress(ctx); err != nil || e != (Egress{Local: true}) {
		t.Fatalf("a new node: %+v %v", e, err)
	}
	on, off := true, false
	for _, c := range []struct {
		bittorrent, smtp, local *bool
		want                    Egress
	}{
		{&on, nil, nil, Egress{BitTorrent: true, Local: true}},
		{nil, &on, nil, Egress{BitTorrent: true, SMTP: true, Local: true}},
		{&off, nil, nil, Egress{SMTP: true, Local: true}},
		{nil, nil, nil, Egress{SMTP: true, Local: true}},
		{&on, &off, nil, Egress{BitTorrent: true, Local: true}},
		{nil, nil, &off, Egress{BitTorrent: true}},
		{nil, &on, nil, Egress{BitTorrent: true, SMTP: true}},
		{nil, nil, &on, Egress{BitTorrent: true, SMTP: true, Local: true}},
		{nil, nil, &off, Egress{BitTorrent: true, SMTP: true}},
	} {
		got, err := s.SetEgress(ctx, c.bittorrent, c.smtp, c.local)
		if err != nil || got != c.want {
			t.Fatalf("set %v %v %v: %+v %v, want %+v", c.bittorrent, c.smtp, c.local, got, err, c.want)
		}
		if stored, _ := s.Egress(ctx); stored != c.want {
			t.Fatalf("stored %+v, want %+v", stored, c.want)
		}
	}
	// Allowed is no setting at all, blocked is "on"; local the other way.
	if _, err := s.GetSetting(ctx, settingEgressSMTP); err != nil {
		t.Fatalf("smtp blocked: %v", err)
	}
	if v, _ := s.GetSetting(ctx, settingEgressLocal); string(v) != "allow" {
		t.Fatalf("local allowed: %q", v)
	}
	if _, err := s.SetEgress(ctx, nil, &off, &on); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{settingEgressSMTP, settingEgressLocal} {
		if _, err := s.GetSetting(ctx, k); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s at its default: %v", k, err)
		}
	}
	if v, _ := s.GetSetting(ctx, settingEgressBitTorrent); string(v) != "on" {
		t.Fatalf("bittorrent blocked: %q", v)
	}
}
