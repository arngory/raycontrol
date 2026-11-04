package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

func TestParseExpiry(t *testing.T) {
	now := time.Unix(1767225600, 0)
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"2026-12-31", time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC).Unix(), false},
		{"30d", now.Add(30 * 24 * time.Hour).Unix(), false},
		{"12h", now.Add(12 * time.Hour).Unix(), false},
		{"0d", 0, true},
		{"-5h", 0, true},
		{"soon", 0, true},
	}
	for _, tt := range tests {
		got, err := parseExpiry(tt.in, now)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("parseExpiry(%q) = %d, %v", tt.in, got, err)
		}
	}
}

func TestBytes(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"1024", 1024, false},
		{"50G", 50 << 30, false},
		{"500m", 500 << 20, false},
		{"2T", 2 << 40, false},
		{"0", 0, true},
		{"-1G", 0, true},
		{"lots", 0, true},
		{"99999999999T", 0, true},
	}
	for _, tt := range tests {
		got, err := parseBytes(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("parseBytes(%q) = %d, %v", tt.in, got, err)
		}
	}
	for _, n := range []int64{50 << 30, 500 << 20, 1500} {
		back, _ := parseBytes(formatBytes(n))
		if back != n {
			t.Errorf("formatBytes(%d) = %s does not round-trip", n, formatBytes(n))
		}
	}
}

func TestUpdateWarnings(t *testing.T) {
	if !versionLess("6.1.0-27-amd64", "6.1.0-28-amd64") || versionLess("6.12.9", "6.2.1") || !versionLess("5.14.0-427.el9", "5.14.0-503.el9") {
		t.Fatal("versionLess")
	}
	root := t.TempDir()
	for _, d := range []string{"/lib/modules/6.1.0-27-amd64", "/lib/modules/6.1.0-28-amd64", "/etc/apt/apt.conf.d", "/usr/bin"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	w := strings.Join(updateWarnings(root, "6.1.0-27-amd64"), "\n")
	if !strings.Contains(w, "kernel 6.1.0-28-amd64 is installed but 6.1.0-27-amd64 is running") || !strings.Contains(w, "not installed automatically") {
		t.Fatalf("warnings:\n%s", w)
	}
	os.WriteFile(filepath.Join(root, "/etc/apt/apt.conf.d/20auto-upgrades"), []byte("APT::Periodic::Unattended-Upgrade \"1\";\n"), 0o644)
	os.WriteFile(filepath.Join(root, "/usr/bin/unattended-upgrade"), nil, 0o755)
	if w := updateWarnings(root, "6.1.0-28-amd64"); len(w) != 0 {
		t.Fatalf("up to date: %v", w)
	}
}

func TestInstallServices(t *testing.T) {
	parse := func(args ...string) ([]serviceKind, error) {
		fs := flag.NewFlagSet("install", flag.ContinueOnError)
		services := fs.String("services", "", "")
		domain := fs.String("domain", "", "")
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return installServices(*services, *domain, fs)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, ""},
		{[]string{"-domain", "example.com"}, "reality:reality"},
		{[]string{"-domain", "example.com", "-services", "none"}, ""},
		{[]string{"-domain", "example.com", "-services", ""}, ""},
		{[]string{"-domain", "example.com", "-services", "reality,dnstt,masterdns"}, "reality:reality dnstt:dns masterdns:mdns"},
	} {
		got, err := parse(c.args...)
		var s []string
		for _, k := range got {
			s = append(s, k.kind+":"+k.name)
		}
		if err != nil || strings.Join(s, " ") != c.want {
			t.Errorf("%v: %v %v", c.args, s, err)
		}
	}
	if _, err := parse("-services", "reality"); err == nil {
		t.Error("REALITY without a domain")
	}
	if _, err := parse("-domain", "example.com", "-services", "vmess"); err == nil {
		t.Error("unknown kind")
	}
}

func TestExportText(t *testing.T) {
	got := exportText([]*nodev1.Profile{
		{ServiceId: 4, Service: "reality", Link: "vless://a", NextLink: "vless://b", NextFrom: 1767225600},
		{ServiceId: 5, Service: "hy2", Link: "hysteria2://c"},
	})
	want := "# reality (service 4)\nvless://a\n# reality from 2026-01-01T00:00:00Z\nvless://b\n# hy2 (service 5)\nhysteria2://c\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}
