package main

import (
	"flag"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/summary"
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

func TestOutsidePorts(t *testing.T) {
	got := outsidePorts([]*nodev1.PortRange{{Proto: "tcp", From: 443, To: 443}, {Proto: "udp", From: 20100, To: 20611},
		{Proto: "tcp", From: 22, To: 22}, {Proto: "udp", From: 443, To: 443}, {Proto: "tcp", From: 20100, To: 20611}})
	if got != "tcp 22, tcp+udp 443, tcp+udp 20100-20611" {
		t.Errorf("%q", got)
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

// rayd reads the release's AS database where install and update put it.
func TestReleaseDBPath(t *testing.T) {
	if summary.ReleaseDB != filepath.Join(deploy.DataDir, "ipinfo_lite.mmdb") || !slices.Contains(deploy.DataFiles, filepath.Base(summary.ReleaseDB)) {
		t.Fatalf("%s is not where the release puts it (%s)", summary.ReleaseDB, deploy.DataDir)
	}
}
