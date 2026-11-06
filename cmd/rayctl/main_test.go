package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/sub"
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
		// Every kind the cheatsheet adds; REALITY first, whose site the
		// others on TCP 443 take; a kind once.
		{[]string{"-domain", "example.com", "-services", "naive,yggdrasil,doh,hy2-masq,reality,api,naive"},
			"reality:reality naive:naive yggdrasil:ygg doh:doh hy2-masq:hy2-masq api:api"},
		// The remote API needs no domain.
		{[]string{"-services", "api"}, "api:api"},
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

// rayctl probe -dns takes its zones from the subscription's links: the
// dnstt one with the probe key, the seal key of the link and the device's
// dnsauth key for the service; masterdns with its zone alone.
func TestProbeDNSZones(t *testing.T) {
	var dev [spa.KeySize]byte
	dev[0] = 1
	nodeID := strings.Repeat("ab", spa.NodeIDSize)
	seal := bytes.Repeat([]byte{9}, 32)
	p := sub.Payload{
		DNSProbe: &sub.DNSProbeHint{V: 1, Key: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))},
		Profiles: []sub.Profile{
			{Svc: 5, Name: "dns", Link: "vless://u@inner:1?niko-dns=" + url.QueryEscape("dnstt;;t.example.com;pub") +
				"&niko-dnsseal=" + url.QueryEscape("v1;"+base64.RawURLEncoding.EncodeToString(seal)) + "&niko-dnsauth=v1&niko-node=" + nodeID + "&niko-svc=5#dns"},
			{Svc: 6, Name: "mdns", Link: "vless://u@inner:1?niko-dns=" + url.QueryEscape("masterdns;;m.example.com;5") + "&niko-dnskey=x#mdns"},
			{Svc: 7, Name: "reality", Link: "vless://u@203.0.113.7:443?security=reality#reality"},
		},
	}
	zones := probeDNSZones(&p, "203.0.113.7", dev)
	if len(zones) != 2 {
		t.Fatalf("zones %+v", zones)
	}
	id, _ := hex.DecodeString(nodeID)
	want := spa.DNSAuthKey(dev, [spa.NodeIDSize]byte(id), 5)
	d, m := zones[0], zones[1]
	if d.Kind != "dnstt" || d.Name != "t.example.com" || d.Host != "203.0.113.7" || d.SvcID != 5 || len(d.ProbeKey) != 32 ||
		d.Seal != "required" || !bytes.Equal(d.SealKey, seal) || d.Auth != "required" || !bytes.Equal(d.AuthKey, want[:]) {
		t.Fatalf("dnstt %+v", d)
	}
	if m.Kind != "masterdns" || m.Name != "m.example.com" || m.ProbeKey != nil || m.AuthKey != nil {
		t.Fatalf("masterdns %+v", m)
	}
}
