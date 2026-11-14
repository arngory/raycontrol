package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
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
	got := outsidePorts([]deploy.PortRange{{Proto: "tcp", From: 443, To: 443}, {Proto: "udp", From: 20100, To: 20611},
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
// dnsauth key for the service; masterdns with its zone alone. The spare
// zones of a link (niko-dns-spare) after its main one, with its keys.
func TestProbeDNSZones(t *testing.T) {
	var dev [spa.KeySize]byte
	dev[0] = 1
	nodeID := strings.Repeat("ab", spa.NodeIDSize)
	seal := bytes.Repeat([]byte{9}, 32)
	p := sub.Payload{
		DNSProbe: &sub.DNSProbeHint{V: 1, Key: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))},
		Profiles: []sub.Profile{
			{Svc: 5, Name: "dns", Link: "vless://u@inner:1?niko-dns=" + url.QueryEscape("dnstt;;t.example.com;pub") +
				"&niko-dnsseal=" + url.QueryEscape("v1;"+base64.RawURLEncoding.EncodeToString(seal)) + "&niko-dnsauth=v1&niko-node=" + nodeID +
				"&niko-svc=5&niko-dns-spare=" + url.QueryEscape("s.example.net,u.example.org") + "#dns"},
			{Svc: 6, Name: "mdns", Link: "vless://u@inner:1?niko-dns=" + url.QueryEscape("masterdns;;m.example.com;5") + "&niko-dnskey=x" +
				"&niko-mdseal=v1&niko-dnsauth=v1&niko-node=" + nodeID + "&niko-svc=6&niko-dns-spare=v.example.net#mdns"},
			{Svc: 7, Name: "reality", Link: "vless://u@203.0.113.7:443?security=reality#reality"},
			{Svc: 8, Name: "slip", Link: "vless://u@inner:1?niko-dns=" + url.QueryEscape("slipstream;;q.example.com;8") +
				"&niko-slip=" + url.QueryEscape("v1;"+strings.Repeat("A", 43)+";abcdefgh;quiet.dev") + "&niko-dnsauth=v1&niko-node=" + nodeID + "&niko-svc=8#slip"},
		},
	}
	zones := probeDNSZones(&p, "203.0.113.7", netip.MustParseAddr("203.0.113.7"), dev)
	var names []string
	for _, z := range zones {
		names = append(names, z.Name)
	}
	if want := []string{"t.example.com", "s.example.net", "u.example.org", "m.example.com", "v.example.net", "q.example.com"}; !slices.Equal(names, want) {
		t.Fatalf("zones %v, want %v", names, want)
	}
	id, _ := hex.DecodeString(nodeID)
	want := spa.DNSAuthKey(dev, [spa.NodeIDSize]byte(id), 5)
	// The front is asked at the node's address, never at this machine's
	// loopback (review 13).
	for _, z := range zones {
		if z.Front != netip.MustParseAddrPort("203.0.113.7:53") {
			t.Fatalf("%s: front at %v", z.Name, z.Front)
		}
	}
	for _, d := range zones[:3] {
		if d.Kind != "dnstt" || d.Service != "dns" || d.Spare != (d.Name != "t.example.com") || d.Host != "203.0.113.7" || d.SvcID != 5 ||
			len(d.ProbeKey) != 32 || d.Seal != "required" || !bytes.Equal(d.SealKey, seal) || d.Auth != "required" || !bytes.Equal(d.AuthKey, want[:]) {
			t.Fatalf("dnstt %+v", d)
		}
	}
	for _, m := range zones[3:5] {
		if m.Kind != "masterdns" || m.Service != "mdns" || m.Spare != (m.Name != "m.example.com") || m.SvcID != 6 || m.ProbeKey != nil || m.AuthKey != nil {
			t.Fatalf("masterdns %+v", m)
		}
	}
	// slipstream: the front's probes with the key; no tag (the front checks
	// it before the server, and the check asks the front only).
	if s := zones[5]; s.Kind != "slipstream" || s.Service != "slip" || s.SvcID != 8 || len(s.ProbeKey) != 32 || s.AuthKey != nil || s.Seal != "" {
		t.Fatalf("slipstream %+v", s)
	}
	// Without dns_probe (a user with no dnstt): no key, and the check asks
	// a random name (dnscheck.TestCheckSlipstream).
	p.DNSProbe = nil
	if s := probeDNSZones(&p, "203.0.113.7", netip.MustParseAddr("203.0.113.7"), dev)[5]; s.Kind != "slipstream" || s.ProbeKey != nil {
		t.Fatalf("slipstream without dns_probe %+v", s)
	}
}

// rayctl service list: a DNS tunnel's dnsauth and seal modes, dnstt's or
// masterdns's, then its spare zones.
func TestKeyStateDNS(t *testing.T) {
	for _, c := range []struct{ kind, settings, want string }{
		{"dnstt", `{"auth":"required","seal":"optional","spare_zones":["s.example.net","u.example.org"]}`,
			"auth required, v2 optional, seal optional, spare zones s.example.net u.example.org"},
		{"masterdns", `{"auth":"required","seal":"required","encryption_method":5}`, "auth required, v2 optional, seal required"},
		// dnsauth-v2 as set (optional when unset)
		{"dnstt", `{"auth":"required","auth_hint":"required","seal":"off"}`, "auth required, v2 required, seal off"},
		{"dnstt", `{"auth":"optional","auth_hint":"off"}`, "auth optional (open: auth=required keeps floods out), v2 off, seal off"},
		{"masterdns", `{"zone":"m.example.com","auth":"optional","seal":"optional","spare_zones":["v.example.net"]}`,
			"auth optional (open: auth=required keeps floods out), v2 optional, seal optional, spare zones v.example.net"},
		// A masterdns service from before: neither mode.
		{"masterdns", `{}`, "auth off (open: auth=required keeps floods out), seal off"},
	} {
		if got := keyState(&nodev1.Service{Kind: c.kind, SettingsJson: c.settings}); got != c.want {
			t.Errorf("%s %s: %q", c.kind, c.settings, got)
		}
	}
}

// rayctl service list: a site's certificate keys (spec/cert-pin-v1.md), once
// its links carry pins; the operator's own certificate has none.
func TestKeyStateSite(t *testing.T) {
	for _, c := range []struct{ settings, want string }{
		{`{"sni":"a.example.com"}`, ""}, // no certificate of the node's yet, or no ACME
		{`{"tls_key_at":1767225600,"tls_next_at":1767312000}`, "key since 2026-01-01 00:00, next key pinned since 2026-01-02 00:00"},
		{`{"tls_key_at":1767225600,"tls_next_at":1767312000,"tls_rotate_at":1768000000}`,
			"key since 2026-01-01 00:00, next key pinned since 2026-01-02 00:00, switch to it ordered"},
		{`{"tls_key_at":1767225600,"tls_next_at":1767312000,"tls_imported":true}`, "certificate of your own: no pins"},
	} {
		if got := keyState(&nodev1.Service{Kind: "site", SettingsJson: c.settings}); got != c.want {
			t.Errorf("site %s: %q", c.settings, got)
		}
	}
}

// inviteNode makes invites as a node does, the short form when it has one,
// and keeps the IDs of those withdrawn.
type inviteNode struct {
	nodev1connect.NodeServiceClient
	short   string
	revoked []string
}

func (n *inviteNode) CreateInvite(context.Context, *connect.Request[nodev1.CreateInviteRequest]) (*connect.Response[nodev1.CreateInviteResponse], error) {
	return connect.NewResponse(&nodev1.CreateInviteResponse{Invite: &nodev1.Invite{Id: "inv1", User: "alice", Name: "phone", Role: "user"},
		InviteCode: "rcinv1:long", InviteCodeShort: n.short}), nil
}

func (n *inviteNode) RevokeDevice(_ context.Context, req *connect.Request[nodev1.RevokeDeviceRequest]) (*connect.Response[nodev1.RevokeDeviceResponse], error) {
	n.revoked = append(n.revoked, req.Msg.Id)
	return connect.NewResponse(&nodev1.RevokeDeviceResponse{}), nil
}

// rayctl device invite: rcinv2 by default (Niko 1.35), rcinv1 when asked.
// From a node that makes no rcinv2 (before v0.13, or a host that cannot go
// in it) rcinv1 by default; with -format rcinv2 the invite is withdrawn.
func TestInviteFormat(t *testing.T) {
	for _, c := range []struct {
		short string
		args  []string
		want  string // the invite written; "": none, withdrawn
	}{
		{"RCINV2:SHORT", nil, "RCINV2:SHORT"},
		{"RCINV2:SHORT", []string{"-format", "rcinv2"}, "RCINV2:SHORT"},
		{"RCINV2:SHORT", []string{"-format", "rcinv1"}, "rcinv1:long"},
		{"", nil, "rcinv1:long"},
		{"", []string{"-format", "rcinv1"}, "rcinv1:long"},
		{"", []string{"-format", "rcinv2"}, ""},
	} {
		n := &inviteNode{short: c.short}
		out := filepath.Join(t.TempDir(), "invite")
		err := (&cli{c: n}).device(context.Background(), "invite", append([]string{"alice", "phone", "-o", out}, c.args...))
		got, _ := os.ReadFile(out)
		if c.want == "" && (err == nil || got != nil || !slices.Equal(n.revoked, []string{"inv1"})) ||
			c.want != "" && (err != nil || string(got) != c.want+"\n" || n.revoked != nil) {
			t.Errorf("short %q, %v: %v, wrote %q, withdrew %v", c.short, c.args, err, got, n.revoked)
		}
	}
	if err := (&cli{c: &inviteNode{}}).device(context.Background(), "invite", []string{"alice", "phone", "-format", "rcinv3"}); !errors.Is(err, errUsage) {
		t.Errorf("-format rcinv3: %v", err)
	}
}

// remote enroll @FILE finds the invite in the text around it, as rayctl
// device invite prints it, whichever the form.
func TestReadArgInvite(t *testing.T) {
	for _, code := range []string{"RCINV2:AIA4WADRA4AACAQD", "rcinv2:aia4wadra4aacaqd", "rcinv1:eyJ2IjoxfQ"} {
		f := filepath.Join(t.TempDir(), "invite.txt")
		text := "invite 3f2a for alice/phone (user), once, until 2026-11-07 10:00. The client registers with it through the API:\n\n" + code + "\n"
		if err := os.WriteFile(f, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := readArg("@" + f); err != nil || got != code {
			t.Errorf("%s: %q %v", code, got, err)
		}
	}
}

// rayctl summary: a dnstt service's working zones beside its resolvers,
// nothing for a service without.
func TestPrintSummaryZones(t *testing.T) {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	printSummary(w, &nodev1.GetSummaryResponse{Days: 7, K: 10, Networks: []*nodev1.SummaryNetwork{{Asn: 64500, Name: "Mobile One", Reports: 10,
		Services: []*nodev1.SummaryService{
			{Id: 3, Name: "dns", Results: map[string]int64{"works": 10}, Dns: map[string]int64{"udp": 10}, Zone: map[string]int64{"0": 3, "1": 7}},
			{Id: 4, Name: "mdns", Results: map[string]int64{"works": 10}, Dns: map[string]int64{"udp": 10}},
		}}}})
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(b.String(), "\n") {
		if strings.Contains(l, "dns (3)") != strings.HasSuffix(l, "zones 0:3 1:7") || strings.Contains(l, "mdns (4)") && strings.Contains(l, "zones") {
			t.Errorf("line %q", l)
		}
	}
}

// The bootstrap passes its arguments to check and to install alike: check
// takes every flag install has (review: bootstrap.sh -name failed the check).
func TestCheckTakesInstallFlags(t *testing.T) {
	install := flag.NewFlagSet("install", flag.ContinueOnError)
	installFlags(install)
	var args []string
	install.VisitAll(func(f *flag.Flag) {
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			args = append(args, "-"+f.Name)
			return
		}
		args = append(args, "-"+f.Name, "x")
	})
	check := flag.NewFlagSet("check", flag.ContinueOnError)
	check.SetOutput(io.Discard)
	check.String("host", "", "")
	check.String("domain", "", "")
	check.String("services", "", "")
	check.Bool("allow-v0", false, "")
	defineInstallFlags(check)
	if err := check.Parse(args); err != nil {
		t.Fatalf("check refuses install's flags: %v", err)
	}
}
