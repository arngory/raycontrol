package deploy_test

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// goodInputs are a node rayd would report: the inner stage, a DNS tunnel,
// REALITY on its site, naive, SSH.
func goodInputs() deploy.Inputs {
	return deploy.Inputs{FrontTCP: true, Front: true, FrontDNS: true, DNSProbeKey: true, SubscriptionPort: 40443,
		HostPorts: []deploy.PortRange{{Proto: "tcp", From: 443, To: 443}, {Proto: "udp", From: 53, To: 53}},
		Services: []deploy.ServiceInput{
			{Kind: "inner", Name: "inner", UID: 9110},
			{Kind: "dnstt", Name: "dns", UID: 9111},
			{Kind: "site", Name: "site", UID: 9112, Answer: "404"},
			{Kind: "reality", Name: "reality", UID: 9113, Site: "site"},
			{Kind: "naive", Name: "naive", UID: 9114, Site: "site"},
			{Kind: "ssh", Name: "ssh"},
		}}
}

// What a hostile database or rayd puts in the inputs (spec/apply-plan-v1.md
// §2.3) leaves its service out, said, and gets nowhere into the plan; the
// other services are deployed as ever.
func TestBuildHostileInputs(t *testing.T) {
	good := deploy.Build(goodInputs(), render.DefaultPaths, deploy.DefaultBinaries)
	if len(good.Warnings) != 0 || !slices.Contains(good.Units, "niko-naive.service") || !slices.Contains(good.Units, "niko-reality.service") {
		t.Fatalf("good inputs: units %v, warnings %v", good.Units, good.Warnings)
	}
	inject := "ExecStartPre=+/bin/sh -c id"
	slip := func(ss provision.SlipstreamSettings) deploy.ServiceInput {
		return deploy.ServiceInput{Kind: "slipstream", Name: "slip", UID: 9120, Slipstream: ss}
	}
	// Why, where more than one check would refuse it.
	says := map[string]string{
		"REALITY site into usermod": "its site: ", "UID without a process": "no process", "kind unknown": "not known",
		"kind unknown, no UID": "not known",
	}
	for name, c := range map[string]struct {
		s    deploy.ServiceInput
		left string // the service left out
	}{
		"kind unknown, no UID":      {deploy.ServiceInput{Kind: "evil", Name: "e"}, ""},
		"answer with a line":        {deploy.ServiceInput{Kind: "site", Name: "s2", UID: 9120, Answer: "404\n" + inject}, "niko-s2.service"},
		"answer not one of them":    {deploy.ServiceInput{Kind: "site", Name: "s2", UID: 9120, Answer: "teapot"}, "niko-s2.service"},
		"doh name into tmpfiles":    {deploy.ServiceInput{Kind: "doh", Name: "x 0755 root root -\nZ /etc 0777 rayd rayd -\nd /run/niko/y", UID: 9120}, ""},
		"name with a line":          {deploy.ServiceInput{Kind: "dnstt", Name: "d2\n" + inject, UID: 9120}, ""},
		"name with a space":         {deploy.ServiceInput{Kind: "hy2-masq", Name: "h x", UID: 9120}, ""},
		"name out of its dir":       {deploy.ServiceInput{Kind: "dnstt", Name: "a/../x", UID: 9120}, ""},
		"name of the front":         {deploy.ServiceInput{Kind: "dnstt", Name: "front", UID: 9120}, ""},
		"name of a socket dir":      {deploy.ServiceInput{Kind: "dnstt", Name: "dns-in", UID: 9120}, ""},
		"name too long":             {deploy.ServiceInput{Kind: "dnstt", Name: strings.Repeat("a", 28), UID: 9120}, ""},
		"REALITY site into usermod": {deploy.ServiceInput{Kind: "reality", Name: "r2", UID: 9120, Site: "front,disk"}, "niko-r2.service"},
		"REALITY site not a site":   {deploy.ServiceInput{Kind: "reality", Name: "r2", UID: 9120, Site: "dns"}, "niko-r2.service"},
		"UID 0":                     {deploy.ServiceInput{Kind: "hy2-masq", Name: "h2", UID: 0}, "niko-h2.service"},
		"UID past the range":        {deploy.ServiceInput{Kind: "hy2-masq", Name: "h2", UID: 9180}, "niko-h2.service"},
		"UID of the front":          {deploy.ServiceInput{Kind: "hy2-masq", Name: "h2", UID: 9100}, "niko-h2.service"},
		"UID of rayd":               {deploy.ServiceInput{Kind: "hy2-masq", Name: "h2", UID: 9190}, "niko-h2.service"},
		"UID taken":                 {deploy.ServiceInput{Kind: "hy2-masq", Name: "h2", UID: 9111}, "niko-h2.service"},
		"name taken":                {deploy.ServiceInput{Kind: "hy2-masq", Name: "dns", UID: 9120}, ""},
		"UID without a process":     {deploy.ServiceInput{Kind: "ssh", Name: "ssh2", UID: 9120}, ""},
		"kind unknown":              {deploy.ServiceInput{Kind: "evil\x1b[2J", Name: "e", UID: 9120}, "niko-e.service"},
		"slipstream zone":           {slip(provision.SlipstreamSettings{Zone: "s.example.com --key /etc/shadow", ALPN: "abcdefgh", SNI: "abc.com"}), "niko-slip.service"},
		"slipstream ALPN":           {slip(provision.SlipstreamSettings{Zone: "s.example.com", ALPN: "abcdefgh\n" + inject, SNI: "abc.com"}), "niko-slip.service"},
		"slipstream limits":         {slip(provision.SlipstreamSettings{Zone: "s.example.com", ALPN: "abcdefgh", SNI: "abc.com", MaxConnections: -1}), "niko-slip.service"},
		"slipstream error":          {deploy.ServiceInput{Kind: "slipstream", Name: "slip", UID: 9120, SlipstreamError: "service slip: broken"}, "niko-slip.service"},
	} {
		in := goodInputs()
		in.Services = append(in.Services, c.s)
		p := deploy.Build(in, render.DefaultPaths, deploy.DefaultBinaries)
		if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], says[name]) {
			t.Errorf("%s: warnings %q", name, p.Warnings)
		}
		if c.left != "" && slices.Contains(p.Units, c.left) {
			t.Errorf("%s: %s deployed", name, c.left)
		}
		// Nothing of it in the plan: the plan is the good one.
		if !reflect.DeepEqual(p.Files, good.Files) || !reflect.DeepEqual(p.Users, good.Users) || !slices.Equal(p.Units, good.Units) {
			t.Errorf("%s: the plan changed:\nunits %v\nusers %v", name, p.Units, p.Users)
		}
	}

	// Twice the same UID: the first one has it.
	in := goodInputs()
	in.Services = append(in.Services, deploy.ServiceInput{Kind: "hy2-masq", Name: "h1", UID: 9130}, deploy.ServiceInput{Kind: "hy2-masq", Name: "h2", UID: 9130})
	p := deploy.Build(in, render.DefaultPaths, deploy.DefaultBinaries)
	if !slices.Contains(p.Units, "niko-h1.service") || slices.Contains(p.Units, "niko-h2.service") || len(p.Warnings) != 1 {
		t.Errorf("a UID twice: units %v, warnings %v", p.Units, p.Warnings)
	}
	// 71 services with a process: 70 UIDs, one of them left out.
	in = goodInputs()
	in.Services = nil
	for i := range 71 {
		in.Services = append(in.Services, deploy.ServiceInput{Kind: "hy2-masq", Name: fmt.Sprintf("h%d", i), UID: store.FirstServiceUID + i})
	}
	p = deploy.Build(in, render.DefaultPaths, deploy.DefaultBinaries)
	n := 0
	for _, u := range p.Units {
		if strings.HasPrefix(u, "niko-h") {
			n++
		}
	}
	if n != 70 || len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "outside") {
		t.Errorf("71 services: %d deployed, warnings %v", n, p.Warnings)
	}
	// The site left out: naive answers as by default, not as it said, and
	// REALITY, whose group it was, goes too.
	in = goodInputs()
	in.Services[2].Answer = "403\n" + inject
	p = deploy.Build(in, render.DefaultPaths, deploy.DefaultBinaries)
	if u := file(p, "/etc/systemd/system/niko-naive.service"); !strings.Contains(u, "naive -answer 404 ") || strings.Contains(u, "/bin/sh") {
		t.Errorf("naive with a bad site:\n%s", u)
	}
	if slices.Contains(p.Units, "niko-reality.service") || slices.Contains(p.Units, "niko-site.service") || len(p.Warnings) != 2 {
		t.Errorf("REALITY without its site: %v, warnings %q", p.Units, p.Warnings)
	}
}

// The last check of each line (step 2) holds whatever reaches it: paths
// with a line break leave their units and tmpfiles lines out.
func TestBuildBrokenLines(t *testing.T) {
	p := deploy.Build(goodInputs(), render.Paths{Rendered: "/var/lib/raycontrol/rendered\nExecStartPre=+/bin/sh -c id", Run: "/run/niko"},
		deploy.DefaultBinaries)
	for _, f := range p.Files {
		if strings.Contains(string(f.Content), "/bin/sh") {
			t.Errorf("%s:\n%s", f.Path, f.Content)
		}
	}
	if slices.Contains(p.Units, "niko-dns.service") || slices.Contains(p.Units, "rayd.service") || len(p.Warnings) == 0 {
		t.Errorf("units %v, warnings %q", p.Units, p.Warnings)
	}
	p = deploy.Build(goodInputs(), render.Paths{Rendered: "/var/lib/raycontrol/rendered", Run: "/run/niko x\nZ /etc 0777 rayd rayd -"}, deploy.DefaultBinaries)
	if tmp := file(p, "/etc/tmpfiles.d/raycontrol.conf"); strings.Contains(tmp, "Z /etc") || len(p.Dirs) != 0 {
		t.Errorf("tmpfiles:\n%s", tmp)
	}
}

// What is the node's, not a service's, fails the whole apply.
func TestInputsCheck(t *testing.T) {
	if err := goodInputs().Check(); err != nil {
		t.Fatal(err)
	}
	icmp := goodInputs()
	icmp.Services[4].ICMP = true // naive's
	if err := icmp.Check(); err != nil {
		t.Fatalf("naive with ICMP: %v", err)
	}
	for name, f := range map[string]func(*deploy.Inputs){
		"proto":             func(in *deploy.Inputs) { in.HostPorts[0].Proto = `tcp"/><port protocol="tcp" port="1-65535` },
		"port 0":            func(in *deploy.Inputs) { in.HostPorts[0].From = 0 },
		"from after to":     func(in *deploy.Inputs) { in.OutsidePorts = []deploy.PortRange{{Proto: "udp", From: 2, To: 1}} },
		"subscription port": func(in *deploy.Inputs) { in.SubscriptionPort = 65536 },
		"negative port":     func(in *deploy.Inputs) { in.SubscriptionPort = -1 },
		"too many services": func(in *deploy.Inputs) { in.Services = make([]deploy.ServiceInput, deploy.MaxInputServices+1) },
		"too many ports":    func(in *deploy.Inputs) { in.HostPorts = make([]deploy.PortRange, 1025) },
		"ICMP not naive's":  func(in *deploy.Inputs) { in.Services[1].ICMP = true },
	} {
		in := goodInputs()
		f(&in)
		if err := in.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// rayd's warnings reach root's terminal without what it would act on, and
// not without end.
func TestPrintableWarning(t *testing.T) {
	if got := deploy.PrintableWarning("not rendered: \x1b]0;owned\x07\r\nservice x"); strings.ContainsFunc(got, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		t.Errorf("control characters through: %q", got)
	}
	if got := deploy.PrintableWarning(strings.Repeat("é", 1000)); len(got) > 520 || !strings.HasSuffix(got, "…") {
		t.Errorf("long warning: %d bytes", len(got))
	}
	if w := "service olc (olcrtc) is not deployed by this version"; deploy.PrintableWarning(w) != w {
		t.Error("a plain warning changed")
	}
}
