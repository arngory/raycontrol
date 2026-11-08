package deploy_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
)

// FuzzBuild: whatever rayd reports, inputs that pass Check give a plan
// that passes Plan.Check, every unit line one of a template's
// (spec/apply-plan-v1.md §4.2); what Build leaves out it leaves out at the
// checks of the services, never at the last check of a line (step 2).
func FuzzBuild(f *testing.F) {
	f.Add(uint8(0), "site", "s2", 9120, "404\nExecStartPre=+/bin/sh -c id", "", "", "", "", 0, 0, false, false, true, true, true, true, 40443, false)
	f.Add(uint8(9), "doh", "x 0755 root root -\nZ /etc 0777 rayd rayd -", 9121, "", "", "", "", "", 0, 0, false, false, true, true, true, true, 0, false)
	f.Add(uint8(3), "reality", "reality", 9113, "", "front,disk", "", "", "", 0, 0, false, false, false, false, false, false, 1, false)
	f.Add(uint8(9), "slipstream", "slip", 9122, "", "", "s.example.com", "abcdefgh", "abc.com", 16, 1, false, false, true, true, true, true, 443, false)
	f.Add(uint8(9), "yggdrasil", "ygg", 9123, "", "site", "", "", "", 0, 0, true, false, true, true, false, false, 0, false)
	f.Add(uint8(9), "hy2-obfs", "ho", 9124, "", "", "", "", "", 0, 0, false, true, true, true, true, true, 65535, false)
	f.Add(uint8(4), "naive", "naive", 9114, "pages", "site", "", "", "", 0, 0, false, false, true, true, true, true, 8443, true)
	f.Add(uint8(2), "site", "site", 9112, "pages", "", "", "", "", 0, 0, false, false, true, true, true, true, 0, false)
	f.Add(uint8(9), "evil\x1b", "a/../x", 0, "", "", "", "", "", 0, 0, false, false, true, true, true, true, -1, false)
	f.Fuzz(func(t *testing.T, at uint8, kind, name string, uid int, answer, site, zone, alpn, sni string, maxConn, devConn int,
		peers, salamander, frontTCP, front, frontDNS, probeKey bool, subPort int, icmp bool) {
		in := goodInputs()
		in.FrontTCP, in.Front, in.FrontDNS, in.DNSProbeKey, in.SubscriptionPort = frontTCP, front, frontDNS, probeKey, subPort
		s := deploy.ServiceInput{Kind: kind, Name: name, UID: uid, Answer: answer, Site: site, PublicPeers: peers, Salamander: salamander, ICMP: icmp,
			Slipstream: provision.SlipstreamSettings{Zone: zone, ALPN: alpn, SNI: sni, MaxConnections: maxConn, DeviceConnections: devConn}}
		// One of the good services replaced, or one more.
		if i := int(at); i < len(in.Services) {
			in.Services[i] = s
		} else {
			in.Services = append(in.Services, s)
		}
		p := deploy.Build(in, render.DefaultPaths, deploy.DefaultBinaries)
		if in.Check() != nil {
			return
		}
		p.HostPorts = in.HostPorts
		p.Files = append(p.Files, deploy.FirewallFiles(p.HostPorts)...)
		if err := p.Check(); err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
		// The ping groups widen only for a naive unit that has -icmp.
		withICMP := slices.ContainsFunc(p.Files, func(f deploy.File) bool {
			return strings.HasPrefix(f.Path, "/etc/systemd/system/niko-") && strings.Contains(string(f.Content), " naive -") &&
				strings.Contains(string(f.Content), " -icmp\n")
		})
		if p.ICMP != withICMP {
			t.Fatalf("%+v: ICMP %v, a naive unit with -icmp %v", s, p.ICMP, withICMP)
		}
		for _, w := range p.Warnings {
			if strings.Contains(w, "would break") {
				t.Fatalf("%+v: left out only by the last check: %s", s, w)
			}
		}
	})
}

// rootLine matches unit settings that would give a unit, or root, more
// than raycontrol's units have: commands as root or around the sandbox,
// another user, files or credentials from elsewhere, a capability. An
// oracle of its own, apart from Plan.Check's templates.
var rootLine = regexp.MustCompile(`^(Exec[A-Za-z]*=[+!@:-]|Exec(Stop|StopPost|Reload|Condition|StartPost)=|(User|Group)=(root|0|[^n]|n[^i])|` +
	`(Environment|EnvironmentFile|BindPaths|BindReadOnlyPaths|RootDirectory|RootImage|LoadCredential|SetCredential|PAMName|DynamicUser|` +
	`PermissionsStartOnly|Type|KillMode|Delegate|DevicePolicy|DeviceAllow|NotifyAccess|OOMScoreAdjust|Nice)=|.*(CAP_SYS|CAP_DAC|CAP_SETUID|CAP_CHOWN|CAP_FOWNER)|.*[%\\]|Exec[A-Za-z]*=.*[;'"$])`)

// FuzzPlanCheck: a line put into any file of a plan rayctl makes, or a
// mode, is refused, or else it gives nothing of rootLine.
func FuzzPlanCheck(f *testing.F) {
	for _, l := range []string{"User=root", "ExecStartPre=+/bin/sh -c id", "Z /etc 0777 rayd rayd -", "kernel.core_pattern = |/x",
		"ExecStartPre=+/usr/local/bin/rayd credential /var/lib raycontrol/rendered/dns/noise.key rayd niko-dns /run/niko/dns/x",
		"Description=x", "After=niko-dns.service", "d /run/niko/x-in 2750 niko-x niko-front -", "NoNewPrivileges=no"} {
		f.Add(uint8(3), uint16(5), l, uint32(0o644))
	}
	f.Add(uint8(0), uint16(0), "", uint32(0o4755))
	f.Fuzz(func(t *testing.T, at uint8, pos uint16, line string, mode uint32) {
		p := clonePlan(deploy.Build(goodInputs(), render.DefaultPaths, deploy.DefaultBinaries))
		i := int(at) % len(p.Files)
		lines := strings.Split(string(p.Files[i].Content), "\n")
		j := int(pos) % (len(lines) + 1)
		lines = slices.Insert(lines, j, line)
		p.Files[i].Content = []byte(strings.Join(lines, "\n"))
		p.Files[i].Mode = mode
		if p.Check() != nil {
			return
		}
		if mode != 0o644 && mode != 0o755 {
			t.Fatalf("mode %#o accepted", mode)
		}
		if strings.HasPrefix(p.Files[i].Path, "/etc/systemd/system/") {
			for _, l := range strings.Split(line, "\n") {
				if rootLine.MatchString(l) && !strings.HasPrefix(l, "ExecStartPre=+/usr/local/bin/rayd credential ") {
					t.Fatalf("%s: %q accepted", p.Files[i].Path, l)
				}
			}
		}
	})
}
