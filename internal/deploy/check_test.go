package deploy_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/render"
)

// fullPlan is the test node's plan as rayctl apply installs it: host ports
// and their firewall files too.
func fullPlan(t *testing.T) deploy.Plan {
	t.Helper()
	p, _ := plan(t)
	p.HostPorts = []deploy.PortRange{{Proto: "tcp", From: 22, To: 22}, {Proto: "udp", From: 53, To: 53}}
	p.Files = append(p.Files, deploy.FirewallFiles(p.HostPorts)...)
	return p
}

// clonePlan is a copy of p that changes leave p as it is.
func clonePlan(p deploy.Plan) deploy.Plan {
	c := p
	c.Files = nil
	for _, f := range p.Files {
		f.Content = bytes.Clone(f.Content)
		c.Files = append(c.Files, f)
	}
	c.Users = nil
	for _, u := range p.Users {
		u.ExtraGroups = slices.Clone(u.ExtraGroups)
		c.Users = append(c.Users, u)
	}
	c.Units = slices.Clone(p.Units)
	c.HostPorts = slices.Clone(p.HostPorts)
	return c
}

// edit replaces old with new in the plan's file at path.
func edit(t *testing.T, p *deploy.Plan, path, old, new string) {
	t.Helper()
	for i, f := range p.Files {
		if f.Path == path {
			if !strings.Contains(string(f.Content), old) {
				t.Fatalf("%s has no %q", path, old)
			}
			p.Files[i].Content = []byte(strings.Replace(string(f.Content), old, new, 1))
			return
		}
	}
	t.Fatalf("no %s in the plan", path)
}

// The last barrier (spec/apply-plan-v1.md §2.2, §4.2): a plan with what
// rayctl never writes is refused, whole, before anything changes; every
// plan rayctl makes passes.
func TestPlanCheck(t *testing.T) {
	good := fullPlan(t)
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	const (
		dns   = "/etc/systemd/system/niko-dns.service"
		front = "/etc/systemd/system/niko-front.service"
		tmp   = "/etc/tmpfiles.d/raycontrol.conf"
	)
	addFile := func(path, content string, mode uint32) func(*deploy.Plan) {
		return func(p *deploy.Plan) {
			p.Files = append(p.Files, deploy.File{Path: path, Mode: mode, Content: []byte(content)})
		}
	}
	set := func(path, old, new string) func(*deploy.Plan) {
		return func(p *deploy.Plan) { edit(t, p, path, old, new) }
	}
	user := func(name string, f func(*deploy.SystemUser)) func(*deploy.Plan) {
		return func(p *deploy.Plan) {
			for i := range p.Users {
				if p.Users[i].Name == name {
					f(&p.Users[i])
				}
			}
		}
	}
	for name, f := range map[string]func(*deploy.Plan){
		"sudoers":                 addFile("/etc/sudoers.d/x", "rayd ALL=(ALL) NOPASSWD: ALL\n", 0o644),
		"out of the unit dir":     addFile("/etc/systemd/system/../cron.d/x", "* * * * * root id\n", 0o644),
		"a unit named a path":     addFile("/etc/systemd/system/niko-../x.service", "", 0o644),
		"a cron file":             addFile("/etc/cron.d/x", "* * * * * root id\n", 0o644),
		"setuid":                  func(p *deploy.Plan) { p.Files[0].Mode = uint32(os.ModeSetuid) | 0o755 },
		"setuid, octal":           func(p *deploy.Plan) { p.Files[0].Mode = 0o4755 },
		"setgid":                  func(p *deploy.Plan) { p.Files[0].Mode = uint32(os.ModeSetgid) | 0o644 },
		"sticky":                  func(p *deploy.Plan) { p.Files[0].Mode = uint32(os.ModeSticky) | 0o644 },
		"writable by others":      func(p *deploy.Plan) { p.Files[0].Mode = 0o666 },
		"core_pattern":            set(deploy.HardeningSysctl, "net.ipv4.tcp_syncookies = 1\n", "kernel.core_pattern = |/tmp/x\n"),
		"modprobe":                addFile("/etc/sysctl.d/91-raycontrol-relay.conf", "kernel.modprobe = /tmp/x\n", 0o644),
		"a Z line in tmpfiles":    set(tmp, "d /run/niko 0755 root root -\n", "d /run/niko 0755 root root -\nZ /etc 0777 rayd rayd -\n"),
		"a d line for /etc":       set(tmp, "d /run/niko 0755 root root -\n", "d /run/niko 0755 root root -\nd /etc 2750 rayd rayd -\n"),
		"a runtime dir to rayd":   set(tmp, "d /run/niko 0755 root root -\n", "d /run/niko 0755 root root -\nd /run/niko/front 2750 rayd niko-front -\n"),
		"an API dir to another":   set(tmp, "d /run/niko/inner-api 2750 niko-inner rayd -", "d /run/niko/inner-api 2750 niko-dns rayd -"),
		"tmpfiles specifier":      set(tmp, "d /run/niko 0755 root root -\n", "d /run/niko 0755 root root -\nd /run/niko/%h 2750 rayd niko-front -\n"),
		"another polkit rule":     set("/etc/polkit-1/rules.d/50-raycontrol.rules", `verb == "restart"`, `true`),
		"a firewall file":         set(deploy.FirewalldService, `port="22"`, `port="1-65535"`),
		"the update unit changed": set("/etc/systemd/system/raycontrol-update.service", "ExecStart=/usr/local/bin/rayctl update -request", "ExecStart=/tmp/x"),
		"user root":               func(p *deploy.Plan) { p.Users = append(p.Users, deploy.SystemUser{Name: "root", UID: 0}) },
		"a user not ours":         func(p *deploy.Plan) { p.Users = append(p.Users, deploy.SystemUser{Name: "operator", UID: 9120}) },
		"a service UID 0":         user("niko-dns", func(u *deploy.SystemUser) { u.UID = 0 }),
		"rayd's UID":              user("rayd", func(u *deploy.SystemUser) { u.UID = 0 }),
		"a UID twice":             user("niko-dns", func(u *deploy.SystemUser) { u.UID = 9110 }),
		"rayd in docker":          user("rayd", func(u *deploy.SystemUser) { u.ExtraGroups = append(u.ExtraGroups, "docker") }),
		"a group list":            user("niko-reality", func(u *deploy.SystemUser) { u.ExtraGroups = []string{"niko-front,disk"} }),
		"a group not the plan's":  user("niko-reality", func(u *deploy.SystemUser) { u.ExtraGroups = []string{"niko-site"} }),
		"debug-shell":             func(p *deploy.Plan) { p.Units = append(p.Units, "debug-shell.service") },
		"the update service":      func(p *deploy.Plan) { p.Units = append(p.Units, "raycontrol-update.service") },
		"a unit twice":            func(p *deploy.Plan) { p.Units = append(p.Units, "niko-dns.service") },
		"User=root":               set(dns, "User=niko-dns\n", "User=root\n"),
		"another service's user":  set(dns, "User=niko-dns\n", "User=niko-inner\n"),
		"no user":                 set(dns, "User=niko-dns\n", ""),
		"a second user":           set(dns, "Group=niko-dns\n", "Group=niko-dns\nUser=root\n"),
		"ExecStartPre=+/bin/sh":   set(dns, "ExecStart=", "ExecStartPre=+/bin/sh -c id\nExecStart="),
		"ExecStartPre=!":          set(dns, "ExecStart=", "ExecStartPre=!/usr/local/bin/rayd credential /var/lib raycontrol/rendered/dns/noise.key rayd niko-dns /run/niko/dns/noise.key\nExecStart="),
		"ExecStartPost":           set(dns, "ExecStart=", "ExecStartPost=/bin/true\nExecStart="),
		"another binary":          set(dns, "ExecStart=/usr/local/libexec/raycontrol/niko-server", "ExecStart=/bin/sh"),
		"a prefix on ExecStart":   set(dns, "ExecStart=/usr/local/libexec/raycontrol/niko-server", "ExecStart=+/usr/local/libexec/raycontrol/niko-server"),
		"a copy of /etc/shadow":   set(dns, "credential /var/lib raycontrol/rendered/dns/noise.key", "credential /etc shadow"),
		"a copy out of rendered":  set(dns, "raycontrol/rendered/dns/noise.key", "raycontrol/rayd.db"),
		"a copy by ..":            set(dns, "raycontrol/rendered/dns/noise.key", "raycontrol/rendered/../rayd.db"),
		"a copy for another":      set(dns, "noise.key rayd niko-dns /run/niko/dns/", "noise.key rayd root /run/niko/dns/"),
		"a copy elsewhere":        set(dns, "niko-dns /run/niko/dns/noise.key", "niko-dns /etc/shadow"),
		"a copy into the front's": set(dns, "niko-dns /run/niko/dns/noise.key", "niko-dns /run/niko/front/noise.key"),
		// The review's probes: a second command after ;, words systemd
		// would unquote or expand, a command not the unit's, copies from
		// elsewhere.
		"a second command after ;":      set(dns, "ExecStart=/usr/local/libexec/raycontrol/niko-server ", "ExecStart=/usr/local/libexec/raycontrol/niko-server ; +/bin/sh -c id ; "),
		"a quoted word":                 set(dns, "ExecStart=/usr/local/libexec/raycontrol/niko-server backend -c ", "ExecStart=/usr/local/libexec/raycontrol/niko-server backend -c '/etc/shadow' "),
		"a variable":                    set(dns, "ExecStart=/usr/local/libexec/raycontrol/niko-server backend -c ", "ExecStart=/usr/local/libexec/raycontrol/niko-server backend -c $HOME "),
		"rayd credential as ExecStart":  set(dns, "ExecStart=/usr/local/libexec/raycontrol/niko-server backend -c /var/lib/raycontrol/rendered/dns/backend.json", "ExecStart=/usr/local/bin/rayd credential /etc shadow rayd niko-dns /run/niko/dns/x"),
		"rayd serve as a service":       set(dns, "ExecStart=/usr/local/libexec/raycontrol/niko-server backend", "ExecStart=/usr/local/bin/rayd serve"),
		"the front's command elsewhere": set(dns, "ExecStart=/usr/local/libexec/raycontrol/niko-server backend", "ExecStart=/usr/local/libexec/raycontrol/niko-server front"),
		"a quoted copy destination":     set(dns, "niko-dns /run/niko/dns/noise.key", "niko-dns /run/niko/dns/'..'"),
		"another service's secret":      set(dns, "raycontrol/rendered/dns/noise.key rayd niko-dns", "raycontrol/rendered/inner/xray.json rayd niko-dns"),
		"the front from a service's":    set(front, "raycontrol/rendered/front/dnsprobe.key", "raycontrol/rendered/dns/noise.key"),
		"a copy from below its dir":     set(dns, "raycontrol/rendered/dns/noise.key", "raycontrol/rendered/dns/sub/noise.key"),
		"a rendered file of root's":     set(dns, "noise.key rayd niko-dns", "noise.key root niko-dns"),
		// The owner word is what defeats the hard-link race (rayd links
		// root's file into rendered/ and drops the link after root's
		// open): a file of root's is never rayd's, whatever its links.
		// Root, or the service's own user, for rendered/ is refused.
		"the owner root for rendered/":     set(dns, "rendered/dns/noise.key rayd ", "rendered/dns/noise.key root "),
		"the owner niko-dns for rendered/": set(dns, "rendered/dns/noise.key rayd ", "rendered/dns/noise.key niko-dns "),
		// Only clean paths (second review, F): refused here, not at the
		// start.
		"a copy to the directory's parent": set(dns, "niko-dns /run/niko/dns/noise.key", "niko-dns /run/niko/dns/.."),
		"a copy to the directory itself":   set(dns, "niko-dns /run/niko/dns/noise.key", "niko-dns /run/niko/dns/."),
		"a copy to an unclean path":        set(dns, "niko-dns /run/niko/dns/noise.key", "niko-dns /run/niko//dns/noise.key"),
		"a copy of the directory itself":   set(dns, "raycontrol/rendered/dns/noise.key", "raycontrol/rendered/dns/."),
		"an unclean anchor":                set(dns, "credential /var/lib raycontrol", "credential /var/lib/ raycontrol"),
		"the relay's bundle to niko":       set(dns, "credential /var/lib raycontrol/rendered/dns/noise.key rayd niko-dns", "credential /etc/raycontrol relay.bundle root niko-dns"),
		"a copy by another binary":         set(dns, "ExecStartPre=+/usr/local/bin/rayd credential ", "ExecStartPre=+/usr/local/libexec/raycontrol/xray credential "),
		"rayd's other command as root":     set(dns, "ExecStartPre=+/usr/local/bin/rayd credential ", "ExecStartPre=+/usr/local/bin/rayd naive "),
		"a specifier in a description":     set(dns, "Description=", "Description=%h "),
		"an escape in a description":       set(dns, "Description=", "Description=\x1b[2J"),
		"EnvironmentFile":                  set(dns, "UMask=0007\n", "UMask=0007\nEnvironmentFile=/var/lib/raycontrol/env\n"),
		"BindPaths":                        set(dns, "UMask=0007\n", "UMask=0007\nBindPaths=/etc\n"),
		"a continuation":                   set(dns, "UMask=0007\n", "UMask=0007 \\\n"),
		"a specifier":                      set(dns, "ExecStart=/usr/local/libexec/raycontrol/niko-server backend", "ExecStart=/usr/local/libexec/raycontrol/niko-server %h"),
		"a carriage return":                set(dns, "UMask=0007\n", "UMask=0007\r\nUser=root\n"),
		"hardening off":                    set(dns, "NoNewPrivileges=yes\n", "NoNewPrivileges=no\n"),
		"hardening twice":                  set(dns, "NoNewPrivileges=yes\n", "NoNewPrivileges=yes\nNoNewPrivileges=no\n"),
		"hardening gone":                   set(dns, "ProtectSystem=strict\n", ""),
		"CAP_SYS_ADMIN":                    set(front, "CapabilityBoundingSet=CAP_NET_BIND_SERVICE", "CapabilityBoundingSet=CAP_SYS_ADMIN"),
		"CAP_NET_ADMIN for niko":           set(front, "AmbientCapabilities=CAP_NET_BIND_SERVICE", "AmbientCapabilities=CAP_NET_ADMIN"),
		"a group not niko":                 set(dns, "SupplementaryGroups=niko-inner", "SupplementaryGroups=niko-inner disk"),
		"ReadWritePaths /etc":              set(dns, "ReadWritePaths=/run/niko/dns-in", "ReadWritePaths=/etc"),
		"another runtime dir":              set(dns, "RuntimeDirectory=niko/dns", "RuntimeDirectory=niko/front"),
		"a section of its own":             set(dns, "[Install]", "[Socket]\nListenStream=/run/x\n[Install]"),
		"a port out of range":              func(p *deploy.Plan) { p.HostPorts[0].From = 0 },
		"a protocol":                       func(p *deploy.Plan) { p.HostPorts[0].Proto = "sctp" },
	} {
		p := clonePlan(good)
		f(&p)
		err := p.Check()
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// Refused before anything changes: no command, no file.
		root := t.TempDir()
		var cmds []string
		h := &deploy.Host{Root: root, Out: &bytes.Buffer{},
			Run:         func(name string, args ...string) ([]byte, error) { cmds = append(cmds, name); return nil, nil },
			LookupUser:  func(string) (int, error) { return 0, errors.New("unknown") },
			LookupGroup: func(string) (int, error) { return 0, errors.New("unknown") },
		}
		if err := h.Apply(p); err == nil || len(cmds) != 0 {
			t.Errorf("%s: applied (%v), ran %v", name, err, cmds)
		}
		if left, _ := os.ReadDir(root); len(left) != 0 {
			t.Errorf("%s: wrote %v", name, left)
		}
	}
	// The good plan is untouched by the cases above.
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
}

// The relay's units copy the bundle, root's, and nothing else.
func TestPlanCheckRelay(t *testing.T) {
	good := deploy.RelayPlan(deploy.DefaultBinaries)
	unit := "/etc/systemd/system/rayspa.service"
	for name, c := range map[string][2]string{
		"the bundle as rayd's":   {"relay.bundle root rayspa", "relay.bundle rayd rayspa"},
		"a rendered file":        {"credential /etc/raycontrol relay.bundle root rayspa", "credential /var/lib raycontrol/rendered/front/dnsprobe.key rayd rayspa"},
		"another file of /etc":   {"credential /etc/raycontrol relay.bundle", "credential /etc/raycontrol shadow"},
		"to another unit's dir":  {"rayspa /run/rayspa/relay.bundle", "rayspa /run/rayd-relay/relay.bundle"},
		"a second command after": {"ExecStart=/usr/local/bin/rayspa run ", "ExecStart=/usr/local/bin/rayspa run ; /bin/sh ; "},
	} {
		p := clonePlan(good)
		edit(t, &p, unit, c[0], c[1])
		if err := p.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every plan rayctl makes passes: Build of each test model, with other
// inputs too, the control plane alone (rayctl install's first step), and a
// relay's (spec/apply-plan-v1.md §3.6).
func TestPlanCheckAcceptsOurs(t *testing.T) {
	plans := map[string]deploy.Plan{
		"relay":         deploy.RelayPlan(deploy.DefaultBinaries),
		"control plane": deploy.Build(deploy.Inputs{}, render.DefaultPaths, deploy.DefaultBinaries),
		"good inputs":   deploy.Build(goodInputs(), render.DefaultPaths, deploy.DefaultBinaries),
		"test node":     fullPlan(t),
	}
	without := goodInputs()
	without.FrontTCP, without.Front = false, false
	plans["REALITY on TCP 443 itself"] = deploy.Build(without, render.DefaultPaths, deploy.DefaultBinaries)
	icmp := goodInputs()
	icmp.Services[4].ICMP = true
	plans["naive with ICMP"] = deploy.Build(icmp, render.DefaultPaths, deploy.DefaultBinaries)
	if p := plans["naive with ICMP"]; !p.ICMP || !strings.Contains(file(p, "/etc/systemd/system/niko-naive.service"), " -icmp\n") {
		t.Fatal("naive with ICMP: no -icmp")
	}
	for name, services := range map[string][][3]string{
		"self-steal":      {{"reality", "r", ""}, {"doh", "doh", ""}},
		"hysteria":        {{"hy2-masq", "hy2-masq", ""}, {"hy2-obfs", "hy2-obfs", ""}},
		"naive":           {{"reality", "reality", ""}, {"naive", "naive", ""}},
		"slipstream":      {{"slipstream", "slip", ""}},
		"yggdrasil":       {{"reality", "reality", ""}, {"yggdrasil", "ygg", ""}},
		"every kind":      {{"reality", "reality", ""}, {"naive", "naive", ""}, {"doh", "doh", ""}, {"yggdrasil", "ygg", ""}, {"hy2-masq", "hm", ""}, {"hy2-obfs", "ho", ""}, {"dnstt", "dns", ""}, {"masterdns", "mdns", ""}, {"slipstream", "slip", ""}, {"api", "api", ""}, {"ssh", "ssh", ""}, {"olcrtc", "olc", ""}},
		"masterdns alone": {{"masterdns", "mdns", ""}},
		"naive, ICMP":     {{"reality", "reality", ""}, {"naive", "naive", `{"icmp":true}`}},
	} {
		m, files := buildModel(t, render.DefaultPaths, services, nil)
		plans[name] = build(m, files, render.DefaultPaths)
	}
	for name, p := range plans {
		if err := p.Check(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// naive's ICMP: the ping groups' sysctl file is root's own, not the
	// plan's (spec/icmp-v1.md §3): Check does not see it, and a second
	// apply neither refuses nor removes it.
	{
		root := t.TempDir()
		value := "1 0"
		h := &deploy.Host{Root: root, Out: &bytes.Buffer{},
			Run: func(name string, args ...string) ([]byte, error) {
				if name+" "+strings.Join(args, " ") == "sysctl -n "+deploy.PingGroupRange {
					return []byte(value + "\n"), nil
				}
				return nil, nil
			},
			LookupUser: func(string) (int, error) { return 0, errors.New("unknown") }, LookupGroup: func(string) (int, error) { return 0, errors.New("unknown") },
			LookPath: func(string) (string, error) { return "", errors.New("none") }}
		p := plans["naive with ICMP"]
		for range 2 {
			if err := h.Apply(p, "rayd.service"); err != nil {
				t.Fatal(err)
			}
			if b, err := os.ReadFile(filepath.Join(root, deploy.PingSysctl)); err != nil || !strings.Contains(string(b), deploy.PingGroupRange+" = 9100 9179") {
				t.Fatalf("%s: %q %v", deploy.PingSysctl, b, err)
			}
		}
		if err := p.Check(); err != nil {
			t.Fatal(err)
		}
	}
	// The relay's plan goes through Apply too.
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "/etc"), 0o755)
	h := &deploy.Host{Root: root, Out: &bytes.Buffer{}, Run: func(string, ...string) ([]byte, error) { return nil, nil },
		LookupUser: func(string) (int, error) { return 0, errors.New("unknown") }, LookupGroup: func(string) (int, error) { return 0, errors.New("unknown") },
		LookPath: func(string) (string, error) { return "", errors.New("none") }}
	if err := h.Apply(plans["relay"], "rayspa.service"); err != nil {
		t.Fatal(err)
	}
}
