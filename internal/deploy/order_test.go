package deploy_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/render"
)

// The ordering lines ([Unit] only) of the units rayspa's start meets at
// boot, copied from their upstream files, not written from memory. A stub
// is a oneshot (a target, a socket as it is) with the lines below.
var orderingStubs = map[string]string{
	// systemd v255:
	// https://github.com/systemd/systemd/tree/v255/units
	"sysinit.target":                 "Wants=local-fs.target swap.target\nAfter=local-fs.target swap.target\nConflicts=emergency.service emergency.target\nBefore=emergency.service emergency.target",
	"basic.target":                   "Requires=sysinit.target\nWants=sockets.target timers.target paths.target slices.target\nAfter=sysinit.target sockets.target paths.target slices.target tmp.mount",
	"sockets.target":                 "",
	"local-fs.target":                "DefaultDependencies=no\nAfter=local-fs-pre.target\nConflicts=shutdown.target",
	"shutdown.target":                "DefaultDependencies=no\nRefuseManualStart=yes",
	"network-pre.target":             "RefuseManualStart=yes",
	"network.target":                 "After=network-pre.target\nRefuseManualStart=yes",
	"network-online.target":          "After=network.target",
	"systemd-tmpfiles-setup.service": "DefaultDependencies=no\nAfter=local-fs.target systemd-sysusers.service systemd-journald.service\nBefore=sysinit.target\nConflicts=shutdown.target initrd-switch-root.target\nBefore=shutdown.target initrd-switch-root.target",
	"systemd-sysctl.service":         "DefaultDependencies=no\nConflicts=shutdown.target\nAfter=systemd-modules-load.service\nBefore=sysinit.target shutdown.target",
	"systemd-journald.socket":        "DefaultDependencies=no\nBefore=sockets.target",
	// systemd-networkd.service.in, systemd-networkd-wait-online.service.in
	"systemd-networkd.service": "DefaultDependencies=no\nAfter=systemd-networkd.socket systemd-udevd.service network-pre.target systemd-sysusers.service systemd-sysctl.service\n" +
		"Before=network.target multi-user.target shutdown.target initrd-switch-root.target\nConflicts=shutdown.target initrd-switch-root.target\nWants=systemd-networkd.socket network.target",
	"systemd-networkd-wait-online.service": "DefaultDependencies=no\nConflicts=shutdown.target\nBindsTo=systemd-networkd.service\nAfter=systemd-networkd.service\nBefore=network-online.target shutdown.target",

	// cloud-init 24.x and later, Debian and Ubuntu variant (rendered from
	// the templates as the packages are), with the network stage of its own:
	// https://github.com/canonical/cloud-init/tree/main/systemd
	// (cloud-init-main.service.tmpl, cloud-init-local.service.tmpl,
	// cloud-init-network.service.tmpl, cloud-config.service,
	// cloud-config.target, cloud-final.service, cloud-init.target).
	"cloud-init-main.service":  "DefaultDependencies=no\nAfter=systemd-remount-fs.service\nBefore=cloud-init-local.service\nBefore=shutdown.target\nConflicts=shutdown.target\nRequiresMountsFor=/var/lib/cloud",
	"cloud-init-local.service": "DefaultDependencies=no\nWants=network-pre.target\nAfter=hv_kvp_daemon.service\nBefore=network-pre.target\nBefore=shutdown.target\nBefore=sysinit.target\nConflicts=shutdown.target",
	"cloud-init-network.service": "DefaultDependencies=no\nWants=cloud-init-local.service\nWants=sshd-keygen.service\nWants=sshd.service\nAfter=cloud-init-local.service\n" +
		"After=systemd-networkd-wait-online.service\nAfter=networking.service\nBefore=network-online.target\nBefore=sshd-keygen.service\nBefore=sshd.service\n" +
		"Before=systemd-user-sessions.service\nBefore=sysinit.target\nBefore=shutdown.target\nConflicts=shutdown.target",
	"cloud-config.target":  "Wants=cloud-init-local.service cloud-init-network.service\nAfter=cloud-init-local.service cloud-init-network.service",
	"cloud-config.service": "After=network-online.target cloud-config.target\nWants=network-online.target cloud-config.target",
	"cloud-final.service":  "After=network-online.target time-sync.target cloud-config.service rc-local.service\nAfter=multi-user.target\nBefore=apt-daily.service\nWants=network-online.target cloud-config.service",
	"cloud-init.target":    "After=multi-user.target\nWants=cloud-init-main.service cloud-init-local.service cloud-init-network.service cloud-config.service cloud-final.service",

	// cloud-init before 24.1, one network-stage unit, cloud-init.service
	// (Debian variant): https://github.com/canonical/cloud-init/tree/23.4/systemd
	"cloud-init.service": "DefaultDependencies=no\nWants=cloud-init-local.service\nWants=sshd-keygen.service\nWants=sshd.service\nAfter=cloud-init-local.service\n" +
		"After=systemd-networkd-wait-online.service\nAfter=networking.service\nBefore=network-online.target\nBefore=sshd-keygen.service\nBefore=sshd.service\n" +
		"Before=sysinit.target\nBefore=shutdown.target\nConflicts=shutdown.target",

	// Debian's ifupdown:
	// https://salsa.debian.org/debian/ifupdown/-/blob/master/debian/networking.service
	"networking.service": "DefaultDependencies=no\nWants=network.target ifupdown-pre.service\n" +
		"After=local-fs.target network-pre.target apparmor.service systemd-sysctl.service systemd-modules-load.service ifupdown-pre.service\n" +
		"Before=network.target shutdown.target network-online.target\nConflicts=shutdown.target",

	// NetworkManager:
	// https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/tree/main/data
	// (NetworkManager.service.in, NetworkManager-wait-online.service.in);
	// and the D-Bus it binds to,
	// https://gitlab.freedesktop.org/dbus/dbus/-/tree/main/bus (dbus.service.in, dbus.socket.in).
	"NetworkManager.service":             "Wants=network.target\nAfter=network-pre.target dbus.service\nBefore=network.target\nBindsTo=dbus.service",
	"NetworkManager-wait-online.service": "Requires=NetworkManager.service\nAfter=NetworkManager.service\nBefore=network-online.target",
	"dbus.service":                       "Requires=dbus.socket",
	"dbus.socket":                        "",

	// OpenSSH, Debian and Ubuntu (Ubuntu's ssh.socket, on by default since
	// 22.10, is this file; a generator sets its ports):
	// https://salsa.debian.org/ssh-team/openssh/-/tree/master/debian/systemd
	"ssh.service": "After=network.target nss-user-lookup.target auditd.service",
	"ssh.socket":  "Before=sockets.target",
	// Fedora and RHEL: https://src.fedoraproject.org/rpms/openssh/blob/rawhide/f/sshd.service
	"sshd.service": "After=network.target sshd-keygen.target\nWants=sshd-keygen.target",

	// Host firewalls. Debian's nftables:
	// https://salsa.debian.org/pkg-netfilter-team/pkg-nftables/-/blob/master/debian/nftables.service
	"nftables.service": "Wants=network-pre.target\nBefore=network-pre.target shutdown.target\nConflicts=shutdown.target\nDefaultDependencies=no",
	// ufw: https://git.launchpad.net/ufw/tree/doc/systemd.example
	"ufw.service": "DefaultDependencies=no\nBefore=network-pre.target\nWants=network-pre.target local-fs.target\nAfter=local-fs.target\n" +
		"Conflicts=iptables.service ip6tables.service nftables.service firewalld.service",
	// firewalld, with its default dependencies:
	// https://github.com/firewalld/firewalld/blob/main/config/firewalld.service.in
	"firewalld.service": "Before=network-pre.target\nWants=network-pre.target\nPartOf=dbus.service\nConflicts=iptables.service ip6tables.service ebtables.service ipset.service",
}

// cloud-init's RHEL variant of the same templates: its network stage
// keeps the default dependencies, after NetworkManager.
var rhelStubs = map[string]string{
	"cloud-init-main.service":  "DefaultDependencies=no\nRequires=dbus.socket\nAfter=dbus.socket\nAfter=systemd-remount-fs.service\nBefore=cloud-init-local.service\nBefore=shutdown.target\nConflicts=shutdown.target",
	"cloud-init-local.service": "DefaultDependencies=no\nWants=network-pre.target\nAfter=hv_kvp_daemon.service\nBefore=network-pre.target\nBefore=shutdown.target\nBefore=firewalld.target\nConflicts=shutdown.target",
	"cloud-init-network.service": "Wants=cloud-init-local.service\nWants=sshd-keygen.service\nWants=sshd.service\nAfter=cloud-init-local.service\nAfter=systemd-networkd-wait-online.service\n" +
		"After=NetworkManager.service\nAfter=NetworkManager-wait-online.service\nBefore=network-online.target\nBefore=sshd-keygen.service\nBefore=sshd.service\nBefore=systemd-user-sessions.service",
}

// ubuntuStubs: cloud-init's Ubuntu variant is not after
// systemd-networkd-wait-online.service (netplan's networkd is waited for
// otherwise).
var ubuntuStubs = map[string]string{
	"cloud-init-network.service": "DefaultDependencies=no\nWants=cloud-init-local.service\nWants=sshd-keygen.service\nWants=sshd.service\nAfter=cloud-init-local.service\n" +
		"After=networking.service\nBefore=network-online.target\nBefore=sshd-keygen.service\nBefore=sshd.service\n" +
		"Before=systemd-user-sessions.service\nBefore=sysinit.target\nBefore=shutdown.target\nConflicts=shutdown.target",
}

type bootScenario struct {
	name  string
	units []string          // started at boot besides the targets and rayspa's plan
	over  map[string]string // a variant's own stubs
	// network are the units that give interfaces their addresses, ssh the
	// SSH daemons: all of them start only after rayspa is ready.
	network, ssh []string
}

var cloudInit24 = []string{"cloud-init.target", "cloud-init-main.service", "cloud-init-local.service", "cloud-init-network.service",
	"cloud-config.target", "cloud-config.service", "cloud-final.service"}

var bootScenarios = []bootScenario{
	{name: "debian-cloud-init-24-ifupdown", units: append(slices.Clone(cloudInit24), "networking.service", "ssh.service", "nftables.service"),
		network: []string{"networking.service"}, ssh: []string{"ssh.service"}},
	{name: "debian-cloud-init-23-ifupdown", units: []string{"cloud-init.target", "cloud-init-local.service", "cloud-init.service",
		"cloud-config.service", "cloud-final.service", "networking.service", "ssh.service", "nftables.service"},
		network: []string{"networking.service"}, ssh: []string{"ssh.service"}},
	{name: "debian-cloud-init-24-networkd", units: append(slices.Clone(cloudInit24), "systemd-networkd.service", "systemd-networkd-wait-online.service",
		"ssh.service", "nftables.service"), network: []string{"systemd-networkd.service"}, ssh: []string{"ssh.service"}},
	{name: "ubuntu-cloud-init-24-networkd-ssh-socket", units: append(slices.Clone(cloudInit24), "systemd-networkd.service",
		"systemd-networkd-wait-online.service", "ssh.socket", "ssh.service", "ufw.service"), over: ubuntuStubs,
		network: []string{"systemd-networkd.service"}, ssh: []string{"ssh.service"}},
	{name: "rhel-cloud-init-24-networkmanager-firewalld", units: append(slices.Clone(cloudInit24), "NetworkManager.service",
		"NetworkManager-wait-online.service", "dbus.service", "dbus.socket", "sshd.service", "firewalld.service"), over: rhelStubs,
		network: []string{"NetworkManager.service"}, ssh: []string{"sshd.service"}},
	{name: "debian-ifupdown", units: []string{"networking.service", "ssh.service", "nftables.service", "ufw.service"},
		network: []string{"networking.service"}, ssh: []string{"ssh.service"}},
	{name: "networkd-firewalld", units: []string{"systemd-networkd.service", "systemd-networkd-wait-online.service", "ssh.service",
		"firewalld.service", "dbus.service", "dbus.socket"}, network: []string{"systemd-networkd.service"}, ssh: []string{"ssh.service"}},
	{name: "networkmanager", units: []string{"NetworkManager.service", "NetworkManager-wait-online.service", "dbus.service",
		"dbus.socket", "sshd.service", "nftables.service"}, network: []string{"NetworkManager.service"}, ssh: []string{"sshd.service"}},
}

// writeBoot writes a scenario's stubs and the plan's units into dir, with a
// multi-user.target that wants all of them (as the enabled units' links
// would), and returns the unit files to verify.
func writeBoot(t *testing.T, dir string, sc bootScenario, plan deploy.Plan, rayspa func(string) string) []string {
	t.Helper()
	write := func(name, unitLines string) {
		body := "[Unit]\nDescription=stub " + name + "\n" + unitLines + "\n"
		switch {
		case strings.HasSuffix(name, ".service"):
			body += "\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n"
		case strings.HasSuffix(name, ".socket"):
			body += "\n[Socket]\nListenStream=@raycontrol-test-" + name + "\n"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wants := slices.Clone(sc.units)
	for _, name := range []string{"sysinit.target", "basic.target", "sockets.target", "local-fs.target", "shutdown.target",
		"network-pre.target", "network.target", "network-online.target", "systemd-tmpfiles-setup.service",
		"systemd-sysctl.service", "systemd-journald.socket"} {
		write(name, orderingStubs[name])
	}
	for _, name := range sc.units {
		lines, ok := sc.over[name]
		if !ok {
			lines, ok = orderingStubs[name]
		}
		if !ok {
			t.Fatalf("no stub for %s", name)
		}
		write(name, lines)
	}
	var verify []string
	for _, f := range plan.Files {
		dirName, name := filepath.Split(f.Path)
		if dirName != "/etc/systemd/system/" {
			continue
		}
		content := string(f.Content)
		if name == "rayspa.service" && rayspa != nil {
			content = rayspa(content)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		wants = append(wants, name)
		verify = append(verify, filepath.Join(dir, name))
	}
	write("multi-user.target", "Requires=basic.target\nConflicts=rescue.service rescue.target\nAfter=basic.target rescue.service rescue.target\nWants="+
		strings.Join(wants, " "))
	return append([]string{filepath.Join(dir, "multi-user.target")}, verify...)
}

// analyze runs systemd-analyze verify on the files with dir as the only
// unit path, and returns what it printed.
func analyze(t *testing.T, bin, dir string, files []string) string {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"verify", "--man=no"}, files...)...) //nolint:gosec // G204: the test's own files
	cmd.Env = append(os.Environ(), "SYSTEMD_UNIT_PATH="+dir, "SYSTEMD_LOG_LEVEL=notice")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run() // a cycle is broken, not an error: the output says
	return out.String()
}

// befores is the ordering of the units in dir: who starts before whom, by
// After= and Before=, transitively.
func before(t *testing.T, dir, first, then string) bool {
	t.Helper()
	edges := map[string][]string{} // a -> units ordered after a
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(b), "\n") {
			k, v, _ := strings.Cut(l, "=")
			for _, u := range strings.Fields(v) {
				switch k {
				case "After":
					edges[u] = append(edges[u], e.Name())
				case "Before":
					edges[e.Name()] = append(edges[e.Name()], u)
				}
			}
		}
	}
	seen := map[string]bool{first: true}
	queue := []string{first}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, v := range edges[u] {
			if v == then {
				return true
			}
			if !seen[v] {
				seen[v] = true
				queue = append(queue, v)
			}
		}
	}
	return false
}

// rayspa's unit closes no ordering cycle at boot, with cloud-init's stages
// (24.x and the older single network stage), ifupdown, systemd-networkd and
// NetworkManager, OpenSSH (service and socket) and the host firewalls; and
// no interface gets its address, nor does sshd start, before rayspa is
// ready (its table in, R4-40). systemd-analyze verify finds the cycles,
// as systemd would at boot; without it the test is skipped, but not in CI
// (RAYCONTROL_REQUIRE_SYSTEMD_ANALYZE=1).
func TestRayspaNoOrderingCycle(t *testing.T) {
	bin, err := exec.LookPath("systemd-analyze")
	if err != nil {
		if os.Getenv("RAYCONTROL_REQUIRE_SYSTEMD_ANALYZE") != "" {
			t.Fatal("no systemd-analyze here")
		}
		t.Skip("no systemd-analyze here")
	}
	// ExecStart's binaries must exist for verify: any executable does.
	bins := deploy.Binaries{Rayd: "/bin/true", Rayspa: "/bin/true", NikoServer: "/bin/true", Xray: "/bin/true", Slipstream: "/bin/true"}
	plans := map[string]deploy.Plan{
		"node":  deploy.Build(deploy.Inputs{}, render.DefaultPaths, bins),
		"relay": deploy.RelayPlan(bins),
	}
	for _, sc := range bootScenarios {
		for kind, plan := range plans {
			t.Run(sc.name+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				out := analyze(t, bin, dir, writeBoot(t, dir, sc, plan, nil))
				if strings.Contains(out, "ordering cycle") || strings.Contains(out, "to break ordering cycle") {
					t.Fatalf("systemd-analyze verify:\n%s", out)
				}
				if testing.Verbose() && strings.TrimSpace(out) != "" {
					t.Logf("systemd-analyze verify:\n%s", out)
				}
				for _, u := range slices.Concat(sc.network, sc.ssh) {
					if !before(t, dir, "rayspa.service", u) {
						t.Errorf("%s is not ordered after rayspa.service", u)
					}
				}
			})
		}
	}
	// The harness finds the cycle the default dependencies made (the unit
	// of v0.27.0's first build): or a systemd-analyze that reports none
	// would pass everything above.
	t.Run("default dependencies cycle", func(t *testing.T) {
		dir := t.TempDir()
		old := func(u string) string {
			return strings.Replace(strings.Replace(u, "DefaultDependencies=no\n", "", 1),
				"After=local-fs.target systemd-tmpfiles-setup.service systemd-sysctl.service ", "After=", 1)
		}
		out := analyze(t, bin, dir, writeBoot(t, dir, bootScenarios[0], plans["node"], old))
		if !strings.Contains(out, "ordering cycle") {
			t.Fatalf("no cycle found with the default dependencies:\n%s", out)
		}
	})
}
