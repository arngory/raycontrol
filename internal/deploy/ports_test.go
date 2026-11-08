package deploy_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
)

func ports(rs ...string) []deploy.PortRange {
	var out []deploy.PortRange
	for _, r := range rs {
		proto, nums, _ := strings.Cut(r, "/")
		a, b, ok := strings.Cut(nums, "-")
		if !ok {
			b = a
		}
		out = append(out, deploy.PortRange{Proto: proto, From: atou16(a), To: atou16(b)})
	}
	return out
}

func atou16(s string) uint16 {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return uint16(n)
}

// The value apply sets (net.ipv4.ip_local_reserved_ports): the host's
// ports from 1024, merged, whatever the protocol; what else is reserved
// stays, what raycontrol reserved before and no longer listens on goes.
func TestReservedValue(t *testing.T) {
	node := ports("tcp/42000-43023", "udp/42000-43023", "udp/53", "tcp/443", "udp/443", "tcp/60718", "udp/60718", "tcp/51000")
	for _, c := range []struct {
		name, live, before string
		ports              []deploy.PortRange
		value, own         string
	}{
		{"a node", "", "", node, "42000-43023,51000,60718", "42000-43023,51000,60718"},
		{"merged where they touch", "", "", ports("tcp/2000-2009", "udp/2010", "tcp/2012", "tcp/2011"), "2000-2012", "2000-2012"},
		{"from 1024", "", "", ports("tcp/1000-1100", "tcp/22", "udp/1023"), "1024-1100", "1024-1100"},
		{"another's kept", "8080,9000-9010", "", node, "8080,9000-9010,42000-43023,51000,60718", "42000-43023,51000,60718"},
		{"another's below 1024 kept", "443", "", node, "443,42000-43023,51000,60718", "42000-43023,51000,60718"},
		{"another's within ours", "42500", "", node, "42000-43023,51000,60718", "42000-43023,51000,60718"},
		{"ours before goes", "8080,42000-43023,50000", "42000-43023,50000", ports("tcp/44000-44099"), "8080,44000-44099", "44000-44099"},
		{"ours again, another's stays", "8080,42000-43023,51000,60718", "42000-43023,51000,60718", node, "8080,42000-43023,51000,60718", "42000-43023,51000,60718"},
		{"another's beside ours stays", "41000-45000", "42000-43023", ports("tcp/50000"), "41000-41999,43024-45000,50000", "50000"},
		{"spaces and tabs", " 8080,\t9000 \n", "", ports("tcp/50000"), "8080,9000,50000", "50000"},
		{"our file garbled: nothing taken away", "8080,42000-43023", "x-y", ports("tcp/50000"), "8080,42000-43023,50000", "50000"},
	} {
		value, own, err := deploy.ReservedValue(c.live, c.before, c.ports)
		if err != nil || value != c.value || own != c.own {
			t.Errorf("%s: %q own %q, %v; want %q own %q", c.name, value, own, err, c.value, c.own)
		}
	}
	for _, live := range []string{"abc", "9000-8000", "70000", "1,,2", "-5"} {
		if _, _, err := deploy.ReservedValue(live, "", node); err == nil {
			t.Errorf("%q read as ports", live)
		}
	}
	for _, c := range []struct{ live, missing string }{
		{"42000-43023,51000,60718", ""},
		{"1024-65535", ""},
		{"", "42000-43023,51000,60718"},
		{"42000-42999,60718", "43000-43023,51000"},
	} {
		if m, err := deploy.MissingReserved(c.live, node); err != nil || m != c.missing {
			t.Errorf("missing from %q: %q %v, want %q", c.live, m, err, c.missing)
		}
	}
}

// A relay listens on its SPA slots (rayspa's TCP carrier) and its probe
// endpoint.
func TestRelayPorts(t *testing.T) {
	for _, c := range []struct {
		base, rng uint32
		probe     uint16
		want      string
	}{
		{30000, 1024, 45000, "[tcp/45000 udp/45000 tcp/30000-31023 udp/30000-31023]"},
		{30000, 1024, 0, "[tcp/30000-31023 udp/30000-31023]"},
		{0, 0, 45000, "[tcp/45000 udp/45000]"},        // no snapshot's SPA
		{65000, 4096, 45000, "[tcp/45000 udp/45000]"}, // past 65535: not ports
	} {
		if got := deploy.RelayPorts(c.base, c.rng, c.probe); fmtRanges(got) != c.want {
			t.Errorf("%d+%d, probe %d: %s", c.base, c.rng, c.probe, fmtRanges(got))
		}
	}
}

func fmtRanges(rs []deploy.PortRange) string {
	s := make([]string, len(rs))
	for i, r := range rs {
		s[i] = r.String()
	}
	return "[" + strings.Join(s, " ") + "]"
}

// sysctlHost is a host whose net.ipv4.ip_local_reserved_ports is value:
// sysctl -n reads it, sysctl -p and -w set it (unless locked, a container
// that does not let it change).
type sysctlHost struct {
	root   string
	value  string
	locked bool
	cmds   []string
	out    bytes.Buffer
}

func (s *sysctlHost) host(t *testing.T) *deploy.Host {
	t.Helper()
	h := &deploy.Host{Root: s.root, Out: &s.out,
		Run: func(name string, args ...string) ([]byte, error) {
			cmd := name + " " + strings.Join(args, " ")
			s.cmds = append(s.cmds, cmd)
			switch {
			case cmd == "sysctl -n "+deploy.ReservedPortsKey:
				return []byte(s.value + "\n"), nil
			case cmd == "sysctl -q -e -p "+deploy.PortsSysctl && !s.locked:
				b, _ := os.ReadFile(filepath.Join(s.root, deploy.PortsSysctl))
				for _, l := range strings.Split(string(b), "\n") {
					if v, ok := strings.CutPrefix(l, deploy.ReservedPortsKey+" = "); ok {
						s.value = v
					}
				}
			case strings.HasPrefix(cmd, "sysctl -q -w "+deploy.ReservedPortsKey+"=") && !s.locked:
				s.value = strings.TrimPrefix(cmd, "sysctl -q -w "+deploy.ReservedPortsKey+"=")
			}
			return nil, nil
		},
		LookPath:    func(string) (string, error) { return "", errors.New("not found") },
		LookupUser:  func(string) (int, error) { return 0, errors.New("unknown") },
		LookupGroup: func(string) (int, error) { return 0, errors.New("unknown") },
	}
	j, err := deploy.OpenJournal(s.root)
	if err != nil {
		t.Fatal(err)
	}
	h.Journal = j
	return h
}

// apply reserves the plan's host ports in a sysctl file of its own and
// now, before the units start; keeps the administrator's; updates them as
// the ports change; and uninstall takes the file and the old value back,
// an empty one too.
func TestApplyReservesPorts(t *testing.T) {
	node := ports("tcp/42000-43023", "udp/42000-43023", "udp/53", "tcp/60718", "udp/60718")
	for _, before := range []string{"", "8080"} {
		s := &sysctlHost{root: t.TempDir(), value: before}
		h := s.host(t)
		// A plan with units (the relay's), its binaries there.
		plan := deploy.RelayPlan(deploy.DefaultBinaries)
		plan.HostPorts = node
		for _, bin := range []string{deploy.DefaultBinaries.Rayspa, deploy.DefaultBinaries.Rayd} {
			os.MkdirAll(filepath.Join(s.root, filepath.Dir(bin)), 0o755)
			os.WriteFile(filepath.Join(s.root, bin), nil, 0o755)
		}
		if err := h.Apply(plan); err != nil {
			t.Fatal(err)
		}
		want := strings.TrimPrefix(before+",42000-43023,60718", ",")
		b, err := os.ReadFile(filepath.Join(s.root, deploy.PortsSysctl))
		if err != nil || !strings.Contains(string(b), deploy.ReservedPortsKey+" = "+want+"\n") || s.value != want {
			t.Fatalf("before %q: file %q (%v), now %q", before, b, err, s.value)
		}
		// Reserved before the units start.
		reserved := slicesIndex(s.cmds, "sysctl -q -e -p "+deploy.PortsSysctl)
		started := slicesIndex(s.cmds, "systemctl enable --now rayspa.service")
		if reserved < 0 || started < 0 || reserved > started {
			t.Errorf("before %q: reserved at %d, rayspa started at %d: %v", before, reserved, started, s.cmds)
		}
		if c, ok := h.Journal.Original(deploy.ChangeSysctl, "", deploy.ReservedPortsKey); !ok || c.Value != before {
			t.Errorf("before %q: journaled %+v %v", before, c, ok)
		}
		// The same again: nothing written, nothing set.
		s.cmds, s.out = nil, bytes.Buffer{}
		if err := h.Apply(deploy.Plan{HostPorts: node}); err != nil {
			t.Fatal(err)
		}
		if slicesIndex(s.cmds, "sysctl -q -e -p "+deploy.PortsSysctl) >= 0 || strings.Contains(s.out.String(), "wrote") {
			t.Errorf("before %q: the same ports set again: %v %q", before, s.cmds, s.out.String())
		}
		// Another reserves a port meanwhile; a service goes, SPA moves.
		s.value += ",9000"
		if err := h.Apply(deploy.Plan{HostPorts: ports("tcp/44000-45023", "udp/44000-45023")}); err != nil {
			t.Fatal(err)
		}
		if want := strings.TrimPrefix(before+",9000,44000-45023", ","); s.value != want {
			t.Errorf("before %q: after the change %q, want %q", before, s.value, want)
		}
		// Uninstall: the file goes, the value as it was before raycontrol.
		if err := h.Uninstall(h.Journal, deploy.UninstallOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(s.root, deploy.PortsSysctl)); !os.IsNotExist(err) || s.value != before {
			t.Errorf("before %q: after uninstall %v, value %q", before, err, s.value)
		}
	}
}

// Where the value cannot change (a container), apply warns and goes on;
// a plan without host ports leaves it alone; one past what raycontrol
// listens on (a rayd that says so) is not reserved.
func TestApplyReservedPortsRefusals(t *testing.T) {
	s := &sysctlHost{root: t.TempDir(), locked: true}
	if err := s.host(t).Apply(deploy.Plan{HostPorts: ports("tcp/42000-43023")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.out.String(), "warning: "+deploy.ReservedPortsKey+" is , not 42000-43023") {
		t.Errorf("locked: %q", s.out.String())
	}
	for name, hp := range map[string][]deploy.PortRange{
		"no host ports":    nil,
		"well-known only":  ports("tcp/443", "udp/53"),
		"the whole range":  ports("tcp/1024-65535"),
		"past SPA's slots": ports("tcp/20000-24095", "udp/30000-31100"),
	} {
		s := &sysctlHost{root: t.TempDir(), value: "8080"}
		if err := s.host(t).Apply(deploy.Plan{HostPorts: hp}); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(filepath.Join(s.root, deploy.PortsSysctl))
		if !os.IsNotExist(err) || s.value != "8080" {
			t.Errorf("%s: file %v, value %q", name, err, s.value)
		}
		if big := strings.Contains(name, "range") || strings.Contains(name, "past"); big != strings.Contains(s.out.String(), "none reserved") {
			t.Errorf("%s: said %q", name, s.out.String())
		}
	}
	// SPA's widest slots and the services' ports are reserved.
	s = &sysctlHost{root: t.TempDir()}
	if err := s.host(t).Apply(deploy.Plan{HostPorts: ports("tcp/20000-24095", "udp/20000-24095", "tcp/50000", "udp/50001", "tcp/50002")}); err != nil {
		t.Fatal(err)
	}
	if s.value != "20000-24095,50000-50002" {
		t.Errorf("SPA's widest: %q %q", s.value, s.out.String())
	}
}

func slicesIndex(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}
