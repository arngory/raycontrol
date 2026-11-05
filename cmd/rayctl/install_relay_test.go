package main

import (
	"slices"
	"strings"
	"testing"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// A relay opens one SSH port: sshd's, from its listen addresses, which
// carry the ports of Port too.
func TestSSHDPorts(t *testing.T) {
	for out, want := range map[string][]int{
		"port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n":                 {22},
		"port 2222\naddressfamily any\n":                                             {2222},
		"port 22\nport 2222\nlistenaddress 0.0.0.0:22\nlistenaddress 0.0.0.0:2222\n": {22, 2222},
		// ListenAddress with its own port: Port is not where sshd is.
		"port 22\nlistenaddress 198.51.100.1:2200\n":      {2200},
		"port 22\nlistenaddress 0.0.0.0:22 rdomain red\n": {22},
	} {
		got, err := parseSSHDPorts(out)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %v %v, want %v", out, got, err, want)
		}
	}
	if _, err := parseSSHDPorts("port x\n"); err == nil {
		t.Error("a port that is no number")
	}
}

func TestAdminIncludes(t *testing.T) {
	admin := []string{"203.0.113.9/32", "2001:db8:1::/48"}
	for addr, want := range map[string]bool{
		"203.0.113.9": true, "::ffff:203.0.113.9": true, "2001:db8:1::5": true, "fe80::1%eth0": false,
		"203.0.113.10": false, "": false, "garbage": false,
	} {
		if got := adminIncludes(admin, addr); got != want {
			t.Errorf("%q: %v", addr, got)
		}
	}
}

// The one port the relay opens: configured, listened on, and the one this
// session came in on.
func TestRelaySSHPort(t *testing.T) {
	on := func(ports ...int) func(int) bool { return func(p int) bool { return slices.Contains(ports, p) } }
	for name, c := range map[string]struct {
		sshd    []int
		listen  func(int) bool
		session int
		ok      bool
	}{
		"one":                       {[]int{22}, on(22), 22, true},
		"session not known":         {[]int{2200}, on(2200), 0, true},
		"two":                       {[]int{22, 2200}, on(22, 2200), 22, false},
		"none":                      {nil, on(22), 22, false},
		"configured, not restarted": {[]int{2200}, on(22), 22, false},
		"ssh.socket on 22 only":     {[]int{2200}, on(22), 0, false},
	} {
		port, err := relaySSHPort(c.sshd, c.listen, c.session)
		if (err == nil) != c.ok || c.ok && port != c.sshd[0] {
			t.Errorf("%s: %d %v", name, port, err)
		}
	}
}

func TestListensOn(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
   1: 0100007F:0898 0100007F:B5E2 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0 20 4 30 10 -1
`
	tcp6 := `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A
`
	for port, want := range map[int]bool{22: true, 8080: true, 2200: false, 0x16 << 8: false} {
		if got := listensOn([]string{tcp, tcp6}, port); got != want {
			t.Errorf("port %d: %v", port, got)
		}
	}
}

// The relay's perimeter must let this session's next connection in.
func TestCheckRelaySSH(t *testing.T) {
	snap := &perimeterv1.Snapshot{AdminPrefixes: []string{"203.0.113.9/32"}, AdminPorts: []*perimeterv1.Port{{Proto: "tcp", Port: 22}}}
	for name, c := range map[string]struct {
		port            int
		client          string
		ok, warn        bool
		suggestContains string
	}{
		"inside":           {22, "203.0.113.9", true, false, ""},
		"another port":     {2200, "203.0.113.9", false, false, "-ssh-port 2200"},
		"outside":          {22, "198.51.100.7", false, false, "-admin 203.0.113.9/32,198.51.100.7 r1"},
		"not known":        {22, "", true, true, ""},
		"through a tunnel": {22, "127.0.0.1", true, true, ""},
	} {
		warning, err := checkRelaySSH(snap, c.port, c.client, "r1")
		if (err == nil) != c.ok || (warning != "") != c.warn || err != nil && !strings.Contains(err.Error(), c.suggestContains) {
			t.Errorf("%s: %q %v", name, warning, err)
		}
	}
	if _, err := checkRelaySSH(&perimeterv1.Snapshot{AdminPorts: snap.AdminPorts}, 22, "203.0.113.9", "r1"); err == nil {
		t.Error("no admin addresses")
	}
}
