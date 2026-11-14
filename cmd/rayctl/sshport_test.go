package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// The perimeter admits SSH on the ports of the enabled ssh services (22 by
// the kind when the settings name none); a disabled one, or another kind,
// adds nothing.
func TestSSHAdmitted(t *testing.T) {
	got := sshAdmitted([]*nodev1.Service{
		{Name: "ssh", Kind: "ssh", Enabled: true, SettingsJson: `{"ports":["tcp/2200"]}`},
		{Name: "ssh-2222", Kind: "ssh", Enabled: true, SettingsJson: `{"ports":["tcp/2222"]}`},
		{Name: "old", Kind: "ssh", Enabled: false, SettingsJson: `{"ports":["tcp/22"]}`},
		{Name: "plain", Kind: "ssh", Enabled: true, SettingsJson: `{}`},
		{Name: "reality", Kind: "reality", Enabled: true, SettingsJson: `{}`},
	})
	if want := map[int][]string{2200: {"ssh"}, 2222: {"ssh-2222"}, 22: {"plain"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("admitted %v", got)
	}
}

// sshd's ports against the perimeter's: the same, fine; sshd moved to a
// port the perimeter does not admit, a warning with the commands that
// admit it; the old port kept beside the new one, fine and said.
func TestSSHPortResult(t *testing.T) {
	one := map[int][]string{22: {"ssh"}}
	r := sshPortResult([]int{22}, one)
	if !r.OK || r.Detail != "sshd's port 22: the perimeter admits SSH on 22 (ssh)" {
		t.Errorf("in line: %+v", r)
	}
	// Port 2222 in sshd_config, the perimeter on 22: shut out once sshd runs.
	r = sshPortResult([]int{2222}, one)
	if r.OK || !strings.Contains(r.Detail, "sshd is configured for 2222, which the perimeter does not admit (it admits SSH on 22 (ssh))") ||
		!strings.Contains(r.Detail, "closed to everyone") ||
		!strings.HasPrefix(r.Fix, `rayctl service add ssh ssh-2222 -settings '{"ports":["tcp/2222"]}'`) ||
		!strings.Contains(r.Fix, "or put sshd back on 22") {
		t.Errorf("moved: %+v", r)
	}
	// Both ports in sshd (the guide's step 2): 2222 not admitted yet, 22
	// still is: a warning, not "closed".
	r = sshPortResult([]int{22, 2222}, one)
	if r.OK || strings.Contains(r.Detail, "closed to everyone") || !strings.Contains(r.Fix, "ssh-2222") {
		t.Errorf("both in sshd: %+v", r)
	}
	// Moved and admitted, the old service kept: fine, the old one named.
	r = sshPortResult([]int{2222}, map[int][]string{22: {"ssh"}, 2222: {"ssh-2222"}})
	if !r.OK || !strings.Contains(r.Detail, "sshd is not configured for 22") {
		t.Errorf("old kept: %+v", r)
	}
	// No ssh service enabled at all.
	r = sshPortResult([]int{22}, map[int][]string{})
	if r.OK || !strings.Contains(r.Detail, "admits SSH on no port") || !strings.Contains(r.Fix, "rayctl service list") {
		t.Errorf("none: %+v", r)
	}
}

// No OpenSSH sshd to ask: none at all, or another server under its name
// (Dropbear's), is a quiet state; an OpenSSH sshd whose sshd -T fails (a
// configuration that does not read, no root) is not.
func TestNoOpenSSH(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name, body string
		want       bool
	}{
		{"dropbear", `echo "dropbear: unknown option" >&2; exit 1`, true},
		{"openssh", `case "$1" in -V) echo "OpenSSH_9.6p1, OpenSSL 3.0.13" >&2; exit 0;; esac
echo "/etc/ssh/sshd_config: line 3: Bad configuration option" >&2; exit 255`, false},
		{"openssh-old", `case "$1" in -V) echo "unknown option -- V" >&2; echo "OpenSSH_8.4p1, OpenSSL 1.1.1w" >&2; exit 1;; esac
exit 255`, false},
	} {
		bin := filepath.Join(dir, c.name)
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+c.body+"\n"), 0o700); err != nil { //nolint:gosec // G306: a test's script
			t.Fatal(err)
		}
		_, err := sshdPortsOf(bin)
		if err == nil {
			t.Fatalf("%s: sshd -T passed", c.name)
		}
		if got := noOpenSSH(bin, err); got != c.want {
			t.Errorf("%s: %v (%v)", c.name, got, err)
		}
	}
	missing := filepath.Join(dir, "none")
	if _, err := sshdPortsOf(missing); !noOpenSSH(missing, err) {
		t.Errorf("no sshd at all: %v", err)
	}
}

// sshd started by a socket unit: the check says it does not see the
// unit's ports.
func TestSSHSocketNote(t *testing.T) {
	dir := t.TempDir()
	links := []string{filepath.Join(dir, "ssh.socket"), filepath.Join(dir, "sshd.socket")}
	if n := sshSocketNote(links); n != "" {
		t.Errorf("no socket unit: %q", n)
	}
	if err := os.Symlink("/lib/systemd/system/ssh.socket", links[0]); err != nil {
		t.Fatal(err)
	}
	if n := sshSocketNote(links); !strings.Contains(n, "ssh.socket is enabled") || !strings.Contains(n, "does not read") {
		t.Errorf("an enabled socket unit (a dangling link here): %q", n)
	}
}
