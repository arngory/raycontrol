package main

import (
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
