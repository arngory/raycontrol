package main

import (
	"strings"
	"testing"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// rayctl egress lists what the local part lets through: a REALITY target
// on a local address, for its process only.
func TestLocalExemptLines(t *testing.T) {
	got := localExemptLines([]*nodev1.Service{
		{Kind: "reality", Name: "steal", Enabled: true, Uid: 9120, SettingsJson: `{"target":"127.0.0.1:8443","sni":"www.example.org"}`},
		{Kind: "reality", Name: "public", Enabled: true, Uid: 9121, SettingsJson: `{"target":"www.example.org:443"}`},
	})
	if len(got) != 1 || !strings.HasPrefix(got[0], "tcp 127.0.0.1:8443: REALITY steal's target, for its process only (uid 9120)") {
		t.Fatalf("%q", got)
	}
}

// rayctl status's egress line says what is true: on a node with a
// perimeter the policy, on one of rayd serve -supervise that nothing of
// it is the kernel's there (no rayspa by default, and the local part never
// covers rayd's UID).
func TestEgressStatusLine(t *testing.T) {
	e := &nodev1.Egress{Local: true, Smtp: true}
	if got := egressStatusLine(e, false); got != "blocked: smtp (tcp 25), local networks (rayctl egress)" {
		t.Errorf("a node: %q", got)
	}
	got := egressStatusLine(e, true)
	for _, want := range []string{"set: blocked: smtp (tcp 25), local networks;", "local networks: not in the kernel here",
		"smtp and bittorrent: only where a rayspa runs", "(rayctl egress)"} {
		if !strings.Contains(got, want) {
			t.Errorf("supervised: %q lacks %q", got, want)
		}
	}
	if strings.HasPrefix(got, "blocked") {
		t.Errorf("supervised reads as blocked: %q", got)
	}
	if got := egressStatusLine(&nodev1.Egress{}, true); got != "set: nothing blocked (rayctl egress)" {
		t.Errorf("supervised, nothing set: %q", got)
	}
}
