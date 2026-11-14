package main

import (
	"strings"
	"testing"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

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
