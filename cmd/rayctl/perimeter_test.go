package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/api"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// rayctl status and check say when the perimeter is down (R4-40): no table
// is an open host, FAILED; a table without rayspa a closed one that
// answers no knock, WARNING.
func TestPerimeterResult(t *testing.T) {
	unit := filepath.Join(t.TempDir(), "rayspa.service")
	host := func(state string, in bool, err error) perimeterHost {
		return perimeterHost{unitFile: unit, state: func() string { return state },
			input: func() (bool, error) { return in, err }, euid: func() int { return 0 }, look: func(string) error { return nil }}
	}
	if rs := perimeterResult(host("active", false, nil)); rs != nil {
		t.Fatalf("before the install: %v", rs)
	}
	os.WriteFile(unit, []byte("[Unit]\n"), 0o644)
	for _, c := range []struct {
		h    perimeterHost
		ok   bool
		line string
	}{
		{host("active", true, nil), true, "ok: rayspa runs, its table is in"},
		{host("failed", false, nil), false, "FAILED perimeter down: the host is open (no table inet raycontrol with its input chain; rayspa.service is failed): systemctl restart rayspa"},
		{host("active", false, nil), false, "FAILED perimeter down: the host is open"},
		{host("inactive", true, nil), false, "WARNING rayspa.service is inactive: its table stays in force"},
		{host("active", false, errors.New("netlink: busy")), false, "WARNING the perimeter's table cannot be read: netlink: busy"},
	} {
		rs := perimeterResult(c.h)
		if len(rs) != 1 || rs[0].OK != c.ok || !strings.HasPrefix(perimeterLine(rs[0]), c.line) {
			t.Errorf("%+v: %v %q", c, rs, perimeterLine(rs[0]))
		}
	}
	noNFT := host("active", false, nil)
	noNFT.look = func(string) error { return errors.New("not found") }
	if rs := perimeterResult(noNFT); rs[0].OK || !strings.HasPrefix(perimeterLine(rs[0]), "FAILED nft is not installed") {
		t.Errorf("no nft: %q", perimeterLine(rs[0]))
	}
	user := host("active", false, nil)
	user.euid = func() int { return 1000 }
	if rs := perimeterResult(user); !rs[0].OK || !strings.Contains(rs[0].Detail, "needs root") {
		t.Errorf("not root: %v", rs)
	}
}

// rayd's perimeter loop when rayspa reports nothing of its table: unknown,
// neither ok nor FAILED; every other loop, and that loop otherwise, as
// loopState says.
func TestPerimeterLoopState(t *testing.T) {
	now := time.Unix(1767225600, 0)
	l := &nodev1.LoopHealth{Name: api.RayspaLoop, LastOk: now.Add(-12 * time.Second).Unix(), Detail: api.RayspaUnknown + "rayspa follows the perimeter, its table is not reported"}
	if got := perimeterLoopState(l, now); got != "unknown 12s ago: rayspa follows the perimeter, its table is not reported" {
		t.Errorf("unknown: %q", got)
	}
	l.Detail = "rayspa follows the perimeter, its table is in (rayspa v0.27.1)"
	if got := perimeterLoopState(l, now); got != "ok 12s ago: "+l.Detail {
		t.Errorf("up: %q", got)
	}
	other := &nodev1.LoopHealth{Name: "apply", LastOk: l.LastOk, Detail: api.RayspaUnknown + "x"}
	if got := perimeterLoopState(other, now); !strings.HasPrefix(got, "ok ") {
		t.Errorf("another loop: %q", got)
	}
}
