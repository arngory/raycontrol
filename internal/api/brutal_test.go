package api

import (
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/store"
)

// Hysteria2 without a ceiling (a link's speed unknown, or too low to
// trust) is in the status; one with up_mbps of its own, 0 too, is not, nor one disabled
// (protocol review 2026-11, M1).
func TestBrutalWarnings(t *testing.T) {
	services := []store.Service{
		{Kind: "hy2-masq", Name: "hm", Enabled: true, Settings: `{}`},
		{Kind: "hy2-obfs", Name: "ho", Enabled: true, Settings: `{"up_mbps":500}`},
		{Kind: "hy2-obfs", Name: "h0", Enabled: true, Settings: `{"up_mbps":0}`},
		{Kind: "hy2-obfs", Name: "off", Settings: `{}`},
		{Kind: "reality", Name: "r", Enabled: true, Settings: `{}`},
	}
	asked := 0
	link := func(mbps int) func() (int, string) {
		return func() (int, string) { asked++; return mbps, "ens3" }
	}
	for _, c := range []struct {
		mbps int
		want string // in the one warning; "": none
	}{
		{0, "hy2-masq hm: Brutal has no ceiling, the speed of the node's link unknown"},
		{100, "hy2-masq hm: Brutal has no ceiling: ens3 tells 100 Mbit/s"},
		{1000, ""},
		{10000, ""},
	} {
		asked = 0
		got := brutalWarnings(services, link(c.mbps))
		if c.want == "" && len(got) != 0 || c.want != "" && (len(got) != 1 || !strings.HasPrefix(got[0], c.want) ||
			!strings.Contains(got[0], "rayctl service set hm up_mbps=N")) || asked != 1 {
			t.Errorf("link %d: %q, asked %d", c.mbps, got, asked)
		}
	}
	// Every ceiling set: the link is not even looked at.
	asked = 0
	if got := brutalWarnings(services[1:], link(0)); len(got) != 0 || asked != 0 {
		t.Errorf("ceilings set: %q, asked %d", got, asked)
	}
}
