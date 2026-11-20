package render_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// relay-names-v1 §7: the front routes each relay's name to its service,
// REALITY, naive and DoH over TCP, hy2-masq, naive and DoH over UDP;
// REALITY takes them in serverNames, its grace inbound too. A REALITY with
// a target of someone else's and hy2-obfs have none.
func TestRenderRelayNames(t *testing.T) {
	ctx := context.Background()
	st := node(t)
	for _, s := range []store.Service{
		{Kind: "reality", Name: "r", Enabled: true},
		{Kind: "reality", Name: "fx", Enabled: true, Settings: `{"target":"www.example.org:443"}`},
		{Kind: "naive", Name: "nv", Enabled: true},
		{Kind: "doh", Name: "dh", Enabled: true},
		{Kind: "hy2-masq", Name: "hm", Enabled: true},
		{Kind: "hy2-obfs", Name: "ho", Enabled: true},
	} {
		if _, err := provision.CreateService(ctx, st, s); err != nil {
			t.Fatal(s.Name, err)
		}
	}
	siteCert(t, ctx, st, "*.example.com")
	if _, err := st.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if fc := renderFront(t, ctx, st); fc.err != nil || len(fc.tcp) == 0 {
		t.Fatalf("before the bundle: %v", fc.err)
	}
	if err := st.SetRelayCertPin(ctx, "r1", "pin"); err != nil {
		t.Fatal(err)
	}
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string][]string{}
	for _, s := range m.Services {
		byName[s.Name] = m.RelayNames[s.ID]
	}
	for _, name := range []string{"r", "nv", "dh", "hm"} {
		if len(byName[name]) != 1 {
			t.Fatalf("%s: relay names %v", name, byName[name])
		}
	}
	for _, name := range []string{"fx", "ho", "dns"} {
		if len(byName[name]) != 0 {
			t.Fatalf("%s: relay names %v", name, byName[name])
		}
	}
	fc := renderFront(t, ctx, st)
	if fc.err != nil {
		t.Fatal(fc.err)
	}
	for name, want := range map[string][2]string{"r": {"r", ""}, "nv": {"nv", "nv/quic"}, "dh": {"dh", "dh/quic"}, "hm": {"", "hm"}} {
		rn := byName[name][0]
		if fc.tcp[rn] != want[0] || fc.udp[rn] != want[1] {
			t.Errorf("%s's relay name %s: TCP to %q, UDP to %q", name, rn, fc.tcp[rn], fc.udp[rn])
		}
	}

	serverNames := func() [][]string {
		t.Helper()
		m, err := render.CollectForRender(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		files, _, err := render.Render(m, render.DefaultPaths)
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			Inbounds []struct {
				Stream struct {
					Reality struct {
						ServerNames []string `json:"serverNames"`
					} `json:"realitySettings"`
				} `json:"streamSettings"`
			} `json:"inbounds"`
		}
		for _, f := range files {
			if f.Path == "/var/lib/raycontrol/rendered/r/xray.json" {
				if err := json.Unmarshal(f.Content, &c); err != nil {
					t.Fatal(err)
				}
			}
		}
		var out [][]string
		for _, in := range c.Inbounds {
			out = append(out, in.Stream.Reality.ServerNames)
		}
		return out
	}
	r, _ := st.ServiceByName(ctx, "r")
	sni := provision.SiteName(r) // the sni setting
	if got := serverNames(); len(got) != 1 || !slices.Equal(got[0], []string{sni, byName["r"][0]}) {
		t.Fatalf("serverNames %v", got)
	}
	// In the grace period after a switch: both inbounds, the server name
	// of each and the relay's.
	e := provision.RealityEpoch{Period: 90 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Prepare: 24 * time.Hour, Grace: 48 * time.Hour}
	for _, at := range []time.Duration{87, 90} {
		if n, err := provision.RotateReality(ctx, st, r.CreatedAt.Add(at*24*time.Hour), e, nil, nil); err != nil || n == 0 {
			t.Fatalf("rotate: %d %v", n, err)
		}
	}
	got := serverNames()
	if len(got) != 2 || !slices.Contains(got[0], byName["r"][0]) || !slices.Contains(got[1], byName["r"][0]) {
		t.Fatalf("serverNames in the grace period %v", got)
	}
}
