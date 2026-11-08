package deploy_test

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// buildModel is a node with the services ([kind, name, settings]), then
// tweak, rendered for p.
func buildModel(t *testing.T, p render.Paths, services [][3]string, tweak func(context.Context, *store.Store)) (render.Model, []render.File) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range services {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: s[0], Name: s[1], Enabled: true, Settings: s[2]}); err != nil {
			t.Fatal(err)
		}
	}
	if tweak != nil {
		tweak(ctx, st)
	}
	m, err := render.CollectForRender(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := render.Render(m, p)
	if err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
	return m, files
}

// The plan from the inputs rayd reports is the plan rayd built from its
// model before Inputs, byte for byte, on the models of the tests above and
// a few more: on a node nothing changes (spec/apply-plan-v1.md §4.2).
func TestBuildFromInputs(t *testing.T) {
	other := render.Paths{Rendered: "/tmp/r", Run: "/tmp/run"}
	supervised := render.Paths{Rendered: "/tmp/r", Run: "/tmp/run", Supervised: true}
	plan2Services := [][3]string{{"dnstt", "dns", ""}, {"reality", "reality", `{"target":"www.example.org:443"}`}, {"olcrtc", "olc", ""}}
	setOption := func(name, key, value string) func(context.Context, *store.Store) {
		return func(ctx context.Context, st *store.Store) {
			if _, err := provision.SetServiceOption(ctx, st, name, key, value); err != nil {
				t.Fatal(err)
			}
		}
	}
	type model struct {
		p        render.Paths
		services [][3]string
		tweak    func(context.Context, *store.Store)
		// drop: files left out, as of a service that failed to render.
		drop func(render.File) bool
	}
	for name, c := range map[string]model{
		"TestBuild":              {p: render.DefaultPaths, services: plan2Services},
		"TestBuild, other paths": {p: other, services: plan2Services},
		"supervised":             {p: supervised, services: plan2Services},
		"TestBuildSelfSteal":     {p: render.DefaultPaths, services: [][3]string{{"reality", "r", ""}, {"doh", "doh", ""}}},
		"TestBuildHysteria":      {p: render.DefaultPaths, services: [][3]string{{"hy2-masq", "hy2-masq", ""}, {"hy2-obfs", "hy2-obfs", ""}}},
		"TestBuildNaive":         {p: render.DefaultPaths, services: [][3]string{{"reality", "reality", ""}, {"naive", "naive", ""}}},
		"naive, supervised":      {p: supervised, services: [][3]string{{"reality", "reality", ""}, {"naive", "naive", ""}, {"hy2-obfs", "h", ""}}},
		"naive answers as the site": {p: render.DefaultPaths, services: [][3]string{{"reality", "reality", ""}, {"naive", "naive", ""}},
			tweak: setOption("site", "answer", "403")},
		"the site's pages": {p: render.DefaultPaths, services: [][3]string{{"reality", "reality", ""}, {"naive", "naive", ""}},
			tweak: setOption("site", "answer", "pages")},
		"naive with ICMP": {p: render.DefaultPaths, services: [][3]string{{"reality", "reality", ""}, {"naive", "naive", ""}},
			tweak: setOption("naive", "icmp", "on")},
		"naive with ICMP, supervised": {p: supervised, services: [][3]string{{"reality", "reality", ""}, {"naive", "naive", `{"icmp":true}`}}},
		"naive with ICMP off again": {p: render.DefaultPaths, services: [][3]string{{"reality", "reality", ""}, {"naive", "naive", `{"icmp":true}`}},
			tweak: setOption("naive", "icmp", "off")},
		"TestBuildDNSKeyWithoutRender": {p: render.DefaultPaths, services: [][3]string{{"dnstt", "dnstt", ""}, {"masterdns", "masterdns", ""}},
			drop: func(f render.File) bool { return f.Service == "dnstt" || f.Service == "masterdns" }},
		"TestFrontCredentialsOnlyRendered": {p: render.DefaultPaths, services: plan2Services,
			drop: func(f render.File) bool { return f.Path == "/var/lib/raycontrol/rendered/front/dnsprobe.key" }},
		"salamander not rendered": {p: render.DefaultPaths, services: [][3]string{{"hy2-obfs", "h", ""}},
			drop: func(f render.File) bool { return f.Path == "/var/lib/raycontrol/rendered/front/h.salamander" }},
		"TestProbeKeyBeforeDNSTT": {p: render.DefaultPaths, services: [][3]string{{"masterdns", "mdns", ""}, {"reality", "reality", `{"target":"www.example.org:443"}`}}},
		"TestBuildSlipstream":     {p: render.DefaultPaths, services: [][3]string{{"slipstream", "slip", ""}}},
		"slipstream, broken": {p: render.DefaultPaths, services: [][3]string{{"slipstream", "slip", ""}, {"olcrtc", "olc", ""}},
			tweak: func(ctx context.Context, st *store.Store) {
				s, _ := st.ServiceByName(ctx, "slip")
				if err := st.UpdateService(ctx, s.ID, store.ServiceUpdate{Settings: `{"zone":"s.example.com"}`}); err != nil {
					t.Fatal(err)
				}
			}},
		"yggdrasil":          {p: render.DefaultPaths, services: [][3]string{{"reality", "reality", ""}, {"yggdrasil", "ygg", ""}}},
		"yggdrasil, peers":   {p: render.DefaultPaths, services: [][3]string{{"reality", "reality", ""}, {"yggdrasil", "ygg", ""}}, tweak: setOption("ygg", "peers", "tls://192.0.2.1:443")},
		"everything":         {p: render.DefaultPaths, services: [][3]string{{"reality", "reality", ""}, {"naive", "naive", ""}, {"doh", "doh", ""}, {"yggdrasil", "ygg", ""}, {"hy2-masq", "hm", ""}, {"hy2-obfs", "ho", ""}, {"dnstt", "dns", ""}, {"masterdns", "mdns", ""}, {"slipstream", "slip", ""}, {"api", "api", ""}, {"ssh", "ssh", ""}}},
		"REALITY on TCP 443": {p: render.DefaultPaths, services: [][3]string{{"reality", "reality", `{"target":"www.example.org:443"}`}}},
		"no services":        {p: render.DefaultPaths},
	} {
		m, files := buildModel(t, c.p, c.services, c.tweak)
		if c.drop != nil {
			n := len(files)
			files = slices.DeleteFunc(files, c.drop)
			if len(files) == n {
				t.Fatalf("%s: nothing dropped", name)
			}
		}
		want := deploy.LegacyBuild(m, files, c.p, deploy.DefaultBinaries)
		got := deploy.Build(deploy.InputsOf(m, files, c.p), c.p, deploy.DefaultBinaries)
		if len(want.Files) == 0 || len(want.Units) == 0 {
			t.Fatalf("%s: an empty plan", name)
		}
		// The ICMP models do have it (spec/icmp-v1.md): -icmp and Plan.ICMP.
		if icmp := strings.Contains(name, "ICMP") && !strings.Contains(name, "off"); want.ICMP != icmp ||
			strings.Contains(file(want, "/etc/systemd/system/niko-naive.service"), " -icmp\n") != icmp {
			t.Errorf("%s: ICMP %v", name, want.ICMP)
		}
		for i := range max(len(want.Files), len(got.Files)) {
			if i >= len(want.Files) || i >= len(got.Files) || want.Files[i].Path != got.Files[i].Path ||
				!bytes.Equal(want.Files[i].Content, got.Files[i].Content) || want.Files[i].Mode != got.Files[i].Mode {
				t.Errorf("%s: file %d differs", name, i)
			}
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s: the plan from the inputs differs:\nwant %+v\ngot  %+v", name, want, got)
		}
	}
}

// A service named as before v0.10.1 allowed (-api, -in): the plan before
// Inputs deployed it, the plan now leaves it out and says so (the review's
// case; rayctl check and update warn first).
func TestBuildOldName(t *testing.T) {
	m, _ := buildModel(t, render.DefaultPaths, [][3]string{{"hy2-masq", "edge", ""}}, nil)
	for i := range m.Services {
		if m.Services[i].Name == "edge" {
			m.Services[i].Name = "edge-api"
		}
	}
	files, _, err := render.Render(m, render.DefaultPaths)
	if err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
	old := deploy.LegacyBuild(m, files, render.DefaultPaths, deploy.DefaultBinaries)
	p := deploy.Build(deploy.InputsOf(m, files, render.DefaultPaths), render.DefaultPaths, deploy.DefaultBinaries)
	if !slices.Contains(old.Units, "niko-edge-api.service") || slices.Contains(p.Units, "niko-edge-api.service") ||
		!strings.Contains(strings.Join(p.Warnings, "\n"), `"edge-api"`) {
		t.Errorf("old units %v, new %v, warnings %q", old.Units, p.Units, p.Warnings)
	}
}

// A REALITY service without the front binds TCP 443 itself: Collect sets
// FrontTCP for every node now, so the model is made by hand.
func TestBuildFromInputsWithoutFront(t *testing.T) {
	m, files := buildModel(t, render.DefaultPaths, [][3]string{{"reality", "reality", ""}, {"naive", "naive", ""}}, nil)
	m.FrontTCP = false
	want := deploy.LegacyBuild(m, files, render.DefaultPaths, deploy.DefaultBinaries)
	got := deploy.Build(deploy.InputsOf(m, files, render.DefaultPaths), render.DefaultPaths, deploy.DefaultBinaries)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("the plan from the inputs differs:\nwant %+v\ngot  %+v", want, got)
	}
}
