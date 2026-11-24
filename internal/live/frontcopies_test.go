package live

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// A hy2-obfs added through the API waits off the front until rayctl
// apply: the front reads every salamander password its config names at
// its start, and its installed unit copies in only those of the last
// apply. Routed at once, the new one kept the whole front, every route
// on TCP and UDP 443, from starting until that apply (restarting every
// 2 s). After the apply (here: its unit written as rayctl apply writes
// it), the next render routes it. One password for the service, before
// niko-server v0.19.3: from it the front rereads the devices' passwords in
// place and routes a new hy2-obfs at once (salamander_test.go).
func TestApplyObfsWaitsForFrontUnit(t *testing.T) {
	defer render.UseNikoServer("v0.19.2")()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "o1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"}
	unit := filepath.Join(dir, "niko-front.service")
	// rayctl apply: the plan from rayd's render (no FrontCopies), its
	// front unit installed.
	applyUnits := func() {
		t.Helper()
		m, err := render.CollectForRender(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		files, _, err := render.Render(m, paths)
		if err != nil {
			t.Fatal(err)
		}
		plan := deploy.Build(deploy.InputsOf(m, files, paths), paths, deploy.DefaultBinaries)
		for _, f := range plan.Files {
			if f.Path == deploy.UnitPath(render.UnitName("front")) {
				if err := os.WriteFile(unit, f.Content, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
		}
		t.Fatal("no front unit in the plan")
	}
	var restarted []string
	a := &Applier{
		Store: st, Paths: paths, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), FrontUnit: unit,
		Restart: func(_ context.Context, verb, unit string) error {
			restarted = append(restarted, verb+" "+unit)
			return nil
		},
		Inner: func(string) InnerAPI { return &fakeInner{} },
	}
	config := filepath.Join(paths.Rendered, "front", "front.json")
	apply := func(what string, want ...string) string {
		t.Helper()
		restarted = nil
		if err := a.Apply(ctx); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		slices.Sort(restarted)
		if !slices.Equal(restarted, want) {
			t.Fatalf("%s restarted %v, want %v", what, restarted, want)
		}
		b, err := os.ReadFile(config)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return string(b)
	}

	// No unit installed yet (a first install): everything is routed, and
	// rayctl apply writes the unit with it.
	if c := apply("before any unit", "restart niko-front.service", "restart niko-o1.service"); !strings.Contains(c, "o1.salamander") {
		t.Fatalf("o1 not routed before the first apply: %s", c)
	}
	applyUnits()
	apply("after the apply")

	// o2 through the API: its files are written (the next apply copies
	// its password from them), the front's config stays as it was.
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "o2", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	c := apply("o2 added", "restart niko-o2.service")
	if strings.Contains(c, "o2") || !strings.Contains(c, "o1.salamander") {
		t.Fatalf("o2 routed before its password is copied in, or o1 gone: %s", c)
	}
	if _, err := os.Stat(filepath.Join(paths.Rendered, "front", "o2.salamander")); err != nil {
		t.Fatalf("o2's password for the front not written: %v", err)
	}
	apply("again, before the apply")

	// rayctl apply installs the unit with o2's copy: routed, the front
	// restarted once.
	applyUnits()
	b, err := os.ReadFile(unit)
	must(t, err)
	if !deploy.UnitCopies(b)[paths.FrontSalamander("o2")] {
		t.Fatal("the unit rayctl apply writes does not copy o2's password in")
	}
	if c := apply("o2 after the apply", "try-restart niko-front.service"); !strings.Contains(c, "o2.salamander") {
		t.Fatalf("o2 not routed after the apply: %s", c)
	}

	// A supervised node (no FrontUnit): routed at once, as the
	// supervisor copies in what its own plan names.
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "o3", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	a.FrontUnit = ""
	if c := apply("o3 supervised", "restart niko-front.service", "restart niko-o3.service"); !strings.Contains(c, "o3.salamander") {
		t.Fatalf("o3 not routed without a unit to read: %s", c)
	}
}
