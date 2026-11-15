package live

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// The front's last service gone, its config goes too, and the front stops:
// try-restart, its unit's condition (ConditionPathExists) failing. Left
// on disk, the config of before started the front at the next apply,
// update or boot with the backends of before, among them the salamander
// password of a deleted hy2-obfs, which its unit no longer copied in:
// niko-server exited, restarted every 2 s, and rayctl update failed on
// it (review of v0.28.0). REALITY waits for its site's certificate here,
// as on a node without a working domain: hy2-obfs is all the front has.
func TestApplyFrontConfigGone(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	for _, k := range []string{"reality", "hy2-obfs"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: k, Name: k, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	var restarted []string
	fail := map[string]error{}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"}
	a := &Applier{
		Store: st, Paths: paths, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, verb, unit string) error {
			restarted = append(restarted, verb+" "+unit)
			return fail[unit]
		},
		Inner: func(string) InnerAPI { return &fakeInner{} },
	}
	apply := func(what string, wantErr string, want ...string) {
		t.Helper()
		restarted = nil
		err := a.Apply(ctx)
		if wantErr == "" && err != nil || wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)) {
			t.Fatalf("%s: %v", what, err)
		}
		slices.Sort(restarted)
		if !slices.Equal(restarted, want) {
			t.Fatalf("%s restarted %v, want %v", what, restarted, want)
		}
	}
	config := filepath.Join(paths.Rendered, "front", "front.json")
	probe := filepath.Join(paths.Rendered, "front", render.DNSProbeKeyFile)
	exists := func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	}

	apply("first apply", "", "restart niko-front.service", "restart niko-hy2-obfs.service")
	if b, err := os.ReadFile(config); err != nil || !strings.Contains(string(b), "hy2-obfs.salamander") {
		t.Fatalf("the front's config: %s %v", b, err)
	}

	// hy2-obfs deleted: the front carries nothing. Its stop owed while
	// systemctl fails, made at the next apply, then nothing more.
	if err := st.DeleteService(ctx, "hy2-obfs"); err != nil {
		t.Fatal(err)
	}
	fail["niko-front.service"] = errors.New("systemd is busy")
	apply("hy2-obfs deleted", "niko-front.service", "try-restart niko-front.service")
	if exists(config) {
		t.Fatal("the front's config of before stays: it starts the front with a backend that is gone")
	}
	// The key stays: the unit copies it in as long as there is no config
	// (TestProbeKeyBeforeDNSTT), and the config comes with it again.
	if !exists(probe) {
		t.Fatal("the probe key went with the front's config")
	}
	delete(fail, "niko-front.service")
	apply("the next apply", "", "try-restart niko-front.service")
	apply("an idle apply", "")
	// Nor a rayd started anew.
	a = &Applier{Store: a.Store, Paths: a.Paths, Log: a.Log, Restart: a.Restart, Inner: a.Inner}
	apply("a new rayd", "")

	// A tunnel that does not render (inner off under it, a database from
	// before the API refused that): the front leaves it out (Q-1), and
	// with it, as its only service, its config. The tunnel keeps its
	// files.
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	apply("a tunnel", "", "restart niko-dns.service", "restart niko-front.service", "restart niko-inner.service")
	if err := st.SetServiceEnabled(ctx, "inner", false); err != nil {
		t.Fatal(err)
	}
	apply("the tunnel broken", "service dns", "try-restart niko-front.service")
	if exists(config) || !exists(filepath.Join(paths.Rendered, "dns", "noise.key")) {
		t.Fatalf("the broken tunnel's front: config there %v, its key gone %v", exists(config), !exists(filepath.Join(paths.Rendered, "dns", "noise.key")))
	}
	// Mended: the config is new, and starts the front; the tunnel's files
	// are those it kept.
	if err := st.SetServiceEnabled(ctx, "inner", true); err != nil {
		t.Fatal(err)
	}
	apply("the tunnel mended", "", "restart niko-front.service")
	if !exists(config) {
		t.Fatal("no front's config after the tunnel came back")
	}
}
