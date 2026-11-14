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

// A switch of the site's key writes chain and key and then restarts the
// units that hold a copy of the key (spec/cert-pin-v1.md §6). A restart
// that does not happen (rayd stopped or killed between the write and
// systemctl, systemctl failing) used to be lost for good: the files
// already equal the store, so later applies saw no change, and the
// processes kept the old key while subscriptions pinned the new one.
//
// The restart is owed on disk from before the files change until it is
// made: the apply that loses it says so in its error, a later apply makes
// it, and so does a rayd started anew.
func TestApplyOwesLostRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	for _, k := range []string{"reality", "naive", "hy2-masq"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: k, Name: k, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	site, _ := st.ServiceByName(ctx, "site")
	set := func(chain, key string) {
		t.Helper()
		if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{
			provision.SecretTLSChain: []byte(chain), provision.SecretTLSKey: []byte(key)}}); err != nil {
			t.Fatal(err)
		}
	}
	set("chain A\n", "key A")
	var restarted []string
	var fail error
	applier := func() *Applier {
		return &Applier{
			Store: st, Paths: render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"},
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Restart: func(_ context.Context, verb, unit string) error {
				if fail != nil {
					return fail
				}
				restarted = append(restarted, verb+" "+unit)
				return nil
			},
			Inner: func(string) InnerAPI { return &fakeInner{} },
		}
	}
	a := applier()
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	owed := func() []string {
		t.Helper()
		entries, err := os.ReadDir(filepath.Join(dir, "restarts"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return names
	}
	if got := owed(); len(got) != 0 {
		t.Fatalf("restarts owed after a clean apply: %v", got)
	}
	keyed := []string{"hy2-masq", "naive", "site"} // the processes with a copy of the key

	// The key switch: the store has chain B and key B; the restart is lost.
	set("chain B\n", "key B")
	fail, restarted = errors.New("context canceled"), nil // rayd is stopping, or systemctl failed
	err = a.Apply(ctx)
	if err == nil {
		t.Fatal("an apply whose restarts failed reports nothing: rayctl status would show the node in order")
	}
	for _, service := range keyed {
		if !strings.Contains(err.Error(), "niko-"+service+".service") {
			t.Errorf("the apply's error does not name %s: %v", service, err)
		}
	}
	if got := owed(); !slices.Equal(got, keyed) {
		t.Fatalf("restarts owed after the lost ones: %v, want %v", got, keyed)
	}
	// Still failing: still owed, still said.
	if err := a.Apply(ctx); err == nil || !slices.Equal(owed(), keyed) {
		t.Fatalf("a second failing apply: %v, owed %v", err, owed())
	}

	// rayd comes back: a new applier, which knows of the restarts only what
	// is on disk. The files equal the store; the restarts are made anyway.
	fail, restarted = nil, nil
	a = applier()
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	slices.Sort(restarted)
	if want := []string{"try-restart niko-hy2-masq.service", "try-restart niko-naive.service", "try-restart niko-site.service"}; !slices.Equal(restarted, want) {
		t.Fatalf("restarts after rayd came back: %v, want %v", restarted, want)
	}
	if got := owed(); len(got) != 0 {
		t.Fatalf("restarts still owed after they were made: %v", got)
	}
	// Made once.
	restarted = nil
	if err := a.Apply(ctx); err != nil || len(restarted) != 0 {
		t.Fatalf("the apply after: %v, restarted %v", err, restarted)
	}

	// A unit that is not installed (a node not deployed yet) owes nothing:
	// no process runs with the old files, and rayctl apply starts it with
	// the new ones. No error either, as before.
	set("chain C\n", "key C")
	fail = errors.Join(errNoUnit, errors.New("exit status 5"))
	if err := a.Apply(ctx); err != nil || len(owed()) != 0 {
		t.Fatalf("units not installed: %v, owed %v", err, owed())
	}

	// A restart owed to a service that is turned off meanwhile is dropped:
	// its unit must not be started for it.
	set("chain D\n", "key D")
	fail = errors.New("systemctl failed")
	if err := a.Apply(ctx); err == nil {
		t.Fatal("no error")
	}
	if err := st.SetServiceEnabled(ctx, "hy2-masq", false); err != nil {
		t.Fatal(err)
	}
	fail, restarted = nil, nil
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	// (The front restarts too: its config lost a backend.)
	if !slices.Contains(restarted, "try-restart niko-naive.service") || !slices.Contains(restarted, "try-restart niko-site.service") ||
		slices.ContainsFunc(restarted, func(r string) bool { return strings.Contains(r, "hy2-masq") }) || len(owed()) != 0 {
		t.Fatalf("after hy2-masq was turned off: restarted %v, owed %v", restarted, owed())
	}
}

// A file that could not be written owes no restart, and an Xray whose only
// change was its users, synced through its API, owes none either.
func TestApplyOwesNothingWithoutAChange(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	reality, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// REALITY is rendered once the site it borrows has a certificate.
	site, _ := st.ServiceByName(ctx, "site")
	if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{
		provision.SecretTLSChain: []byte("chain\n"), provision.SecretTLSKey: []byte("key")}}); err != nil {
		t.Fatal(err)
	}
	var restarted []string
	a := &Applier{
		Store: st, Paths: render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, verb, unit string) error {
			restarted = append(restarted, verb+" "+unit)
			return nil
		},
		Inner: func(string) InnerAPI { return &fakeInner{} },
	}
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	// The test is about a rendered REALITY: without its file it would pass
	// by doing nothing.
	rdir := filepath.Join(dir, "rendered", "reality")
	if _, err := os.Stat(filepath.Join(rdir, "xray.json")); err != nil {
		t.Fatal(err)
	}
	restarted = nil
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetUserServices(ctx, "alice", []int64{reality.ID})
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "restarts")); len(restarted) != 0 || len(entries) != 0 {
		t.Fatalf("users synced through the API: restarted %v, %d restarts owed", restarted, len(entries))
	}
	// The directory of REALITY's files cannot be written: nothing changes,
	// nothing is owed, and the apply says what failed.
	if os.Getuid() == 0 {
		t.Skip("root writes anywhere")
	}
	if err := os.Chmod(rdir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(rdir, 0o750)
	st.CreateUser(ctx, store.User{Name: "bob", Enabled: true})
	st.SetUserServices(ctx, "bob", []int64{reality.ID})
	if err := a.Apply(ctx); err == nil {
		t.Fatal("no error for a file that could not be written")
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "restarts")); len(entries) != 0 {
		t.Fatalf("%d restarts owed for a change that was not written", len(entries))
	}
}
