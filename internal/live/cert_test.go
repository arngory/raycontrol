package live

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// A renewed certificate of the site (spec/cert-pin-v1.md §6, the review's
// finding B6): the chain changes and the key stays, as the certificate
// manager keeps it. rayd naive and rayd site read the chain again, so
// their units are not restarted and no connection is cut; DoH is rayd's
// own. The niko-server backends that answer with the same certificate
// (hy2-masq, Yggdrasil) still restart. The pinned niko-server takes a new
// chain by itself (xrayapi's TestRenewedChainWithNikoServer), but live does
// not rely on it yet (§12). A new key restarts every one of them: the
// processes get the key as a copy made at the start.
func TestApplyCertificateRenewal(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	for _, k := range []string{"reality", "naive", "doh", "hy2-masq", "yggdrasil"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: k, Name: k, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	// Only the bytes matter to apply: a chain is what the store holds.
	set := func(chain, key string) {
		t.Helper()
		if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{
			provision.SecretTLSChain: []byte(chain), provision.SecretTLSKey: []byte(key)}}); err != nil {
			t.Fatal(err)
		}
	}
	set("chain 1\n", "key 1")
	var restarted []string
	rendered := filepath.Join(dir, "rendered")
	a := &Applier{
		Store: st, Paths: render.Paths{Rendered: rendered, Run: "/run/niko"},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, verb, unit string) error {
			restarted = append(restarted, verb+" "+unit)
			return nil
		},
		Inner: func(string) InnerAPI { return &fakeInner{} },
	}
	apply := func() []string {
		t.Helper()
		restarted = nil
		if err := a.Apply(ctx); err != nil {
			t.Fatal(err)
		}
		slices.Sort(restarted)
		return restarted
	}
	// The first apply: the units waited for their files and start.
	first := apply()
	for _, unit := range []string{"niko-naive.service", "niko-site.service", "niko-hy2-masq.service", "niko-yggdrasil.service"} {
		if !slices.Contains(first, "restart "+unit) {
			t.Fatalf("first apply: %s not started: %v", unit, first)
		}
	}
	if got := apply(); len(got) != 0 {
		t.Fatalf("nothing changed, restarted %v", got)
	}

	// The renewal: a new chain, the same key.
	set("chain 2\n", "key 1")
	got := apply()
	for _, unit := range []string{"niko-naive.service", "niko-site.service"} {
		if slices.Contains(got, "try-restart "+unit) || slices.Contains(got, "restart "+unit) {
			t.Errorf("the renewal restarted %s: %v", unit, got)
		}
	}
	// The niko-server backends, and nothing else.
	if want := []string{"try-restart niko-hy2-masq.service", "try-restart niko-yggdrasil.service"}; !slices.Equal(got, want) {
		t.Errorf("the renewal restarted %v, want %v", got, want)
	}
	for _, service := range []string{"naive", "site", "hy2-masq"} {
		if b, err := os.ReadFile(filepath.Join(rendered, service, "chain.pem")); err != nil || string(b) != "chain 2\n" {
			t.Errorf("%s: the new chain is not in its file: %q %v", service, b, err)
		}
	}

	// A new key with its chain (the site's next key): the processes have
	// the old key's copy, so each restarts, a running one only.
	set("chain 3\n", "key 2")
	got = apply()
	for _, unit := range []string{"niko-naive.service", "niko-site.service", "niko-hy2-masq.service", "niko-yggdrasil.service"} {
		if !slices.Contains(got, "try-restart "+unit) {
			t.Errorf("the new key did not restart %s: %v", unit, got)
		}
	}

	// A chain that was not there: its unit waited for it and is started,
	// though the process rereads the file (File.Needed). The conn-limit
	// switch, reread too, starts nothing (TestApplyReload).
	if err := os.Remove(filepath.Join(rendered, "naive", render.NaiveChain)); err != nil {
		t.Fatal(err)
	}
	if got := apply(); !slices.Equal(got, []string{"restart niko-naive.service"}) {
		t.Errorf("a new chain file restarted %v", got)
	}
}

// A key switch cut off half way must leave the running processes a chain
// for the key they hold. apply wrote the chain first (it needs no restart
// written down) and the key second: when the restart could not be
// written down, or rayd stopped between the two, the files held the new
// key's chain beside the old key, and rayd naive and rayd site exited
// after 30 s (certfile.Loader.Unpaired) and could not start again on that
// pair, where before the rule they went on serving the old one. Now the
// key goes first, its restart written down before it, and takes the chain
// with it: both staged, then renamed back to back.
func TestApplyKeySwitchCutOff(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	for _, k := range []string{"reality", "naive"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: k, Name: k, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	set := func(chain, key string) {
		t.Helper()
		if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{
			provision.SecretTLSChain: []byte(chain), provision.SecretTLSKey: []byte(key)}}); err != nil {
			t.Fatal(err)
		}
	}
	var restarted []string
	rendered := filepath.Join(dir, "rendered")
	a := &Applier{Store: st, Paths: render.Paths{Rendered: rendered, Run: "/run/niko"},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, verb, unit string) error {
			restarted = append(restarted, verb+" "+unit)
			return nil
		},
		Inner: func(string) InnerAPI { return &fakeInner{} }}
	set("chain A\n", "key A")
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	files := func(service string) (chain, key string) {
		t.Helper()
		c, err1 := os.ReadFile(filepath.Join(rendered, service, render.NaiveChain))
		k, err2 := os.ReadFile(filepath.Join(rendered, service, render.NaiveKey))
		if err := errors.Join(err1, err2); err != nil {
			t.Fatal(err)
		}
		return string(c), string(k)
	}
	_, keyA := files("naive")

	// The restart cannot be written down (a full disk; here a file where
	// the directory of the records goes): neither file changes.
	records := filepath.Join(dir, "restarts")
	if err := os.RemoveAll(records); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(records, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	set("chain B\n", "key B")
	restarted = nil
	if err := a.Apply(ctx); err == nil {
		t.Fatal("no error")
	}
	for _, svc := range []string{"naive", "site"} {
		if chain, key := files(svc); chain != "chain A\n" || key != keyA {
			t.Errorf("%s, the restart not written down: chain %q, the key changed %v", svc, chain, key != keyA)
		}
	}
	if len(restarted) != 0 {
		t.Errorf("restarted %v", restarted)
	}
	if err := os.Remove(records); err != nil {
		t.Fatal(err)
	}

	// Stopped between the renames (here: the chain's fails): the new key
	// beside the old chain, which a running process, holding the old key,
	// does not see as a change. It is not restarted onto that pair; its
	// restart stays owed, and the next apply brings the chain and makes it.
	renamePair = func(string, string) error { return errors.New("stopped") }
	t.Cleanup(func() { renamePair = os.Rename })
	restarted = nil
	if err := a.Apply(ctx); err == nil {
		t.Fatal("no error")
	}
	for _, svc := range []string{"naive", "site"} {
		if chain, key := files(svc); chain != "chain A\n" || key == keyA {
			t.Errorf("%s, cut off between the renames: chain %q, the key changed %v", svc, chain, key != keyA)
		}
		if _, err := os.Stat(filepath.Join(records, svc)); err != nil {
			t.Errorf("%s: its restart is not owed: %v", svc, err)
		}
	}
	if len(restarted) != 0 {
		t.Errorf("restarted onto the new key and the old chain: %v", restarted)
	}
	renamePair = os.Rename
	restarted = nil
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	for _, svc := range []string{"naive", "site"} {
		if chain, _ := files(svc); chain != "chain B\n" {
			t.Errorf("%s: chain %q after the next apply", svc, chain)
		}
		if !slices.Contains(restarted, "try-restart "+render.UnitName(svc)) {
			t.Errorf("%s: not restarted after the next apply: %v", svc, restarted)
		}
		// Whatever was staged is gone.
		if left, _ := filepath.Glob(filepath.Join(rendered, svc, ".tmp-*")); len(left) != 0 {
			t.Errorf("%s: staged files left: %v", svc, left)
		}
	}
}
