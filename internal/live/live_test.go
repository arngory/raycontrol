package live

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

type fakeInner struct {
	calls []map[string]string
}

func (f *fakeInner) SyncVLESS(_ context.Context, _, _ string, want map[string]string) (int, int, error) {
	f.calls = append(f.calls, want)
	return len(want), 0, nil
}

func TestApply(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	dns, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	var restarted []string
	inner := &fakeInner{}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"}
	a := &Applier{
		Store: st, Paths: paths, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, verb, unit string) error {
			restarted = append(restarted, verb+" "+unit)
			return nil
		},
		// The traffic loop reads a process right before its restart
		// (traffic-limit-v1 §2.4): the hook comes just before it.
		BeforeRestart: func(_ context.Context, service string) {
			restarted = append(restarted, "before "+render.UnitName(service))
		},
		Inner: func(string) InnerAPI { return inner },
	}
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(restarted); i += 2 {
		if !strings.HasPrefix(restarted[i], "before ") || i+1 >= len(restarted) ||
			strings.TrimPrefix(restarted[i], "before ") != strings.TrimPrefix(restarted[i+1], "restart ") {
			t.Fatalf("not read before the restart: %v", restarted)
		}
	}
	restarted = slices.DeleteFunc(restarted, func(s string) bool { return strings.HasPrefix(s, "before ") })
	slices.Sort(restarted)
	if !slices.Equal(restarted, []string{"restart niko-dns.service", "restart niko-front.service", "restart niko-inner.service"}) {
		t.Fatalf("first apply restarted %v", restarted)
	}
	a.BeforeRestart = nil
	if fi, err := os.Stat(paths.Rendered); err != nil || fi.Mode().Perm() != 0o711 {
		t.Fatalf("rendered dir must let service users through: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(paths.Rendered, "dns")); err != nil || fi.Mode().Perm() != 0o750 {
		t.Fatalf("service dir: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(paths.Rendered, "dns", "noise.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("noise key: %v %v", fi, err)
	}

	// Nothing changed: nothing restarts.
	restarted = nil
	if err := a.Apply(ctx); err != nil || len(restarted) != 0 || len(inner.calls) != 0 {
		t.Fatalf("idle apply: restarted %v, inner %v, %v", restarted, inner.calls, err)
	}

	// A new tunnel user only changes inner users: synced, not restarted.
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetUserServices(ctx, "alice", []int64{dns.ID})
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if len(restarted) != 0 || len(inner.calls) != 1 || len(inner.calls[0]) != 1 {
		t.Fatalf("user change: restarted %v, inner %v", restarted, inner.calls)
	}

	// inner off under the tunnel (a database from before the API refused
	// it): the tunnel keeps its files and process, the rest is applied (Q-1).
	// A new service at the same time still comes up.
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetServiceEnabled(ctx, "inner", false)
	restarted = nil
	err = a.Apply(ctx)
	if err == nil || !strings.Contains(err.Error(), "service dns") {
		t.Fatalf("apply without inner: %v", err)
	}
	slices.Sort(restarted)
	if !slices.Equal(restarted, []string{"restart niko-front.service", "restart niko-hy2.service"}) {
		t.Fatalf("apply without inner restarted %v", restarted)
	}
	if _, err := os.Stat(filepath.Join(paths.Rendered, "dns", "noise.key")); err != nil {
		t.Fatalf("the broken tunnel lost its files: %v", err)
	}
}

func TestSameExceptClients(t *testing.T) {
	a := []byte(`{"inbounds":[{"tag":"inner","settings":{"clients":[{"id":"1"}],"decryption":"x"}}],"log":{}}`)
	b := []byte(`{"inbounds":[{"tag":"inner","settings":{"clients":[{"id":"2"}],"decryption":"x"}}],"log":{}}`)
	c := []byte(`{"inbounds":[{"tag":"inner","settings":{"clients":[{"id":"2"}],"decryption":"y"}}],"log":{}}`)
	if !sameExceptClients(a, b) || sameExceptClients(a, c) || sameExceptClients(a, []byte("{")) {
		t.Fatal("client-only diff misdetected")
	}
}

func TestFixMeta(t *testing.T) {
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skip("no name for the current group")
	}
	p := filepath.Join(t.TempDir(), "front", "front.json")
	os.MkdirAll(filepath.Dir(p), 0o750)
	os.WriteFile(p, []byte("{}"), 0o600)
	f := render.File{Path: p, Mode: 0o640, Group: g.Name, Content: []byte("{}")}
	if fixed, err := fixMeta(f); err != nil || !fixed {
		t.Fatalf("first fix: %v %v", fixed, err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode())
	}
	if fixed, err := fixMeta(f); err != nil || fixed {
		t.Fatalf("second fix: %v %v", fixed, err)
	}
	// A group that does not exist yet is left for later.
	f.Group = "raycontrol-no-such-group"
	if fixed, err := fixMeta(f); err != nil || fixed {
		t.Fatalf("missing group: %v %v", fixed, err)
	}
}

// naive reads its users file again by itself: a new user restarts nothing.
func TestApplyReload(t *testing.T) {
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
	key, cert, err := provision.SelfSigned("site.example.com")
	if err != nil {
		t.Fatal(err)
	}
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, key)
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, cert) // only its presence matters here
	naive, _ := st.ServiceByName(ctx, "naive")

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
	if !slices.Contains(restarted, "restart niko-naive.service") {
		t.Fatalf("first apply restarted %v", restarted)
	}
	restarted = nil
	users := filepath.Join(dir, "rendered", "naive", render.NaiveUsers)
	before, _ := os.ReadFile(users)
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetUserServices(ctx, "alice", []int64{naive.ID})
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(users)
	if string(before) == string(after) || slices.Contains(restarted, "try-restart niko-naive.service") {
		t.Fatalf("users %s -> %s, restarted %v", before, after, restarted)
	}
}

// A service that fails to render keeps its process (Q-1), but who may
// connect to it still follows the database: a revoked device's key leaves
// its keys file, reread without a restart. A file that is not there is not
// made for a broken service.
func TestApplyBrokenKeepsRevoking(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	dns, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true, Settings: `{"auth":"required"}`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetUserServices(ctx, "alice", []int64{dns.ID})
	d1, _, _ := st.CreateDevice(ctx, "alice", "phone", "user")
	d2, _, _ := st.CreateDevice(ctx, "alice", "laptop", "user")

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
	keys := filepath.Join(dir, "rendered", "dns", render.DNSAuthKeys)
	if b, _ := os.ReadFile(keys); !strings.Contains(string(b), d1.ID) || !strings.Contains(string(b), d2.ID) {
		t.Fatalf("keys file:\n%s", b)
	}

	// Broken: inner off (a database from before the check), then a
	// revocation.
	st.SetServiceEnabled(ctx, "inner", false)
	must(t, st.RevokeDevice(ctx, d1.ID))
	restarted = nil
	if err := a.Apply(ctx); !render.Partial(err) {
		t.Fatalf("apply with a broken dns: %v", err)
	}
	b, _ := os.ReadFile(keys)
	if strings.Contains(string(b), d1.ID) || !strings.Contains(string(b), d2.ID) {
		t.Fatalf("revoked device still in the broken service's keys:\n%s", b)
	}
	if slices.ContainsFunc(restarted, func(s string) bool { return strings.Contains(s, "niko-dns") }) {
		t.Fatalf("broken service restarted: %v", restarted)
	}
	if _, err := os.Stat(filepath.Join(dir, "rendered", "dns", "backend.json")); err != nil {
		t.Fatalf("the broken service lost its config: %v", err)
	}
	// Not made where it is missing.
	os.Remove(keys)
	must(t, st.RevokeDevice(ctx, d2.ID))
	a.Apply(ctx)
	if _, err := os.Stat(keys); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("keys file made for a broken service: %v", err)
	}
}

// A credential rotation as apply carries it out (R4-1): the next credential
// published is one user added to inner (no restart) and to the Hysteria2
// users file (read again by the process); the switch changes no file and
// syncs nothing, so no connection is cut; the grace's end removes the
// previous credential only.
func TestApplyCredentialSwitch(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	dns, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	must(t, err)
	hy, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2", Enabled: true})
	must(t, err)
	u, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	must(t, err)
	must(t, st.SetUserServices(ctx, "alice", []int64{dns.ID, hy.ID}))

	var restarted []string
	inner := &fakeInner{}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"}
	a := &Applier{
		Store: st, Paths: paths, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, verb, unit string) error {
			restarted = append(restarted, verb+" "+unit)
			return nil
		},
		Inner: func(string) InnerAPI { return inner },
	}
	must(t, a.Apply(ctx))
	usersFile := filepath.Join(paths.Rendered, "hy2", render.HysteriaUsers)
	read := func() string {
		t.Helper()
		b, err := os.ReadFile(usersFile)
		must(t, err)
		return string(b)
	}
	step := func(at time.Duration) (calls []map[string]string, file string) {
		t.Helper()
		restarted, inner.calls = nil, nil
		r := store.Rotation{Period: 30 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Grace: 2 * 24 * time.Hour}
		if _, err := st.RotateCredentials(ctx, time.Now().Add(at), r, render.NewUUID); err != nil {
			t.Fatal(err)
		}
		must(t, a.Apply(ctx))
		if len(restarted) != 0 {
			t.Fatalf("after %v: restarted %v", at, restarted)
		}
		return inner.calls, read()
	}
	day := 24 * time.Hour
	before := read()
	calls, published := step(28 * day)
	if len(calls) != 1 || len(calls[0]) != 2 || published == before {
		t.Fatalf("published: inner %v, users file the same %v", calls, published == before)
	}
	if calls, switched := step(31 * day); len(calls) != 0 || switched != published {
		t.Fatalf("the switch: inner %v, users file changed %v", calls, switched != published)
	}
	calls, ended := step(34 * day)
	if len(calls) != 1 || len(calls[0]) != 1 || ended == published || strings.Count(ended, `"name"`) != 1 {
		t.Fatalf("the grace's end: inner %v, users file\n%s", calls, ended)
	}
	// What stays is the credential that was next, under the name it was
	// published with.
	innerSvc, err := st.ServiceByName(ctx, "inner")
	must(t, err)
	sets, err := st.CredentialSets(ctx, innerSvc.ID, nil, nil)
	must(t, err)
	if name := store.CredentialName(u.ID, sets[u.ID].Current); calls[0][name] != sets[u.ID].Current {
		t.Fatalf("inner keeps %v, want %s", calls[0], name)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
