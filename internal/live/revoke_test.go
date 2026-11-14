package live

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// failingInner is an Xray whose API does not answer.
type failingInner struct{}

func (failingInner) SyncVLESS(context.Context, string, string, map[string]string) (int, int, error) {
	return 0, 0, errors.New("no answer")
}

// A revocation as apply carries it out (R4-36): the user's credentials are
// new, a rotation in flight included, so the apply leaves the processes
// only the new ones, none the revoked device knew (current, next or
// previous), without a restart; another user's stay. When Xray's API does
// not answer, the process is restarted, and a restart that fails stays
// owed and makes the apply fail until it is done.
func TestApplyRevocationRenews(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	must(t, err)
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	dns, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	must(t, err)
	hy, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2", Enabled: true})
	must(t, err)
	alice, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true, Services: []int64{dns.ID, hy.ID}})
	must(t, err)
	bob, err := st.CreateUser(ctx, store.User{Name: "bob", Enabled: true, Services: []int64{dns.ID, hy.ID}})
	must(t, err)
	phone, _, _ := st.CreateDevice(ctx, "alice", "phone", "user")
	st.CreateDevice(ctx, "alice", "laptop", "user")

	var restarted []string
	restartErr := error(nil)
	inner := &fakeInner{}
	var api InnerAPI = inner
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"}
	a := &Applier{
		Store: st, Paths: paths, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, verb, unit string) error {
			restarted = append(restarted, verb+" "+unit)
			return restartErr
		},
		Inner: func(string) InnerAPI { return api },
	}
	must(t, a.Apply(ctx))
	// A rotation in flight: the next credentials published.
	r := store.Rotation{Period: 30 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Grace: 2 * 24 * time.Hour}
	if _, err := st.RotateCredentials(ctx, time.Now().Add(28*24*time.Hour), r, render.NewUUID); err != nil {
		t.Fatal(err)
	}
	must(t, a.Apply(ctx))
	innerSvc, err := st.ServiceByName(ctx, "inner")
	must(t, err)
	known := map[string]bool{} // what alice's devices knew
	for _, svc := range []int64{innerSvc.ID, hy.ID} {
		sets, err := st.CredentialSets(ctx, svc, nil, nil)
		must(t, err)
		if sets[alice.ID].Next == "" {
			t.Fatalf("no next on %d", svc)
		}
		known[sets[alice.ID].Current], known[sets[alice.ID].Next] = true, true
	}
	usersFile := filepath.Join(paths.Rendered, "hy2", render.HysteriaUsers)
	bobBefore, _ := st.CredentialSets(ctx, hy.ID, nil, nil)

	restarted, inner.calls = nil, nil
	if _, err := st.RevokeDevice(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	must(t, a.Apply(ctx))
	if len(restarted) != 0 {
		t.Fatalf("restarted %v", restarted)
	}
	if len(inner.calls) != 1 {
		t.Fatalf("inner synced %v", inner.calls)
	}
	aliceNames := 0
	for name, secret := range inner.calls[0] {
		if known[secret] {
			t.Errorf("inner still takes %s, which the revoked device knew", name)
		}
		if strings.HasPrefix(name, "u"+strconv.FormatInt(alice.ID, 10)+"-") {
			aliceNames++
		}
	}
	if aliceNames != 1 {
		t.Errorf("alice has %d credentials on inner, want the new one only: %v", aliceNames, inner.calls[0])
	}
	b, err := os.ReadFile(usersFile)
	must(t, err)
	for secret := range known {
		if strings.Contains(string(b), secret) {
			t.Errorf("the Hysteria2 users file still has a secret the revoked device knew:\n%s", b)
		}
	}
	bobAfter, _ := st.CredentialSets(ctx, hy.ID, nil, nil)
	if bobAfter[bob.ID] != bobBefore[bob.ID] || !strings.Contains(string(b), bobAfter[bob.ID].Current) {
		t.Errorf("bob's credential changed or left the users file")
	}

	// Xray's API down: the next revocation restarts the process instead;
	// the restart failing, it stays owed and the apply fails until it
	// works.
	laptop := ""
	devs, _ := st.ListDevices(ctx, "alice")
	for _, d := range devs {
		if d.RevokedAt == nil {
			laptop = d.ID
		}
	}
	api, restartErr, restarted = failingInner{}, errors.New("unit failed"), nil
	if _, err := st.RevokeDevice(ctx, laptop); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx); err == nil || !strings.Contains(err.Error(), "niko-inner") {
		t.Fatalf("apply with the restart failing: %v", err)
	}
	if a.owed()["inner"] == "" {
		t.Fatalf("the restart of inner is not owed: %v", a.owed())
	}
	restartErr, restarted = nil, nil
	if err := a.Apply(ctx); err != nil && !render.Partial(err) {
		t.Fatalf("the next apply: %v", err)
	}
	if len(restarted) != 1 || restarted[0] != "try-restart niko-inner.service" || len(a.owed()) != 0 {
		t.Fatalf("the owed restart: %v, owed %v", restarted, a.owed())
	}
}
