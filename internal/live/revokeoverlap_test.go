package live

import (
	"context"
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

// firstOr is the first of the calls, or none.
func firstOr(calls []map[string]string) map[string]string {
	if len(calls) == 0 {
		return nil
	}
	return calls[0]
}

// A revocation with overlap as apply carries it out (R4-43): the user's
// credentials rotate, so the apply gives the processes a fresh next secret
// beside the current one and drops the next one in flight, which the
// revoked device may have fetched, without a restart; at the switch the
// current one is the previous, and after the grace none the revoked device
// knew is left. Another user's stay.
func TestApplyRevocationOverlap(t *testing.T) {
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
	// What alice's devices knew, per service: the current secret and the
	// next one in flight.
	current, inFlight := map[int64]string{}, map[int64]string{}
	for _, svc := range []int64{innerSvc.ID, hy.ID} {
		sets, err := st.CredentialSets(ctx, svc, nil, nil)
		must(t, err)
		if sets[alice.ID].Next == "" {
			t.Fatalf("no next on %d", svc)
		}
		current[svc], inFlight[svc] = sets[alice.ID].Current, sets[alice.ID].Next
	}
	usersFile := filepath.Join(paths.Rendered, "hy2", render.HysteriaUsers)
	bobBefore, _ := st.CredentialSets(ctx, hy.ID, nil, nil)
	alicePrefix := "u" + strconv.FormatInt(alice.ID, 10) + "-"
	// check is what the processes take of alice's after an apply: how many
	// names on inner, which of the secrets she had, and the fresh ones.
	// names 0: inner is not synced at all, its users the same.
	check := func(when string, names int, withCurrent bool) {
		t.Helper()
		if len(restarted) != 0 {
			t.Fatalf("%s: restarted %v", when, restarted)
		}
		if names == 0 && len(inner.calls) != 0 || names > 0 && len(inner.calls) != 1 {
			t.Fatalf("%s: inner synced %v", when, inner.calls)
		}
		n, sawCurrent := 0, false
		for name, secret := range firstOr(inner.calls) {
			switch secret {
			case inFlight[innerSvc.ID]:
				t.Errorf("%s: inner still takes %s, the next secret in flight, which the revoked device may have fetched", when, name)
			case current[innerSvc.ID]:
				sawCurrent = true
			}
			if strings.HasPrefix(name, alicePrefix) {
				n++
			}
		}
		if n != names || names > 0 && sawCurrent != withCurrent {
			t.Errorf("%s: alice has %d credentials on inner, want %d, the one the revoked device knew %v: %v", when, n, names, withCurrent, inner.calls)
		}
		b, err := os.ReadFile(usersFile)
		must(t, err)
		if strings.Contains(string(b), inFlight[hy.ID]) {
			t.Errorf("%s: the Hysteria2 users file still has the next secret in flight:\n%s", when, b)
		}
		if strings.Contains(string(b), current[hy.ID]) != withCurrent {
			t.Errorf("%s: the Hysteria2 users file has the secret the revoked device knew: %v, want %v\n%s", when, !withCurrent, withCurrent, b)
		}
		sets, _ := st.CredentialSets(ctx, hy.ID, nil, nil)
		if fresh := sets[alice.ID]; !strings.Contains(string(b), fresh.Current) || (fresh.Next != "" && !strings.Contains(string(b), fresh.Next)) {
			t.Errorf("%s: alice's credentials %+v not all in the users file:\n%s", when, fresh, b)
		}
		if sets[bob.ID] != bobBefore[bob.ID] || !strings.Contains(string(b), sets[bob.ID].Current) {
			t.Errorf("%s: bob's credential changed or left the users file", when)
		}
		restarted, inner.calls = nil, nil
	}

	restarted, inner.calls = nil, nil
	rev, err := st.RevokeDeviceOverlap(ctx, phone.ID)
	if err != nil || rev.SwitchAt.IsZero() {
		t.Fatalf("revoke: %+v %v", rev, err)
	}
	must(t, a.Apply(ctx))
	check("the revocation", 2, true) // the current secret and a fresh next one
	// The switch, a lead later: the one the device knew is the previous,
	// still taken, under the same name (traffic-limit-v1 §2.6): nothing to
	// sync, no connection cut.
	if _, err := st.RotateCredentials(ctx, rev.SwitchAt, r, render.NewUUID); err != nil {
		t.Fatal(err)
	}
	must(t, a.Apply(ctx))
	check("the switch", 0, true)
	// The grace over: nothing it knew is taken.
	if _, err := st.RotateCredentials(ctx, rev.Until, r, render.NewUUID); err != nil {
		t.Fatal(err)
	}
	must(t, a.Apply(ctx))
	check("the grace over", 1, false)
}
