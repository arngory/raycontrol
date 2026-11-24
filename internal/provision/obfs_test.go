package provision

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// A rotation of hy2-obfs's S (spec/salamander-device-v1.md §3): the next
// S published at once, accepted from then, its switch a lead away; at the
// switch it is current and the previous one accepted for the grace, then
// dropped. A second request while one is published keeps it; -now
// replaces S at once with nothing kept.
func TestRotateObfsPassword(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Domain: "example.com", Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2o", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	state := func(now time.Time) (store.Service, map[string][]byte, [][]byte) {
		t.Helper()
		svc, err := st.ServiceByName(ctx, "hy2o")
		if err != nil {
			t.Fatal(err)
		}
		secrets, err := st.ServiceSecrets(ctx, svc.ID)
		if err != nil {
			t.Fatal(err)
		}
		return svc, secrets, ObfsSecrets(svc, secrets, now)
	}
	now := time.Unix(1_800_000_000, 0)
	lead, grace := 72*time.Hour, 48*time.Hour
	svc, s0, acc := state(now)
	first := s0[SecretObfsPassword]
	if len(acc) != 1 || !bytes.Equal(acc[0], first) || len(first) != 32 {
		t.Fatalf("before a rotation: %q", acc)
	}
	if _, _, ok := ObfsNext(svc, s0); ok {
		t.Fatal("a next S before a rotation")
	}
	if _, err := RotateObfsPassword(ctx, st, "ssh", now, lead, false); err == nil {
		t.Fatal("ssh rotated as hy2-obfs")
	}

	got, err := RotateObfsPassword(ctx, st, "hy2o", now, lead, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.NextFrom != now.Add(lead).Unix() {
		t.Fatalf("state %+v", got)
	}
	svc, s1, acc := state(now)
	next, from, ok := ObfsNext(svc, s1)
	if !ok || !from.Equal(now.Add(lead)) || len(next) != 32 || bytes.Equal(next, first) || !bytes.Equal(s1[SecretObfsPassword], first) {
		t.Fatalf("next %q from %v, current %q", next, from, s1[SecretObfsPassword])
	}
	if len(acc) != 2 || !bytes.Equal(acc[0], first) || !bytes.Equal(acc[1], next) {
		t.Fatalf("published: accepted %q", acc)
	}
	// Asked again: the published one stays.
	if again, err := RotateObfsPassword(ctx, st, "hy2o", now.Add(time.Hour), lead, false); err != nil || again.NextFrom != got.NextFrom {
		t.Fatalf("asked again: %+v %v", again, err)
	}
	if _, s, _ := state(now); !bytes.Equal(s[NextSecret(SecretObfsPassword)], next) {
		t.Fatal("asked again: another next S")
	}
	// Not due: nothing.
	if n, err := AdvanceObfs(ctx, st, from.Add(-time.Second), grace, log); err != nil || n != 0 {
		t.Fatalf("before the switch: %d %v", n, err)
	}
	if n, err := AdvanceObfs(ctx, st, from, grace, log); err != nil || n != 1 {
		t.Fatalf("the switch: %d %v", n, err)
	}
	svc, s2, acc := state(from)
	if st := ParseObfsState(svc); st.RotatedAt != from.Unix() || st.NextFrom != 0 || st.PrevUntil != from.Add(grace).Unix() {
		t.Fatalf("after the switch: %+v", st)
	}
	if !bytes.Equal(s2[SecretObfsPassword], next) || len(acc) != 2 || !bytes.Equal(acc[1], first) {
		t.Fatalf("after the switch: current %q, accepted %q", s2[SecretObfsPassword], acc)
	}
	if _, _, acc := state(from.Add(grace)); len(acc) != 1 {
		t.Fatalf("past the grace, before the loop: %q", acc)
	}
	if n, err := AdvanceObfs(ctx, st, from.Add(grace), grace, log); err != nil || n != 1 {
		t.Fatalf("the grace's end: %d %v", n, err)
	}
	svc, s3, _ := state(from.Add(grace))
	if _, ok := s3[PrevSecret(SecretObfsPassword)]; ok || ParseObfsState(svc).PrevUntil != 0 {
		t.Fatal("the previous S kept past its grace")
	}

	// -now: a new S at once, a published next and a previous dropped.
	if _, err := RotateObfsPassword(ctx, st, "hy2o", now, lead, false); err != nil {
		t.Fatal(err)
	}
	at := from.Add(grace + time.Hour)
	if got, err = RotateObfsPassword(ctx, st, "hy2o", at, lead, true); err != nil {
		t.Fatal(err)
	}
	svc, s4, acc := state(at)
	if got.RotatedAt != at.Unix() || got.NextFrom != 0 || got.PrevUntil != 0 || len(acc) != 1 ||
		bytes.Equal(s4[SecretObfsPassword], next) || len(s4[SecretObfsPassword]) != 32 {
		t.Fatalf("-now: %+v, accepted %q", got, acc)
	}
	if _, ok := s4[NextSecret(SecretObfsPassword)]; ok {
		t.Fatal("-now kept the next S")
	}
	if ParseObfsState(svc) != got {
		t.Fatalf("stored %+v, returned %+v", ParseObfsState(svc), got)
	}
}
