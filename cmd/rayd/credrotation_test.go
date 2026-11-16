package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/store"
)

// rayd's -cred-* flags: with a period, as ever (errors); without one, the
// lead and grace of revocations with overlap set right: a grace under
// 12 h raised, a lead out of range the default (R4-43).
func TestCredRotation(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	h := time.Hour
	day := 24 * h
	for _, c := range []struct {
		in, want store.Rotation
		err      bool
	}{
		{in: store.DefaultRotation, want: store.DefaultRotation},
		{in: store.Rotation{Period: 30 * day, Lead: 30 * day, Grace: 2 * day}, err: true},
		{in: store.Rotation{Period: 30 * day, Lead: 3 * day, Grace: 11 * h}, err: true},
		{in: store.Rotation{Lead: 2 * h, Grace: 13 * h}, want: store.Rotation{Lead: 2 * h, Grace: 13 * h}},
		{in: store.Rotation{Lead: 2 * h, Grace: h}, want: store.Rotation{Lead: 2 * h, Grace: minCredGrace}},
		{in: store.Rotation{Lead: -h, Grace: 13 * h}, want: store.Rotation{Lead: store.DefaultRotation.Lead, Grace: 13 * h}},
		{in: store.Rotation{Lead: 40 * day, Grace: 0}, want: store.Rotation{Lead: store.DefaultRotation.Lead, Grace: minCredGrace}},
		// The bounds: a lead of the default period is out, a second less in.
		{in: store.Rotation{Lead: 30 * day, Grace: 13 * h}, want: store.Rotation{Lead: store.DefaultRotation.Lead, Grace: 13 * h}},
		{in: store.Rotation{Lead: 30*day - time.Second, Grace: 13 * h}, want: store.Rotation{Lead: 30*day - time.Second, Grace: 13 * h}},
		{in: store.Rotation{Lead: 0, Grace: 13 * h}, want: store.Rotation{Lead: 0, Grace: 13 * h}},
		// A negative period is none, stored as 0 (review 5, S1).
		{in: store.Rotation{Period: -h, Lead: 2 * h, Grace: 13 * h}, want: store.Rotation{Lead: 2 * h, Grace: 13 * h}},
	} {
		got, err := credRotation(c.in, log)
		if (err != nil) != c.err || err == nil && got != c.want {
			t.Errorf("%+v: %+v %v, want %+v", c.in, got, err, c.want)
		}
	}
}

// Without a period rayd still stores its schedule for revocations with
// overlap and runs the rotation loop, which switches what one published
// and keeps the old secret for the (raised) grace (R4-43).
func TestStartCredentialRotationNoPeriod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc, err := st.CreateService(ctx, store.Service{Kind: "naive", Name: "naive", Enabled: true, Settings: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true, Services: []int64{svc.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Credentials(ctx, svc.ID, []int64{alice.ID}, store.NewUUID); err != nil {
		t.Fatal(err)
	}
	phone, _, _ := st.CreateDevice(ctx, "alice", "phone", "user")
	// A revocation with overlap whose switch is due at once (a lead of 0),
	// before rayd starts.
	if err := st.SetRotation(ctx, store.Rotation{Grace: time.Hour}); err != nil {
		t.Fatal(err)
	}
	before, _ := st.CredentialSets(ctx, svc.ID, nil, nil)
	if _, err := st.RevokeDeviceOverlap(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	published, _ := st.CredentialSets(ctx, svc.ID, nil, nil)
	if published[alice.ID].Next == "" {
		t.Fatal("nothing published")
	}

	log := slog.New(slog.DiscardHandler)
	r, err := credRotation(store.Rotation{Lead: 2 * time.Hour, Grace: time.Hour}, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := startCredentialRotation(ctx, st, r, func() {}, &health.Board{}, log); err != nil {
		t.Fatal(err)
	}
	if got, err := st.StoredRotation(ctx); err != nil || got != r || got.Grace != minCredGrace {
		t.Fatalf("the schedule revocations go by: %+v %v, rayd's %+v", got, err, r)
	}
	start := time.Now()
	for {
		sets, err := st.CredentialSets(ctx, svc.ID, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c := sets[alice.ID]; c.Current == published[alice.ID].Next {
			if c.Prev != before[alice.ID].Current || c.PrevUntil.Before(start.Add(minCredGrace-time.Minute)) ||
				c.PrevUntil.After(time.Now().Add(minCredGrace)) {
				t.Fatalf("after the switch: %+v", c)
			}
			return
		}
		if time.Since(start) > 10*time.Second {
			t.Fatalf("no switch without a period: %+v", sets[alice.ID])
		}
		time.Sleep(50 * time.Millisecond)
	}
}
