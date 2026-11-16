package store

import (
	"context"
	"slices"
	"testing"
	"time"
)

// Regression tests from the fourth review of R4-43: a rotation a
// revocation with overlap began, switched, its previous secret (which the
// revoked device knew) still accepted, is renewed before a rayd before
// v0.31.0 goes in, whatever its timing.

// renewAfter closes f's store and runs the renewal on its database.
func renewAfter(t *testing.T, f renewFix) []string {
	t.Helper()
	f.s.Close()
	users, err := RenewOverlapRotations(context.Background(), f.path, "t", "rollback")
	if err != nil {
		t.Fatal(err)
	}
	return users
}

// -cred-period 0 -cred-lead 0 (credRotation accepts it): the switch is
// "now", rotated_at the revocation's own second.
func TestRenewOverlapRotationsLeadZero(t *testing.T) {
	ctx := context.Background()
	r := Rotation{Lead: 0, Grace: 12 * time.Hour}
	f := newRenewFix(t, r, "alice", "bob")
	t0 := time.Now().Truncate(time.Second).Add(-time.Hour)
	f.exec(t, `UPDATE credentials SET created_at = ?1, rotated_at = ?1`, t0.Add(-30*24*time.Hour).Unix())
	f.s.SetClock(func() time.Time { return t0 })
	rev, err := f.s.RevokeDeviceOverlap(ctx, f.devs["alice"][0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RotateCredentials(ctx, t0.Add(5*time.Minute), r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if users := renewAfter(t, f); !slices.Equal(users, []string{"alice"}) {
		t.Errorf("lead 0: renewed %v; alice's previous secret, the revoked phone's, accepted until %v", users, rev.Until)
	}
}

// The lead lowered (rayd restarted with a smaller -cred-lead) between the
// revocation and the switch.
func TestRenewOverlapRotationsLeadLowered(t *testing.T) {
	ctx := context.Background()
	r := Rotation{Lead: DefaultRotation.Lead, Grace: DefaultRotation.Grace}
	f := newRenewFix(t, r, "alice", "bob")
	t0 := time.Now().Truncate(time.Second).Add(-r.Lead - time.Hour)
	f.exec(t, `UPDATE credentials SET created_at = ?1, rotated_at = ?1`, t0.Add(-30*24*time.Hour).Unix())
	f.s.SetClock(func() time.Time { return t0 })
	if _, err := f.s.RevokeDeviceOverlap(ctx, f.devs["alice"][0].ID); err != nil {
		t.Fatal(err)
	}
	r2 := Rotation{Lead: time.Hour, Grace: r.Grace}
	must(t, f.s.SetRotation(ctx, r2))
	if _, err := f.s.RotateCredentials(ctx, t0.Add(r.Lead+5*time.Minute), r2, NewUUID); err != nil {
		t.Fatal(err)
	}
	if users := renewAfter(t, f); !slices.Equal(users, []string{"alice"}) {
		t.Errorf("lead lowered: renewed %v", users)
	}
}

// A small lead, two revocations, the second after the chain's bound and
// before the loop's next round (every 10 minutes): its switch is "now".
func TestRenewOverlapRotationsChainLateLoop(t *testing.T) {
	ctx := context.Background()
	r := Rotation{Lead: 3 * time.Minute, Grace: 12 * time.Hour}
	f := newRenewFix(t, r, "alice", "bob")
	t0 := time.Now().Truncate(time.Second).Add(-time.Hour)
	f.exec(t, `UPDATE credentials SET created_at = ?1, rotated_at = ?1`, t0.Add(-30*24*time.Hour).Unix())
	f.s.SetClock(func() time.Time { return t0 })
	if _, err := f.s.RevokeDeviceOverlap(ctx, f.devs["alice"][0].ID); err != nil {
		t.Fatal(err)
	}
	f.s.SetClock(func() time.Time { return t0.Add(7 * time.Minute) })
	if _, err := f.s.RevokeDeviceOverlap(ctx, f.devs["alice"][1].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RotateCredentials(ctx, t0.Add(10*time.Minute), r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if users := renewAfter(t, f); !slices.Equal(users, []string{"alice"}) {
		t.Errorf("chain past its bound: renewed %v", users)
	}
}

// The default lead, one revocation, switched by the loop late (rayd down a
// day over the switch).
func TestRenewOverlapRotationsLateSwitch(t *testing.T) {
	ctx := context.Background()
	r := Rotation{Lead: DefaultRotation.Lead, Grace: DefaultRotation.Grace}
	f := newRenewFix(t, r, "alice", "bob")
	t0 := time.Now().Truncate(time.Second).Add(-r.Lead - 24*time.Hour)
	f.exec(t, `UPDATE credentials SET created_at = ?1, rotated_at = ?1`, t0.Add(-30*24*time.Hour).Unix())
	f.s.SetClock(func() time.Time { return t0 })
	if _, err := f.s.RevokeDeviceOverlap(ctx, f.devs["alice"][0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RotateCredentials(ctx, t0.Add(r.Lead+24*time.Hour-time.Minute), r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if users := renewAfter(t, f); !slices.Equal(users, []string{"alice"}) {
		t.Errorf("late switch: renewed %v", users)
	}
}

// A database of another schema than this build's is not migrated by the
// renewal: nothing renewed, the schema as it was (review 4, nit 5).
func TestRenewOverlapRotationsOtherSchema(t *testing.T) {
	ctx := context.Background()
	f := newRenewFix(t, Rotation{Lead: DefaultRotation.Lead, Grace: DefaultRotation.Grace}, "alice")
	f.s.SetClock(func() time.Time { return time.Now().Add(time.Minute) })
	if _, err := f.s.RevokeDeviceOverlap(ctx, f.devs["alice"][0].ID); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `DELETE FROM schema_migrations WHERE version = ?`, KnownSchema())
	if users := renewAfter(t, f); len(users) != 0 {
		t.Errorf("renewed %v", users)
	}
	if v, err := Schema(ctx, f.path); err != nil || v != KnownSchema()-1 {
		t.Errorf("schema %d %v", v, err)
	}
}

// A late scheduled switch of a user with a device revoked before the
// current secret became current keeps R4-1's grace after the round: the
// device is no revocation of this rotation (review 4, M6).
func TestRotateLateSwitchGraceAfterRevocation(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	f := newRenewFix(t, r, "alice")
	t1 := time.Now().Truncate(time.Second).Add(time.Minute)
	f.s.SetClock(func() time.Time { return t1 })
	if _, err := f.s.RevokeDevice(ctx, f.devs["alice"][0].ID); err != nil {
		t.Fatal(err)
	}
	c0 := credRowsOf(t, f.s.db)["alice"][f.svc]
	if _, err := f.s.RotateCredentials(ctx, t1.Add(r.Period-r.Lead), r, NewUUID); err != nil {
		t.Fatal(err)
	}
	c1 := credRowsOf(t, f.s.db)["alice"][f.svc]
	back := time.Unix(c1.NextFrom, 0).Add(r.Grace + time.Hour)
	if _, err := f.s.RotateCredentials(ctx, back, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if c2 := credRowsOf(t, f.s.db)["alice"][f.svc]; c1.Next == "" || c2.Prev != c0.Secret || c2.PrevUntil != back.Add(r.Grace).Unix() {
		t.Errorf("late: the previous until back+%v", time.Unix(c2.PrevUntil, 0).Sub(back))
	}
}

// A rotation a revocation with overlap began in the second of a switch,
// after it, the previous secret of that switch still there at its own
// switch (a lead shorter than the grace), late: the previous secret for
// the grace after its time, as for any revocation's (review 4, M18).
func TestRotateLateSwitchSameSecondRevocation(t *testing.T) {
	ctx := context.Background()
	r := Rotation{Lead: time.Hour, Grace: 12 * time.Hour}
	f := newRenewFix(t, r, "alice")
	t0 := time.Now().Truncate(time.Second).Add(time.Minute)
	f.s.SetClock(func() time.Time { return t0 })
	rev0, err := f.s.RevokeDeviceOverlap(ctx, f.devs["alice"][0].ID)
	if err != nil {
		t.Fatal(err)
	}
	S := rev0.SwitchAt
	if _, err := f.s.RotateCredentials(ctx, S, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	f.s.SetClock(func() time.Time { return S })
	rev, err := f.s.RevokeDeviceOverlap(ctx, f.devs["alice"][1].ID)
	if err != nil {
		t.Fatal(err)
	}
	late := rev.SwitchAt.Add(30 * time.Minute)
	if _, err := f.s.RotateCredentials(ctx, late, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if c := credRowsOf(t, f.s.db)["alice"][f.svc]; c.PrevUntil != rev.Until.Unix() {
		t.Errorf("the previous until switch+%v, announced switch+%v",
			time.Unix(c.PrevUntil, 0).Sub(rev.SwitchAt), rev.Until.Sub(rev.SwitchAt))
	}
}
