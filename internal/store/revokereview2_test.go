package store

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// Regression tests from the second review of R4-43.

// A rollback that keeps the database (the same schema) to a rayd that runs
// no rotation loop: the users with a rotation in flight get new
// credentials, audited: one a revocation with overlap began, not switched
// (alice) or switched with a previous secret still accepted (carol), and
// one the schedule began before the period went to 0 (erin, renewed by
// design since review 4); one revoked without overlap (bob) and one never
// revoked (dave) keep theirs (review 2, B1).
func TestRenewOverlapRotations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	r := Rotation{Lead: DefaultRotation.Lead, Grace: DefaultRotation.Grace} // -cred-period 0
	must(t, s.SetRotation(ctx, r))
	svc, _ := s.CreateService(ctx, Service{Kind: "naive", Name: "naive", Enabled: true, Settings: "{}"})
	doh, _ := s.CreateService(ctx, Service{Kind: "doh", Name: "doh", Enabled: true, Settings: "{}"})
	ids := map[string]int64{}
	for _, n := range []string{"alice", "bob", "carol", "dave", "erin"} {
		u, _ := s.CreateUser(ctx, User{Name: n, Enabled: true, Services: []int64{svc.ID, doh.ID}})
		ids[n] = u.ID
	}
	for _, id := range []int64{svc.ID, doh.ID} {
		if _, err := s.Credentials(ctx, id, []int64{ids["alice"], ids["bob"], ids["carol"], ids["dave"], ids["erin"]}, NewUUID); err != nil {
			t.Fatal(err)
		}
	}
	// bob's DoH secret has a next of a schedule from before -cred-period 0:
	// DoH is no revocation's (R4-37), and makes him no user to renew.
	if _, err := s.db.Exec(`UPDATE credentials SET next_secret = 'n', next_from = ? WHERE user_id = ? AND service_id = ?`,
		time.Now().Add(DefaultRotation.Lead).Unix(), ids["bob"], doh.ID); err != nil {
		t.Fatal(err)
	}
	devs := map[string]Device{}
	for _, n := range []string{"alice", "bob", "carol", "dave", "erin"} {
		devs[n], _, _ = s.CreateDevice(ctx, n, "phone", "user")
	}
	known := credRowsOf(t, s.db)
	t0 := time.Now().Truncate(time.Second).Add(time.Minute)
	s.SetClock(func() time.Time { return t0 })
	if _, err := s.RevokeDeviceOverlap(ctx, devs["alice"].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeDevice(ctx, devs["bob"].ID); err != nil {
		t.Fatal(err)
	}
	rev, err := s.RevokeDeviceOverlap(ctx, devs["carol"].ID)
	if err != nil {
		t.Fatal(err)
	}
	// carol's rotation switched (by hand, as the loop would at its time),
	// her previous secret, the one her phone knew, in its grace.
	if _, err := s.db.Exec(`UPDATE credentials SET prev_secret = secret, prev_until = ?, secret = next_secret,
		next_secret = NULL, next_from = NULL, rotated_at = ? WHERE user_id = ? AND service_id = ?`,
		rev.Until.Unix(), rev.SwitchAt.Unix(), ids["carol"], svc.ID); err != nil {
		t.Fatal(err)
	}
	// erin's phone revoked, her credentials renewed a second later (user
	// renew), then a next of a schedule from before -cred-period 0.
	if _, err := s.RevokeDevice(ctx, devs["erin"].ID); err != nil {
		t.Fatal(err)
	}
	s.SetClock(func() time.Time { return t0.Add(time.Second) })
	if _, err := s.RenewUser(ctx, "erin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE credentials SET next_secret = 'n', next_from = ? WHERE user_id = ? AND service_id = ?`,
		t0.Add(DefaultRotation.Lead).Unix(), ids["erin"], svc.ID); err != nil {
		t.Fatal(err)
	}
	before := credRowsOf(t, s.db)
	s.Close()

	users, err := RenewOverlapRotations(ctx, path, "rayctl update -rollback", "rollback")
	if err != nil || !slices.Equal(users, []string{"alice", "carol", "erin"}) {
		t.Fatalf("renewed %v %v", users, err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := credRowsOf(t, s.db)
	for _, n := range []string{"alice", "carol", "erin"} {
		c := got[n][svc.ID]
		if c.Secret == known[n][svc.ID].Secret || c.Secret == before[n][svc.ID].Secret || c.Next != "" || c.Prev != "" {
			t.Errorf("%s: %+v", n, c)
		}
	}
	for _, n := range []string{"bob", "dave"} {
		if got[n][svc.ID] != before[n][svc.ID] || got[n][doh.ID] != before[n][doh.ID] {
			t.Errorf("%s changed: %+v", n, got[n])
		}
	}
	for _, n := range []string{"alice", "carol", "erin"} {
		if got[n][doh.ID] != before[n][doh.ID] {
			t.Errorf("%s's DoH secret changed", n)
		}
	}
	// Nothing a revoked phone knew is accepted a year on, with no loop.
	sets, _ := s.CredentialSets(ctx, svc.ID, nil, nil)
	for _, n := range []string{"alice", "carol"} {
		for _, sec := range sets[ids[n]].Accepted(time.Now().Add(365 * 24 * time.Hour)) {
			if sec == known[n][svc.ID].Secret {
				t.Errorf("%s's phone's secret accepted", n)
			}
		}
	}
	a, _ := s.ListAudit(ctx, 20)
	if !hasAudit(a, "user.renew:rollback", "alice: 1 credentials new, a rotation in flight, which the rayd that goes in") ||
		!hasAudit(a, "user.renew:rollback", "carol: 1 credentials new") || hasAudit(a, "user.renew:rollback", "bob") {
		t.Errorf("audit %+v", a)
	}
	if got, err := RotationAt(ctx, path); err != nil || got != r {
		t.Errorf("the stored schedule: %+v %v", got, err)
	}
}

// A device revoked with overlap in the second of a switch, after it, knew
// the new current secret: it counts in the chain, which bounds what it
// knew to 2 x lead + grace (review 2, nit 1).
func TestRevokeOverlapSameSecondSwitchChain(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	s, svcs, _ := revokeNode(t, r)
	var devs []Device
	for _, n := range []string{"x", "a", "b", "c"} {
		d, _, _ := s.CreateDevice(ctx, "alice", n, "user")
		devs = append(devs, d)
	}
	t0 := time.Now().Truncate(time.Second).Add(time.Minute)
	s.SetClock(func() time.Time { return t0 })
	rev0, err := s.RevokeDeviceOverlap(ctx, devs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	S := rev0.SwitchAt
	if _, err := s.RotateCredentials(ctx, S, r, NewUUID); err != nil { // the loop in the switch's second
		t.Fatal(err)
	}
	known := credRowsOf(t, s.db)["alice"][svcs[0]].Secret
	s.SetClock(func() time.Time { return S })
	if _, err := s.RevokeDeviceOverlap(ctx, devs[1].ID); err != nil {
		t.Fatal(err)
	}
	tb := S.Add(r.Lead - time.Hour)
	s.SetClock(func() time.Time { return tb })
	if _, err := s.RevokeDeviceOverlap(ctx, devs[2].ID); err != nil {
		t.Fatal(err)
	}
	tc := tb.Add(r.Lead - time.Hour)
	s.SetClock(func() time.Time { return tc })
	rev, err := s.RevokeDeviceOverlap(ctx, devs[3].ID)
	if err != nil {
		t.Fatal(err)
	}
	if c := credRowsOf(t, s.db)["alice"][svcs[0]]; c.Secret != known {
		t.Fatalf("current changed: %+v", c)
	}
	if bound := S.Add(2*r.Lead + r.Grace); rev.Until.After(bound) {
		t.Errorf("what the device revoked at the switch knew is accepted %v past 2 x lead + grace", rev.Until.Sub(bound))
	}
}

// The chain's boundary to the second: a revocation one second after the
// credentials became current starts the chain (review 2, R8).
func TestRevokeOverlapChainBoundary(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	s, svcs, _ := revokeNode(t, r)
	var devs []Device
	for _, n := range []string{"a", "b", "c"} {
		d, _, _ := s.CreateDevice(ctx, "alice", n, "user")
		devs = append(devs, d)
	}
	rotated := time.Unix(credRowsOf(t, s.db)["alice"][svcs[0]].Rotated, 0)
	ta := rotated.Add(time.Second)
	s.SetClock(func() time.Time { return ta })
	if _, err := s.RevokeDeviceOverlap(ctx, devs[0].ID); err != nil {
		t.Fatal(err)
	}
	tb := ta.Add(r.Lead - time.Hour)
	s.SetClock(func() time.Time { return tb })
	if _, err := s.RevokeDeviceOverlap(ctx, devs[1].ID); err != nil {
		t.Fatal(err)
	}
	tc := tb.Add(r.Lead - time.Hour)
	s.SetClock(func() time.Time { return tc })
	rev, err := s.RevokeDeviceOverlap(ctx, devs[2].ID)
	if err != nil || !rev.SwitchAt.Equal(ta.Add(2*r.Lead)) {
		t.Fatalf("the third: switch at ta+%v, want ta+%v (%v)", rev.SwitchAt.Sub(ta), 2*r.Lead, err)
	}
}

// A device revoked without overlap, then a next the schedule published:
// revoking it again says nothing it knew is still accepted (review 2,
// R1/R2).
func TestRevokeRepeatAfterPlainScheduled(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	s, _, _ := revokeNode(t, r)
	stolen, _, _ := s.CreateDevice(ctx, "alice", "stolen", "user")
	t0 := time.Now().Truncate(time.Second).Add(time.Minute)
	s.SetClock(func() time.Time { return t0 })
	if _, err := s.RevokeDevice(ctx, stolen.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateCredentials(ctx, t0.Add(r.Period-r.Lead), r, NewUUID); err != nil {
		t.Fatal(err)
	}
	again, err := s.RevokeDeviceOverlap(ctx, stolen.ID)
	if err != nil || !again.Already || !again.Until.IsZero() {
		t.Errorf("repeat after a plain revocation and a scheduled next: %+v %v", again, err)
	}
}

// A repeat goes by the schedule rayd set on the Store, whatever the
// database holds (review 2, R10).
func TestRevokeRepeatInMemorySchedule(t *testing.T) {
	ctx := context.Background()
	r := Rotation{Lead: 2 * time.Hour, Grace: 13 * time.Hour}
	s, _, _ := revokeNode(t, r)
	phone, _, _ := s.CreateDevice(ctx, "alice", "phone", "user")
	t0 := time.Now().Truncate(time.Second).Add(time.Minute)
	s.SetClock(func() time.Time { return t0 })
	rev, err := s.RevokeDeviceOverlap(ctx, phone.ID)
	if err != nil {
		t.Fatal(err)
	}
	must(t, s.SetSetting(ctx, settingRotation, []byte(`{"period":0,"lead":60,"grace":43200}`)))
	again, err := s.RevokeDevice(ctx, phone.ID)
	if err != nil || !again.Until.Equal(rev.Until) || !rev.Until.Equal(t0.Add(r.Lead+r.Grace)) {
		t.Errorf("repeat: until %v, the revocation's %v", again.Until, rev.Until)
	}
}

// rayd down over a switch: the loop's first round after it switches, and
// the previous secret is accepted until the switch's time plus the grace,
// what the revocation announced, not the round's (review 2, nit 2).
func TestRevokeOverlapDowntimeKeepsUntil(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	s, svcs, _ := revokeNode(t, r)
	a, _, _ := s.CreateDevice(ctx, "alice", "a", "user")
	t0 := time.Now().Truncate(time.Second).Add(time.Minute)
	s.SetClock(func() time.Time { return t0 })
	rev, err := s.RevokeDeviceOverlap(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateCredentials(ctx, rev.SwitchAt.Add(24*time.Hour), r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if c := credRowsOf(t, s.db)["alice"][svcs[0]]; c.PrevUntil != rev.Until.Unix() {
		t.Errorf("the previous secret until t0+%v, announced t0+%v", time.Unix(c.PrevUntil, 0).Sub(t0), rev.Until.Sub(t0))
	}
}

// A restore that keeps a rotation: of the user's devices revoked since the
// backup, the one revoked without overlap before it is labelled as
// renewed, the one revoked with overlap as rotating (review 2, nit 3).
func TestCarryRestorePlainNotRotating(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil)
	s := f.open(t, f.current)
	must(t, s.SetRotation(ctx, DefaultRotation))
	tablet, _, _ := s.CreateDevice(ctx, "alice", "tablet", "user")
	s.Close()
	copyFile(t, f.current, f.backup) // the backup has the phone and the tablet
	s = f.open(t, f.current)
	t1 := time.Now().Truncate(time.Second).Add(time.Minute)
	s.SetClock(func() time.Time { return t1 })
	if _, err := s.RevokeDevice(ctx, tablet.ID); err != nil { // stolen: without overlap
		t.Fatal(err)
	}
	s.SetClock(func() time.Time { return t1.Add(time.Hour) })
	if _, err := s.RevokeDeviceOverlap(ctx, f.phones["alice"].ID); err != nil {
		t.Fatal(err)
	}
	// Her DoH secret has a next of the schedule, older than the tablet's
	// revocation: DoH is no revocation's (R4-37) and labels nothing
	// (review 3, X13).
	if _, err := s.db.Exec(`UPDATE credentials SET next_secret = 'n', next_from = ? WHERE user_id = ? AND service_id = ?`,
		t1.Add(DefaultRotation.Lead).Unix(), f.ids["alice"], f.doh); err != nil {
		t.Fatal(err)
	}
	s.Close()
	res, err := CarryRestore(ctx, f.backup, f.current, "")
	if err != nil {
		t.Fatal(err)
	}
	rotating := map[string]bool{}
	for _, d := range res.Carried {
		rotating[d.Name] = d.Rotating
	}
	if len(res.Carried) != 2 || !rotating["phone"] || rotating["tablet"] {
		t.Fatalf("carried %+v", res.Carried)
	}
	a := auditOf(t, f.backup)
	if !hasAudit(a, "device.revoke:restore", f.phones["alice"].ID+" alice/phone: revoked on the node since the copy, with overlap") ||
		hasAudit(a, "device.revoke:restore", tablet.ID+" alice/tablet: revoked on the node since the copy, with overlap") {
		t.Errorf("audit %+v", a)
	}
}
