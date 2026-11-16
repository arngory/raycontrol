package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Regression tests from the third review of R4-43.

// renewFix is a database at a path with one naive service, the schedule r
// stored, and users each with a phone and a laptop.
type renewFix struct {
	path string
	s    *Store
	svc  int64
	ids  map[string]int64
	devs map[string][2]Device
}

func newRenewFix(t *testing.T, r Rotation, users ...string) renewFix {
	t.Helper()
	ctx := context.Background()
	f := renewFix{path: filepath.Join(t.TempDir(), "rayd.db"), ids: map[string]int64{}, devs: map[string][2]Device{}}
	s, err := Open(ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.s = s
	must(t, s.SetRotation(ctx, r))
	svc, _ := s.CreateService(ctx, Service{Kind: "naive", Name: "naive", Enabled: true, Settings: "{}"})
	f.svc = svc.ID
	var all []int64
	for _, n := range users {
		u, _ := s.CreateUser(ctx, User{Name: n, Enabled: true, Services: []int64{svc.ID}})
		f.ids[n] = u.ID
		all = append(all, u.ID)
	}
	if _, err := s.Credentials(ctx, svc.ID, all, NewUUID); err != nil {
		t.Fatal(err)
	}
	for _, n := range users {
		a, _, _ := s.CreateDevice(ctx, n, "phone", "user")
		b, _, _ := s.CreateDevice(ctx, n, "laptop", "user")
		f.devs[n] = [2]Device{a, b}
	}
	return f
}

func (f renewFix) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.s.db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

// No revocation with overlap, no renewal: a switch of the schedule with
// the previous secret in its grace (dave), a next the schedule published
// after a revocation without overlap (erin), after rayd went to
// -cred-period 0 (review 3, N2).
func TestRenewOverlapRotationsFalsePositives(t *testing.T) {
	ctx := context.Background()
	withPeriod := DefaultRotation
	f := newRenewFix(t, withPeriod, "dave", "erin")
	t0 := time.Now().Truncate(time.Second).Add(time.Minute)
	f.s.SetClock(func() time.Time { return t0 })
	if _, err := f.s.RevokeDevice(ctx, f.devs["erin"][0].ID); err != nil { // stolen: renewed in its second
		t.Fatal(err)
	}
	// dave's credentials from long ago: published now, switched a lead on.
	f.exec(t, `UPDATE credentials SET created_at = ?, rotated_at = NULL WHERE user_id = ?`,
		t0.Add(-withPeriod.Period).Add(-withPeriod.Lead).Unix(), f.ids["dave"])
	if _, err := f.s.RotateCredentials(ctx, t0, withPeriod, NewUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RotateCredentials(ctx, t0.Add(withPeriod.Lead), withPeriod, NewUUID); err != nil {
		t.Fatal(err)
	}
	// erin's next, the schedule's, a period after her renewal.
	f.exec(t, `UPDATE credentials SET next_secret = 'n', next_from = ? WHERE user_id = ?`, t0.Add(withPeriod.Period).Unix(), f.ids["erin"])
	rows := credRowsOf(t, f.s.db)
	if rows["dave"][f.svc].Prev == "" || rows["erin"][f.svc].Next == "" {
		t.Fatalf("fixture: %+v", rows)
	}
	must(t, f.s.SetRotation(ctx, Rotation{Lead: withPeriod.Lead, Grace: withPeriod.Grace}))
	f.s.Close()
	users, err := RenewOverlapRotations(ctx, f.path, "t", "rollback")
	if err != nil || len(users) != 0 {
		t.Errorf("renewed %v %v; none had a device revoked with overlap", users, err)
	}
}

// The renewal's edges (review 3, N2, X6, X7, X17): gina's device revoked
// with overlap in the second of a switch, after it, the previous secret
// dropped since (the loop at the end of the grace), her rotation in
// flight: renewed, with a new LAN key, not none. frank's rotation switched
// and its previous secret past its time (rayd down, not dropped yet):
// nothing is accepted, nothing to renew.
func TestRenewOverlapRotationsEdges(t *testing.T) {
	ctx := context.Background()
	r := Rotation{Lead: DefaultRotation.Lead, Grace: DefaultRotation.Grace}
	f := newRenewFix(t, r, "frank", "gina")
	f.exec(t, `UPDATE users SET lan = 1, lan_key = randomblob(?) WHERE name = 'gina'`, LANKeySize)
	var lanBefore []byte
	if err := f.s.db.QueryRow(`SELECT lan_key FROM users WHERE name = 'gina'`).Scan(&lanBefore); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Truncate(time.Second).Add(time.Minute)
	f.s.SetClock(func() time.Time { return t0 })
	var revs [2]Revocation
	for i, n := range []string{"frank", "gina"} {
		rev, err := f.s.RevokeDeviceOverlap(ctx, f.devs[n][0].ID)
		if err != nil {
			t.Fatal(err)
		}
		revs[i] = rev
	}
	S := revs[1].SwitchAt
	if _, err := f.s.RotateCredentials(ctx, S, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	f.s.SetClock(func() time.Time { return S })
	if _, err := f.s.RevokeDeviceOverlap(ctx, f.devs["gina"][1].ID); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE credentials SET prev_secret = NULL, prev_until = NULL WHERE user_id = ?`, f.ids["gina"])
	f.exec(t, `UPDATE credentials SET prev_until = ? WHERE user_id = ?`, time.Now().Add(-time.Minute).Unix(), f.ids["frank"])
	before := credRowsOf(t, f.s.db)
	if g := before["gina"][f.svc]; g.Next == "" || g.Rotated != S.Unix() || g.Prev != "" || before["frank"][f.svc].Prev == "" {
		t.Fatalf("fixture: %+v", before)
	}
	f.s.Close()
	users, err := RenewOverlapRotations(ctx, f.path, "t", "rollback")
	if err != nil || len(users) != 1 || users[0] != "gina" {
		t.Fatalf("renewed %v %v", users, err)
	}
	s, err := Open(ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after := credRowsOf(t, s.db)
	if g := after["gina"][f.svc]; g.Secret == before["gina"][f.svc].Secret || g.Next != "" {
		t.Errorf("gina: %+v", g)
	}
	if after["frank"][f.svc] != before["frank"][f.svc] {
		t.Errorf("frank renewed: %+v", after["frank"][f.svc])
	}
	var lanAfter []byte
	if err := s.db.QueryRow(`SELECT lan_key FROM users WHERE name = 'gina'`).Scan(&lanAfter); err != nil || len(lanAfter) != LANKeySize ||
		bytes.Equal(lanAfter, lanBefore) {
		t.Errorf("gina's LAN key %x -> %x (%v): the LAN off, or the revoked devices' key kept", lanBefore, lanAfter, err)
	}
}

// The same-second rule with rayd's loop running (it drops the previous
// secret at the end of the grace, shorter than the lead): once it is gone,
// a device revoked in the second of the switch is no longer counted, and
// what it knew is accepted up to (RevocationChain+1) leads + grace after
// its revocation, the documented limit; within the grace, 2 x lead + grace
// as for any other (TestRevokeOverlapSameSecondSwitchChain). Review 3, N1.
func TestRevokeOverlapSameSecondChainWithLoop(t *testing.T) {
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
	if _, err := s.RotateCredentials(ctx, S, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	known := credRowsOf(t, s.db)["alice"][svcs[0]].Secret
	s.SetClock(func() time.Time { return S })
	if _, err := s.RevokeDeviceOverlap(ctx, devs[1].ID); err != nil {
		t.Fatal(err)
	}
	tb := S.Add(r.Lead - time.Hour)
	if _, err := s.RotateCredentials(ctx, tb.Add(-time.Minute), r, NewUUID); err != nil { // the grace ended: prev dropped
		t.Fatal(err)
	}
	if c := credRowsOf(t, s.db)["alice"][svcs[0]]; c.Prev != "" || c.Secret != known {
		t.Fatalf("the loop before b: %+v", c)
	}
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
	if limit := S.Add((RevocationChain+1)*r.Lead + r.Grace); rev.Until.After(limit) {
		t.Errorf("what the device revoked at the switch knew is accepted %v past the documented limit", rev.Until.Sub(limit))
	}
}

// A scheduled switch late after rayd's downtime keeps the previous secret
// for the grace after the round, as R4-1 has it; one a revocation with
// overlap began, for the grace after its time (review 3, N3).
func TestRotateLateSwitchGrace(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	s, svcs, _ := revokeNode(t, r)
	c0 := credRowsOf(t, s.db)["alice"][svcs[0]]
	pub := time.Unix(c0.Rotated, 0).Add(r.Period - r.Lead)
	if _, err := s.RotateCredentials(ctx, pub, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	c1 := credRowsOf(t, s.db)["alice"][svcs[0]]
	if c1.Next == "" {
		t.Fatalf("not published: %+v", c1)
	}
	back := time.Unix(c1.NextFrom, 0).Add(r.Grace + time.Hour) // rayd back an hour past switch + grace
	if _, err := s.RotateCredentials(ctx, back, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if c2 := credRowsOf(t, s.db)["alice"][svcs[0]]; c2.Prev != c0.Secret || c2.PrevUntil != back.Add(r.Grace).Unix() {
		t.Errorf("scheduled, late: the previous until back+%v", time.Unix(c2.PrevUntil, 0).Sub(back))
	}
}

// A revocation with overlap in the second of a switch, after it, says on
// its repeat until when what the device knew is accepted (stillAccepted,
// the chain's rule).
func TestRevokeRepeatSameSecondSwitch(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	s, _, _ := revokeNode(t, r)
	x, _, _ := s.CreateDevice(ctx, "alice", "x", "user")
	a, _, _ := s.CreateDevice(ctx, "alice", "a", "user")
	t0 := time.Now().Truncate(time.Second).Add(time.Minute)
	s.SetClock(func() time.Time { return t0 })
	rev0, err := s.RevokeDeviceOverlap(ctx, x.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateCredentials(ctx, rev0.SwitchAt, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	s.SetClock(func() time.Time { return rev0.SwitchAt })
	rev, err := s.RevokeDeviceOverlap(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.RevokeDevice(ctx, a.ID)
	if err != nil || !again.Already || !again.Until.Equal(rev.Until) {
		t.Errorf("repeat: until %v, the revocation's %v (%v)", again.Until, rev.Until, err)
	}
}
