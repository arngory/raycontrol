package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Regression tests from the review of R4-43.

// A revocation without overlap renews the user's credentials in its own
// second: it is no start of a chain for a later revocation with overlap,
// which gets a full lead (review S1).
func TestRevokeOverlapAfterPlainHasLead(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	s, svcs, _ := revokeNode(t, r)
	stolen, _, _ := s.CreateDevice(ctx, "alice", "stolen", "user")
	old, _, _ := s.CreateDevice(ctx, "alice", "old", "user")
	t0 := time.Now().Truncate(time.Second)
	s.SetClock(func() time.Time { return t0 })
	if _, err := s.RevokeDevice(ctx, stolen.ID); err != nil {
		t.Fatal(err)
	}
	// A week later (no scheduled next yet: a 30-day period), a planned
	// replacement with overlap.
	t1 := t0.Add(7 * 24 * time.Hour)
	s.SetClock(func() time.Time { return t1 })
	rev, err := s.RevokeDeviceOverlap(ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if c := credRowsOf(t, s.db)["alice"][svcs[0]]; !rev.SwitchAt.Equal(t1.Add(r.Lead)) || c.NextFrom != t1.Add(r.Lead).Unix() {
		t.Errorf("switch at %v after the revocation, want a full lead (%v)", rev.SwitchAt.Sub(t1), r.Lead)
	}
}

// After a revocation without overlap the schedule publishes a next; a
// revocation with overlap replaces it, never with an earlier switch
// (subscription-v1 §3: "from the same or later"; review S1).
func TestRevokeOverlapNotEarlierThanScheduled(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	s, svcs, _ := revokeNode(t, r)
	stolen, _, _ := s.CreateDevice(ctx, "alice", "stolen", "user")
	old, _, _ := s.CreateDevice(ctx, "alice", "old", "user")
	t0 := time.Now().Truncate(time.Second)
	s.SetClock(func() time.Time { return t0 })
	if _, err := s.RevokeDevice(ctx, stolen.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateCredentials(ctx, t0.Add(r.Period-r.Lead), r, NewUUID); err != nil {
		t.Fatal(err)
	}
	sched := credRowsOf(t, s.db)["alice"][svcs[0]]
	t1 := t0.Add(28 * 24 * time.Hour)
	s.SetClock(func() time.Time { return t1 })
	if _, err := s.RevokeDeviceOverlap(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	if c := credRowsOf(t, s.db)["alice"][svcs[0]]; sched.Next == "" || c.Next == sched.Next || c.NextFrom < sched.NextFrom {
		t.Errorf("the switch with overlap at t0+%v, the scheduled one it replaced at t0+%v",
			time.Unix(c.NextFrom, 0).Sub(t0), time.Unix(sched.NextFrom, 0).Sub(t0))
	}
}

// A rollback to a copy older than the LAN (schema 12, no users.lan_key)
// with a device made since the copy: its user gets new credentials, and no
// LAN key is written where there is no column (review S2).
func TestCarryRevocationsPreLANCopyAddedDevice(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	saved, current := filepath.Join(dir, "saved.db"), filepath.Join(dir, "current.db")
	schemaAt(t, saved, 12,
		`INSERT INTO users (id, name, enabled, created_at) VALUES (1, 'alice', 1, 1)`,
		`INSERT INTO services (id, kind, name, enabled, settings_json, created_at) VALUES (1, 'naive', 'naive', 1, '{}', 1)`,
		`INSERT INTO user_services (user_id, service_id) VALUES (1, 1)`,
		`INSERT INTO credentials (user_id, service_id, secret, created_at) VALUES (1, 1, 'a1', 1)`,
		`INSERT INTO devices (id, user_id, name, role, spa_key, created_at) VALUES ('0123456789abcdef', 1, 'phone', 'user', x'00', 1)`)
	copyFile(t, saved, current)
	s, err := Open(ctx, current) // migrated to the newest, as the update's rayd does
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateDevice(ctx, "alice", "laptop", "user"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := CarryRevocations(ctx, saved, current); err != nil {
		t.Fatalf("rollback to a schema-12 copy with a device added since: %v", err)
	}
	if got := secrets(t, saved)["alice"][1]; got == "a1" || !isUUID(got) {
		t.Errorf("alice's credential after the rollback: %s", got)
	}
}

// A restore drops a device made since the backup and revoked with overlap:
// its user gets new credentials, so what it knew is not accepted at all,
// and no later chain in the restored database forgets it (review S3).
func TestCarryRestoreAddedOverlapNoChainLost(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil)
	r := DefaultRotation
	s := f.open(t, f.current)
	must(t, s.SetRotation(ctx, r))
	tablet, _, _ := s.CreateDevice(ctx, "alice", "tablet", "user") // made since the backup
	t1 := time.Now().Truncate(time.Second).Add(time.Minute)
	s.SetClock(func() time.Time { return t1 })
	if _, err := s.RevokeDeviceOverlap(ctx, tablet.ID); err != nil {
		t.Fatal(err)
	}
	known := credRowsOf(t, s.db)["alice"][f.naive]
	s.Close()
	res, err := CarryRestore(ctx, f.backup, f.current, "")
	if err != nil || len(res.Added) != 1 || res.Added[0].Rotating {
		t.Fatalf("%+v %v", res, err)
	}
	b := f.open(t, f.backup)
	defer b.Close()
	sets, err := b.CredentialSets(ctx, f.naive, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, sec := range sets[f.ids["alice"]].Accepted(t1.Add(time.Hour)) {
		if sec == known.Secret || sec == known.Next {
			t.Fatalf("a secret the tablet knew is accepted after the restore: %+v", sets[f.ids["alice"]])
		}
	}
}

// A device in the backup revoked with overlap on the node (its rotation in
// flight, carried as is) and another of the user's made since and active:
// the restore renews the user, and says so, not that the rotation goes on
// (review N1).
func TestCarryRestoreRotatingButRenewed(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil)
	s := f.open(t, f.current)
	if _, _, err := s.CreateDevice(ctx, "alice", "laptop", "user"); err != nil { // made since, active
		t.Fatal(err)
	}
	// Not in the credentials' second: the phone revoked after they became
	// current, as on a node.
	s.SetClock(func() time.Time { return time.Now().Add(time.Minute) })
	if _, err := s.RevokeDeviceOverlap(ctx, f.phones["alice"].ID); err != nil {
		t.Fatal(err)
	}
	now := credRowsAt(t, f.current)
	s.Close()
	r, err := CarryRestore(ctx, f.backup, f.current, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := credRowsAt(t, f.backup)["alice"][f.naive]; got.Secret == now["alice"][f.naive].Secret || got.Next != "" {
		t.Fatalf("alice not renewed: %+v", got)
	}
	if len(r.Carried) != 1 || r.Carried[0].Rotating {
		t.Errorf("alice renewed, yet her carried phone is Rotating: %+v", r.Carried)
	}
	a := auditOf(t, f.backup)
	if hasAudit(a, "device.revoke:restore", f.phones["alice"].ID+" alice/phone: revoked on the node since the copy, with overlap") ||
		!hasAudit(a, "user.renew:restore", "alice: 2 credentials new, a device added here since the backup, not in it") {
		t.Errorf("audit %+v", a)
	}
}

// A rollback with a revocation with overlap since the copy, its rotation in
// flight: the rayd it goes back to may run no rotation loop (-cred-period
// 0 before v0.31.0), so the rollback gives new credentials, and, no
// RotateCredentials ever called, nothing the revoked phone knew is
// accepted (review B1).
func TestCarryRevocationsPeriodZero(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	current, saved := filepath.Join(dir, "rayd.db"), filepath.Join(dir, "saved.db")
	s, err := Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	must(t, s.SetRotation(ctx, Rotation{Period: 0, Lead: DefaultRotation.Lead, Grace: DefaultRotation.Grace}))
	svc, _ := s.CreateService(ctx, Service{Kind: "naive", Name: "naive", Enabled: true, Settings: "{}"})
	alice, _ := s.CreateUser(ctx, User{Name: "alice", Enabled: true, Services: []int64{svc.ID}})
	if _, err := s.Credentials(ctx, svc.ID, []int64{alice.ID}, NewUUID); err != nil {
		t.Fatal(err)
	}
	phone, _, _ := s.CreateDevice(ctx, "alice", "phone", "user")
	known := creds(t, s, alice.ID)[svc.ID][0]
	s.Close()
	copyFile(t, current, saved) // the update's copy
	s, _ = Open(ctx, current)
	if _, err := s.RevokeDeviceOverlap(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	must(t, CarryRevocations(ctx, saved, current))
	b, _ := Open(ctx, saved)
	defer b.Close()
	sets, err := b.CredentialSets(ctx, svc.ID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{time.Now(), time.Now().Add(365 * 24 * time.Hour)} {
		for _, sec := range sets[alice.ID].Accepted(at) {
			if sec == known {
				t.Fatalf("the secret the revoked phone knew is accepted after the rollback: %+v", sets[alice.ID])
			}
		}
	}
}

// A user whose revocation since the copy the rollback renews, with a device
// made since the copy too: renewed once, by the revocation's carry; the
// added device's renewal does not run again (review N4).
func TestCarryRevocationsRenewOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	current, saved := filepath.Join(dir, "rayd.db"), filepath.Join(dir, "saved.db")
	s, err := Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := s.CreateService(ctx, Service{Kind: "naive", Name: "naive", Enabled: true, Settings: "{}"})
	bob, _ := s.CreateUser(ctx, User{Name: "bob", Enabled: true, Services: []int64{svc.ID}})
	if _, err := s.Credentials(ctx, svc.ID, []int64{bob.ID}, NewUUID); err != nil {
		t.Fatal(err)
	}
	phone, _, _ := s.CreateDevice(ctx, "bob", "phone", "user")
	s.Close()
	copyFile(t, current, saved)
	s, _ = Open(ctx, current)
	if _, err := s.RevokeDevice(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateDevice(ctx, "bob", "tablet", "user"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	must(t, CarryRevocations(ctx, saved, current))
	var lines []string
	for _, e := range auditOf(t, saved) {
		if e.Action == "user.renew:rollback" {
			lines = append(lines, e.Target)
		}
	}
	if len(lines) != 1 || lines[0] != "bob: 1 credentials new, a device of the user revoked on the node since the copy" {
		t.Errorf("renewals %q", lines)
	}
}

// A revocation with overlap on the node whose rotation has switched, and a
// scheduled next published since: no longer the rotation that revocation
// began, so a restore gives the user new credentials, as for one without
// overlap (overlapInFlight; the mutation run's M7).
func TestCarryRestoreOverlapSwitchedRenews(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil)
	r := DefaultRotation
	s := f.open(t, f.current)
	must(t, s.SetRotation(ctx, r))
	t1 := time.Now().Truncate(time.Second).Add(time.Minute)
	s.SetClock(func() time.Time { return t1 })
	rev, err := s.RevokeDeviceOverlap(ctx, f.phones["alice"].ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateCredentials(ctx, rev.SwitchAt, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateCredentials(ctx, rev.SwitchAt.Add(r.Period-r.Lead), r, NewUUID); err != nil {
		t.Fatal(err)
	}
	now := credRowsOf(t, s.db)["alice"][f.naive]
	if now.Next == "" || now.Rotated != rev.SwitchAt.Unix() {
		t.Fatalf("no scheduled next after the switch: %+v", now)
	}
	s.Close()
	res, err := CarryRestore(ctx, f.backup, f.current, "")
	if err != nil || len(res.Carried) != 1 || res.Carried[0].Rotating {
		t.Fatalf("%+v %v", res, err)
	}
	if got := credRowsAt(t, f.backup)["alice"][f.naive]; got.Secret == now.Secret || got.Next != "" {
		t.Errorf("alice: %+v, the node's %+v", got, now)
	}
}
