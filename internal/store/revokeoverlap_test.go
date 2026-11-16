package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// credRow is a credential's row as stored, its times in Unix seconds.
type credRow struct {
	Secret, Next, Prev           string
	NextFrom, PrevUntil, Rotated int64
}

// credRowsAt reads every credential of the database at path: user name to
// service to row.
func credRowsAt(t *testing.T, path string) map[string]map[int64]credRow {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	return credRowsOf(t, db)
}

func credRowsOf(t *testing.T, db *sql.DB) map[string]map[int64]credRow {
	t.Helper()
	rows, err := db.Query(`SELECT u.name, c.service_id, c.secret, coalesce(c.next_secret, ''), coalesce(c.prev_secret, ''),
		coalesce(c.next_from, 0), coalesce(c.prev_until, 0), coalesce(c.rotated_at, 0) FROM credentials c JOIN users u ON u.id = c.user_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]map[int64]credRow{}
	for rows.Next() {
		var name string
		var svc int64
		var c credRow
		if err := rows.Scan(&name, &svc, &c.Secret, &c.Next, &c.Prev, &c.NextFrom, &c.PrevUntil, &c.Rotated); err != nil {
			t.Fatal(err)
		}
		if out[name] == nil {
			out[name] = map[int64]credRow{}
		}
		out[name][svc] = c
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// revokeNode is a node with REALITY, inner, naive and DoH, alice and bob
// on all of them with their credentials, carol on none, and the schedule
// stored as rayd stores it.
func revokeNode(t *testing.T, r Rotation) (*Store, []int64, map[string]User) {
	t.Helper()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	must(t, s.SetRotation(ctx, r))
	var svcs []int64
	for _, k := range []string{"reality", "inner", "naive", "doh"} {
		svc, err := s.CreateService(ctx, Service{Kind: k, Name: k, Enabled: true, Settings: "{}"})
		if err != nil {
			t.Fatal(err)
		}
		svcs = append(svcs, svc.ID)
	}
	users := map[string]User{}
	for _, n := range []string{"alice", "bob"} {
		u, err := s.CreateUser(ctx, User{Name: n, Enabled: true, Services: svcs})
		if err != nil {
			t.Fatal(err)
		}
		users[n] = u
	}
	carol, err := s.CreateUser(ctx, User{Name: "carol", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	users["carol"] = carol
	for _, svc := range svcs {
		if _, err := s.Credentials(ctx, svc, []int64{users["alice"].ID, users["bob"].ID}, NewUUID); err != nil {
			t.Fatal(err)
		}
	}
	return s, svcs, users
}

// A revocation with overlap (R4-43) starts a rotation of every credential
// of the device's user but DoH's, in the same transaction, with the
// overlap of the scheduled one: a fresh next secret, accepted at once, its
// switch a lead away; the current secret and a previous one in its grace
// stay. The LAN key is new at once, as without overlap (lan-v1 §3).
// Nobody else's changes, a repeat changes nothing, and the name is free
// again.
func TestRevokeOverlapRotatesCredentials(t *testing.T) {
	ctx := context.Background()
	r := Rotation{Period: 30 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Grace: 2 * 24 * time.Hour}
	s, svcs, users := revokeNode(t, r)
	reality, naive, doh := svcs[0], svcs[2], svcs[3]
	alice := users["alice"]
	start := time.Now().Truncate(time.Second)
	// A previous secret in its grace on alice's REALITY, and LAN keys.
	if _, err := s.db.Exec(`UPDATE credentials SET prev_secret = 'old', prev_until = ? WHERE user_id = ? AND service_id = ?`,
		start.Add(time.Hour).Unix(), alice.ID, reality); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE users SET lan = 1, lan_key = randomblob(?)`, LANKeySize); err != nil {
		t.Fatal(err)
	}
	aliceKey, bobKey := s.lanKey(t, "alice"), s.lanKey(t, "bob")
	phone, _, _ := s.CreateDevice(ctx, "alice", "phone", "user")
	laptop, _, _ := s.CreateDevice(ctx, "alice", "laptop", "admin")
	lone, _, _ := s.CreateDevice(ctx, "carol", "phone", "user")
	before := credRowsOf(t, s.db)

	later := start.Add(time.Minute)
	s.SetClock(func() time.Time { return later })
	rev, err := s.RevokeDeviceOverlap(ctx, phone.ID)
	want := Revocation{User: "alice", Device: "phone", Credentials: 3, Overlap: true, SwitchAt: later.Add(r.Lead), Until: later.Add(r.Lead + r.Grace)}
	if err != nil || rev != want {
		t.Fatalf("revoke: %+v %v, want %+v", rev, err, want)
	}
	after := credRowsOf(t, s.db)
	for svc, c := range after["alice"] {
		old := before["alice"][svc]
		if svc == doh {
			if c != old {
				t.Errorf("DoH's secret rotates: %+v, was %+v", c, old)
			}
			continue
		}
		if c.Secret != old.Secret || c.Prev != old.Prev || c.PrevUntil != old.PrevUntil || c.Rotated != old.Rotated {
			t.Errorf("service %d: the current or the previous secret changed: %+v, was %+v", svc, c, old)
		}
		if !isUUID(c.Next) || c.Next == old.Secret || c.Next == old.Prev {
			t.Errorf("service %d: the next secret %q is none or one the device knew (%+v)", svc, c.Next, old)
		}
		if c.NextFrom != later.Add(r.Lead).Unix() {
			t.Errorf("service %d: the switch at %v, not a lead after the revocation", svc, time.Unix(c.NextFrom, 0))
		}
	}
	if after["alice"][reality].Next == after["alice"][naive].Next {
		t.Error("two services got the same next secret")
	}
	if after["bob"] == nil || len(after["bob"]) != 4 {
		t.Fatalf("bob: %+v", after["bob"])
	}
	for svc, c := range after["bob"] {
		if c != before["bob"][svc] {
			t.Errorf("bob's credential on %d changed: %+v", svc, c)
		}
	}
	// What a server takes now: the current secret, the next one and the
	// previous one in its grace.
	sets, err := s.CredentialSets(ctx, reality, nil, nil)
	if got := sets[alice.ID].Accepted(later); err != nil || len(got) != 3 || got[0] != before["alice"][reality].Secret ||
		got[1] != after["alice"][reality].Next || got[2] != "old" {
		t.Fatalf("accepted: %v %v", got, err)
	}
	// The LAN key: alice's new, bob's as it was.
	if k := s.lanKey(t, "alice"); len(k) != LANKeySize || string(k) == string(aliceKey) || string(s.lanKey(t, "bob")) != string(bobKey) {
		t.Error("the LAN keys after the revocation")
	}

	// A repeat: done already, nothing changes, not the credentials again;
	// with or without overlap it says until when what the device knew is
	// still accepted.
	for _, revoke := range []func(context.Context, string) (Revocation, error){s.RevokeDeviceOverlap, s.RevokeDevice} {
		again, err := revoke(ctx, phone.ID)
		if err != nil || again != (Revocation{User: "alice", Device: "phone", Already: true, Until: want.Until}) {
			t.Fatalf("repeat: %+v %v", again, err)
		}
	}
	if got := credRowsOf(t, s.db)["alice"]; got[reality] != after["alice"][reality] || got[naive] != after["alice"][naive] {
		t.Fatal("a repeated revoke changed the credentials")
	}
	if _, err := s.RevokeDeviceOverlap(ctx, "0000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown device: %v", err)
	}
	// The last device of the user (an admin one): its credentials rotate
	// as well, the next one replaced; a user with no credentials yet: none.
	if rev, err := s.RevokeDeviceOverlap(ctx, laptop.ID); err != nil || rev.Credentials != 3 ||
		credRowsOf(t, s.db)["alice"][naive].Next == after["alice"][naive].Next {
		t.Fatalf("the admin device: %+v %v", rev, err)
	}
	if rev, err := s.RevokeDeviceOverlap(ctx, lone.ID); err != nil || rev.Credentials != 0 || !rev.SwitchAt.IsZero() || !rev.Until.IsZero() ||
		len(credRowsOf(t, s.db)["carol"]) != 0 {
		t.Fatalf("a user without credentials: %+v %v", rev, err)
	}

	// The revoked names are free; two active devices still cannot share one.
	if _, _, err := s.CreateDevice(ctx, "alice", "phone", "user"); err != nil {
		t.Fatalf("a new device with a revoked one's name: %v", err)
	}
	if _, _, err := s.CreateDevice(ctx, "alice", "phone", "user"); err == nil || !strings.Contains(err.Error(), "UNIQUE") {
		t.Fatalf("two active devices of one name: %v", err)
	}
	if _, _, err := s.CreateInvite(ctx, "alice", "laptop", "user", time.Hour); err != nil {
		t.Fatalf("an invite for a revoked device's name: %v", err)
	}
	if _, _, err := s.CreateInvite(ctx, "alice", "phone", "user", time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an invite for an active device's name: %v", err)
	}
	devs, err := s.ListDevices(ctx, "alice")
	if err != nil || len(devs) != 3 {
		t.Fatalf("devices: %+v %v", devs, err)
	}
}

// A rotation in flight when a device is revoked with overlap: the next
// secret the schedule published, which the device may have fetched, is
// replaced by a fresh one, and the lead starts again from the revocation.
func TestRevokeOverlapReplacesNextInFlight(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	s, svcs, users := revokeNode(t, r)
	start := time.Now().Truncate(time.Second)
	if n, err := s.RotateCredentials(ctx, start.Add(r.Period-r.Lead), r, NewUUID); err != nil || n != 8 {
		t.Fatalf("scheduled: %d %v", n, err)
	}
	scheduled := credRowsOf(t, s.db)
	phone, _, _ := s.CreateDevice(ctx, "alice", "phone", "user")
	at := start.Add(r.Period - r.Lead/2) // the schedule's switch is half a lead away
	s.SetClock(func() time.Time { return at })
	if _, err := s.RevokeDeviceOverlap(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	got := credRowsOf(t, s.db)
	for _, svc := range svcs {
		old, c := scheduled["alice"][svc], got["alice"][svc]
		if svc == svcs[3] {
			if c != old {
				t.Errorf("DoH's rotation changed: %+v, was %+v", c, old)
			}
			continue
		}
		if old.Next == "" || c.Next == old.Next || c.Next == old.Secret || !isUUID(c.Next) {
			t.Errorf("service %d: the next secret in flight %q stays or comes back: %q", svc, old.Next, c.Next)
		}
		if c.Secret != old.Secret || c.NextFrom != at.Add(r.Lead).Unix() || c.NextFrom <= old.NextFrom {
			t.Errorf("service %d: %+v, was %+v: the lead does not restart at the revocation", svc, c, old)
		}
		// The schedule's next secret is no longer accepted.
		sets, err := s.CredentialSets(ctx, svc, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, sec := range sets[users["alice"].ID].Accepted(at) {
			if sec == old.Next {
				t.Errorf("service %d: the replaced next secret is still accepted", svc)
			}
		}
	}
	for svc, c := range got["bob"] {
		if c != scheduled["bob"][svc] {
			t.Errorf("bob's rotation on %d changed: %+v", svc, c)
		}
	}
}

// Revocations with overlap in a row: each replaces the next secret, the
// one before it published included, and restarts the lead, but the switch
// never comes later than two leads after the first revocation the current
// secret outlived (RevocationChain). After the switch a revocation starts
// a new chain. One past the bound, before rayd's loop switched, switches
// at once.
func TestRevokeOverlapChain(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	s, svcs, users := revokeNode(t, r)
	reality := svcs[0]
	alice := users["alice"].ID
	// A minute after the credentials were made: a revocation in their own
	// second would not count for the chain (it is no later than
	// rotated_at), as a renewal's does not.
	t0 := time.Now().Truncate(time.Second).Add(time.Minute)
	var devs []Device
	for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
		d, _, err := s.CreateDevice(ctx, "alice", n, "user")
		if err != nil {
			t.Fatal(err)
		}
		devs = append(devs, d)
	}
	current := credRowsOf(t, s.db)["alice"][reality].Secret
	seen := map[string]bool{current: true}
	revoke := func(d Device, at time.Time, wantFrom time.Time) credRow {
		t.Helper()
		s.SetClock(func() time.Time { return at })
		rev, err := s.RevokeDeviceOverlap(ctx, d.ID)
		if err != nil || !rev.SwitchAt.Equal(wantFrom) || !rev.Until.Equal(wantFrom.Add(r.Grace)) {
			t.Fatalf("revoke %s at %v: %+v %v, want the switch at %v", d.Name, at.Sub(t0), rev, err, wantFrom.Sub(t0))
		}
		c := credRowsOf(t, s.db)["alice"][reality]
		if seen[c.Next] || c.NextFrom != wantFrom.Unix() || c.Secret != current {
			t.Fatalf("revoke %s: %+v (a next seen before, or the switch not at %v)", d.Name, c, wantFrom.Sub(t0))
		}
		seen[c.Next] = true
		return c
	}
	day := 24 * time.Hour
	revoke(devs[0], t0, t0.Add(r.Lead))                            // the first: a lead
	revoke(devs[1], t0.Add(2*day), t0.Add(2*day+r.Lead))           // within the lead: it restarts
	revoke(devs[2], t0.Add(4*day), t0.Add(2*r.Lead))               // the bound: two leads after the first
	last := revoke(devs[3], t0.Add(5*day+day/2), t0.Add(2*r.Lead)) // still the bound: less notice

	// The switch at the bound: the last next secret current, the one the
	// first revoked device knew previous for the grace, then gone.
	sw := t0.Add(2 * r.Lead)
	if n, err := s.RotateCredentials(ctx, sw.Add(-time.Second), r, NewUUID); err != nil || n != 0 {
		t.Fatalf("before the switch: %d %v", n, err)
	}
	if _, err := s.RotateCredentials(ctx, sw, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	c := credRowsOf(t, s.db)["alice"][reality]
	if c.Secret != last.Next || c.Prev != current || c.PrevUntil != sw.Add(r.Grace).Unix() || c.Rotated != sw.Unix() || c.Next != "" {
		t.Fatalf("after the switch: %+v", c)
	}
	sets, _ := s.CredentialSets(ctx, reality, nil, nil)
	if got := sets[alice].Accepted(sw.Add(r.Grace - time.Second)); len(got) != 2 || got[1] != current {
		t.Fatalf("in the grace: %v", got)
	}
	if _, err := s.RotateCredentials(ctx, sw.Add(r.Grace), r, NewUUID); err != nil {
		t.Fatal(err)
	}
	sets, _ = s.CredentialSets(ctx, reality, nil, nil)
	if got := sets[alice].Accepted(sw.Add(r.Grace)); len(got) != 1 || got[0] != last.Next {
		t.Fatalf("after the grace: %v", got)
	}

	// A new chain: the revocations before the switch do not count.
	current = last.Next
	seen[current] = true
	at := sw.Add(r.Grace + day)
	c = revoke(devs[4], at, at.Add(r.Lead))
	// Past its bound, rayd's loop not yet round: the switch is due at once.
	late := at.Add(2*r.Lead + time.Minute)
	revoke(devs[5], late, late)
	if _, err := s.RotateCredentials(ctx, late, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if got := credRowsOf(t, s.db)["alice"][reality]; got.Prev != current || got.Secret == c.Next || !seen[got.Secret] {
		t.Fatalf("the late switch: %+v", got)
	}
}

// The schedule rayd stores is the one a revocation with overlap goes by:
// its lead for the switch, its grace for what the response says; with no
// period (rayd -cred-period 0) rayd's loop switches what a revocation
// published and drops it after the grace, and publishes nothing by
// itself.
func TestRevokeOverlapStoredRotation(t *testing.T) {
	ctx := context.Background()
	r := Rotation{Lead: 5 * time.Minute, Grace: 12 * time.Hour}
	s, svcs, _ := revokeNode(t, r)
	if got, err := s.StoredRotation(ctx); err != nil || got != r {
		t.Fatalf("stored: %+v %v", got, err)
	}
	// What rayd set wins over what the database holds, one that does not
	// read included: the loop and a revocation go by the same flags.
	must(t, s.SetSetting(ctx, settingRotation, []byte("{")))
	if got, err := s.StoredRotation(ctx); err != nil || got != r {
		t.Fatalf("set, the stored one unreadable: %+v %v", got, err)
	}
	// Another Store on the database (no SetRotation): what is stored, and
	// rayd's defaults where nothing reads.
	s.rotation.Store(nil)
	if got, err := s.StoredRotation(ctx); err != nil || got != DefaultRotation {
		t.Fatalf("unreadable: %+v %v", got, err)
	}
	must(t, s.SetSetting(ctx, settingRotation, []byte(`{"period":0,"lead":300,"grace":43200}`)))
	if got, err := s.StoredRotation(ctx); err != nil || got != r {
		t.Fatalf("stored: %+v %v", got, err)
	}
	must(t, s.SetRotation(ctx, r))
	phone, _, _ := s.CreateDevice(ctx, "bob", "phone", "user")
	now := time.Now().Truncate(time.Second)
	s.SetClock(func() time.Time { return now })
	rev, err := s.RevokeDeviceOverlap(ctx, phone.ID)
	if err != nil || !rev.SwitchAt.Equal(now.Add(r.Lead)) || !rev.Until.Equal(now.Add(r.Lead+r.Grace)) {
		t.Fatalf("revoke: %+v %v", rev, err)
	}
	old := credRowsOf(t, s.db)["bob"][svcs[0]]
	// Nothing due by itself, a period later even.
	if n, err := s.RotateCredentials(ctx, now.Add(r.Lead-time.Second), r, NewUUID); err != nil || n != 0 {
		t.Fatalf("before the switch: %d %v", n, err)
	}
	if n, err := s.RotateCredentials(ctx, now.Add(r.Lead), r, NewUUID); err != nil || n != 3 {
		t.Fatalf("the switch: %d %v", n, err)
	}
	c := credRowsOf(t, s.db)["bob"][svcs[0]]
	if c.Secret != old.Next || c.Prev != old.Secret || c.PrevUntil != now.Add(r.Lead+r.Grace).Unix() {
		t.Fatalf("after the switch: %+v, was %+v", c, old)
	}
	if n, err := s.RotateCredentials(ctx, now.Add(r.Lead+r.Grace), r, NewUUID); err != nil || n != 3 {
		t.Fatalf("the grace over: %d %v", n, err)
	}
	if n, err := s.RotateCredentials(ctx, now.Add(400*24*time.Hour), r, NewUUID); err != nil || n != 0 {
		t.Fatalf("no period, a year on: %d %v", n, err)
	}
	for name, cs := range credRowsOf(t, s.db) {
		for svc, c := range cs {
			if c.Next != "" || c.Prev != "" {
				t.Errorf("%s on %d: %+v", name, svc, c)
			}
		}
	}
}

// With a period, the next scheduled rotation after the switch of a
// revocation with overlap counts from that switch, as after a scheduled
// one (R4-1).
func TestRevokeOverlapThenSchedule(t *testing.T) {
	ctx := context.Background()
	r := DefaultRotation
	s, svcs, _ := revokeNode(t, r)
	phone, _, _ := s.CreateDevice(ctx, "alice", "phone", "user")
	now := time.Now().Truncate(time.Second)
	s.SetClock(func() time.Time { return now })
	if _, err := s.RevokeDeviceOverlap(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	sw := now.Add(r.Lead)
	if _, err := s.RotateCredentials(ctx, sw, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	due := sw.Add(r.Period - r.Lead)
	if _, err := s.RotateCredentials(ctx, due.Add(-time.Second), r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if c := credRowsOf(t, s.db)["alice"][svcs[0]]; c.Next != "" {
		t.Fatalf("published before its time: %+v", c)
	}
	if _, err := s.RotateCredentials(ctx, due, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if c := credRowsOf(t, s.db)["alice"][svcs[0]]; c.Next == "" || c.NextFrom != sw.Add(r.Period).Unix() {
		t.Fatalf("the scheduled next: %+v", c)
	}
}

// A backup taken while a scheduled next secret was in flight, and a
// device revoked with overlap on the node since, which replaced it: the
// node's database is still a later state of the backup (backupNewer), and
// the restore carries the node's rotation as it is, its next secret, not
// the backup's, which the revoked device may hold, and no new credentials
// that would cut the user's other devices.
func TestCarryRestoreOverlapInFlight(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, func(s *Store) {
		start := time.Now()
		if _, err := s.RotateCredentials(ctx, start.Add(DefaultRotation.Period-DefaultRotation.Lead), DefaultRotation, NewUUID); err != nil {
			t.Fatal(err)
		}
	})
	backup := credRowsAt(t, f.backup)
	s := f.open(t, f.current)
	if _, err := s.RevokeDeviceOverlap(ctx, f.phones["alice"].ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	now := credRowsAt(t, f.current)
	if now["alice"][f.naive].Next == backup["alice"][f.naive].Next || backup["alice"][f.naive].Next == "" {
		t.Fatal("the revocation did not replace the next secret in flight")
	}
	r, err := CarryRestore(ctx, f.backup, f.current, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Foreign || r.Newer != "" || len(r.Carried) != 1 || !r.Carried[0].Rotating || r.Kept != 5 || len(r.New) != 0 {
		t.Fatalf("%+v", r)
	}
	if a := auditOf(t, f.backup); !hasAudit(a, "device.revoke:restore", f.phones["alice"].ID+" alice/phone: revoked on the node since the copy, with overlap: its rotation goes on") ||
		hasAudit(a, "user.renew:restore", "") {
		t.Errorf("audit %+v", a)
	}
	got := credRowsAt(t, f.backup)
	for n, cs := range got {
		for svc, c := range cs {
			if c != now[n][svc] {
				t.Errorf("%s on %d: %+v, the node's %+v", n, svc, c, now[n][svc])
			}
		}
	}
	// Without the revocation, another next at the same current is the
	// backup's being ahead: still a sign.
	g := newRestoreFix(t, func(s *Store) {
		if _, err := s.RotateCredentials(ctx, time.Now().Add(DefaultRotation.Period-DefaultRotation.Lead), DefaultRotation, NewUUID); err != nil {
			t.Fatal(err)
		}
	})
	s = g.open(t, g.current)
	if _, err := s.db.Exec(`UPDATE credentials SET next_secret = '00000000-0000-4000-8000-0000000000aa' WHERE user_id = ?`, g.ids["bob"]); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if r, err := CarryRestore(ctx, g.backup, g.current, ""); err != nil || r.Newer == "" {
		t.Fatalf("another next without a revocation: %+v %v", r, err)
	}
}

// A rollback's carry (CarryRevocations) gives the user of a device revoked
// with overlap since the copy new credentials, its rotation in flight or
// switched: the rayd it goes back to (before v0.31.0) runs no rotation
// loop with -cred-period 0, and the rotation would never switch.
func TestCarryRevocationsOverlapRenews(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	current, saved := filepath.Join(dir, "rayd.db"), filepath.Join(dir, "saved.db")
	s, err := Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := s.CreateService(ctx, Service{Kind: "naive", Name: "naive", Enabled: true, Settings: "{}"})
	alice, _ := s.CreateUser(ctx, User{Name: "alice", Enabled: true, Services: []int64{svc.ID}})
	if _, err := s.Credentials(ctx, svc.ID, []int64{alice.ID}, NewUUID); err != nil {
		t.Fatal(err)
	}
	phone, _, _ := s.CreateDevice(ctx, "alice", "phone", "user")
	old := creds(t, s, alice.ID)[svc.ID][0]
	s.Close()
	copyFile(t, current, saved)
	savedBefore := filepath.Join(dir, "saved-before.db")
	copyFile(t, current, savedBefore)
	s, _ = Open(ctx, current)
	if _, err := s.RevokeDeviceOverlap(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	now := credRowsOf(t, s.db)["alice"][svc.ID]
	s.Close()
	must(t, CarryRevocations(ctx, saved, current))
	s, _ = Open(ctx, saved)
	defer s.Close()
	if got := credRowsOf(t, s.db)["alice"][svc.ID]; got.Secret == old || got.Secret == now.Next || !isUUID(got.Secret) ||
		got.Next != "" || got.Prev != "" {
		t.Fatalf("the rollback's credential %+v, the node's %+v", got, now)
	}
	if _, _, err := s.ActiveDevice(ctx, phone.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the phone is back: %v", err)
	}
	a, err := s.ListAudit(ctx, 100)
	if err != nil || !hasAudit(a, "device.revoke:rollback", phone.ID+" alice/phone: revoked on the node since the copy") ||
		hasAudit(a, "device.revoke:rollback", phone.ID+" alice/phone: revoked on the node since the copy, with overlap") ||
		!hasAudit(a, "user.renew:rollback", "alice: 1 credentials new, a device of the user revoked on the node since the copy") {
		t.Fatalf("audit %+v %v", a, err)
	}
	s.Close()

	// The same after the switch: the rotation is done, and the carry gives
	// new credentials, as for a revocation without overlap.
	c, err := Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RotateCredentials(ctx, time.Unix(now.NextFrom, 0), DefaultRotation, NewUUID); err != nil {
		t.Fatal(err)
	}
	switched := credRowsOf(t, c.db)["alice"][svc.ID]
	c.Close()
	must(t, CarryRevocations(ctx, savedBefore, current))
	s, _ = Open(ctx, savedBefore)
	defer s.Close()
	if got := credRowsOf(t, s.db)["alice"][svc.ID]; got.Secret == switched.Secret || got.Secret == switched.Prev || !isUUID(got.Secret) ||
		got.Next != "" || got.Prev != "" {
		t.Fatalf("after the switch: %+v, the node's %+v", got, switched)
	}
}

// A device made on the node since the copy goes with the rollback, which
// takes it for revoked: its user gets new credentials and a new LAN key at
// once, as a restore gives them (R4-36); the others' stay the node's. One
// revoked with overlap too.
func TestCarryRevocationsAddedRenews(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	current, saved := filepath.Join(dir, "rayd.db"), filepath.Join(dir, "saved.db")
	s, err := Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := s.CreateService(ctx, Service{Kind: "naive", Name: "naive", Enabled: true, Settings: "{}"})
	var ids []int64
	for _, n := range []string{"alice", "bob", "carol"} {
		u, _ := s.CreateUser(ctx, User{Name: n, Enabled: true, Services: []int64{svc.ID}})
		ids = append(ids, u.ID)
	}
	if _, err := s.Credentials(ctx, svc.ID, ids, NewUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE users SET lan = 1, lan_key = randomblob(?)`, LANKeySize); err != nil {
		t.Fatal(err)
	}
	s.Close()
	copyFile(t, current, saved)
	s, _ = Open(ctx, current)
	if _, _, err := s.CreateDevice(ctx, "alice", "phone", "user"); err != nil {
		t.Fatal(err)
	}
	tablet, _, _ := s.CreateDevice(ctx, "carol", "tablet", "user")
	if _, err := s.RevokeDeviceOverlap(ctx, tablet.ID); err != nil {
		t.Fatal(err)
	}
	now := credRowsOf(t, s.db)
	aliceKey := s.lanKey(t, "alice")
	s.Close()
	must(t, CarryRevocations(ctx, saved, current))
	s, _ = Open(ctx, saved)
	defer s.Close()
	got := credRowsOf(t, s.db)
	if c := got["alice"][svc.ID]; c.Secret == now["alice"][svc.ID].Secret || !isUUID(c.Secret) || c.Next != "" || c.Prev != "" {
		t.Fatalf("alice: %+v, the node's %+v", c, now["alice"][svc.ID])
	}
	if k := s.lanKey(t, "alice"); len(k) != LANKeySize || string(k) == string(aliceKey) {
		t.Error("alice's LAN key is the node's")
	}
	if c := got["carol"][svc.ID]; got["bob"][svc.ID] != now["bob"][svc.ID] || c.Secret == now["carol"][svc.ID].Secret || c.Next != "" {
		t.Errorf("bob %+v, carol %+v", got["bob"][svc.ID], got["carol"][svc.ID])
	}
	a, _ := s.ListAudit(ctx, 100)
	if !hasAudit(a, "user.renew:rollback", "alice: 1 credentials new, a device made on the node since the copy, not in it") ||
		!hasAudit(a, "user.renew:rollback", "carol: 1 credentials new, a device made and revoked on the node since the copy") ||
		!hasAudit(a, "user.carry:rollback", "1 users") {
		t.Errorf("audit %+v", a)
	}
}

// A device made since the backup and revoked with overlap on the node: the
// restore drops it, and its user gets new credentials, as for one revoked
// without: the restored database has no record of the device, so a later
// revocation with overlap would not count it in its chain.
func TestCarryRestoreAddedOverlap(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil)
	s := f.open(t, f.current)
	watch, _, _ := s.CreateDevice(ctx, "carol", "watch", "user")
	if _, err := s.RevokeDeviceOverlap(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	now := credRowsAt(t, f.current)
	r, err := CarryRestore(ctx, f.backup, f.current, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Foreign || r.Kept != 4 || len(r.Added) != 1 || r.Added[0].Rotating || !r.Added[0].Revoked ||
		len(r.New) != 1 || r.New[0] != (Renewal{User: "carol", Why: "a device added and revoked here since the backup"}) {
		t.Fatalf("%+v", r)
	}
	got := credRowsAt(t, f.backup)
	if c := got["carol"][f.naive]; c.Secret == now["carol"][f.naive].Secret || c.Next != "" || c.Prev != "" {
		t.Fatalf("carol: %+v, the node's %+v", c, now["carol"][f.naive])
	}
	if !hasAudit(auditOf(t, f.backup), "user.renew:restore", "carol: 2 credentials new, a device added and revoked here since the backup") {
		t.Error("carol not renewed")
	}
}
