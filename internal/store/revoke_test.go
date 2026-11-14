package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// creds reads a user's credentials: service to the row's secrets and
// times as stored.
func creds(t *testing.T, s *Store, user int64) map[int64][5]string {
	t.Helper()
	rows, err := s.db.Query(`SELECT service_id, secret, coalesce(next_secret, ''), coalesce(prev_secret, ''),
		coalesce(next_from, 0), coalesce(rotated_at, 0) FROM credentials WHERE user_id = ?`, user)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int64][5]string{}
	for rows.Next() {
		var svc int64
		var c [5]string
		var from, rotated int64
		if err := rows.Scan(&svc, &c[0], &c[1], &c[2], &from, &rotated); err != nil {
			t.Fatal(err)
		}
		c[3], c[4] = time.Unix(from, 0).String(), time.Unix(rotated, 0).String()
		if from == 0 {
			c[3] = ""
		}
		out[svc] = c
	}
	return out
}

// A revocation gives every credential of the device's user a new secret,
// with no next and no previous one, in the same transaction; nobody
// else's changes, a repeat changes nothing, and the name is free again
// (R4-36).
func TestRevokeRenewsCredentials(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var svcs []int64
	for _, k := range []string{"reality", "inner", "naive"} {
		svc, err := s.CreateService(ctx, Service{Kind: k, Name: k, Enabled: true, Settings: "{}"})
		if err != nil {
			t.Fatal(err)
		}
		svcs = append(svcs, svc.ID)
	}
	alice, _ := s.CreateUser(ctx, User{Name: "alice", Enabled: true, Services: svcs})
	bob, _ := s.CreateUser(ctx, User{Name: "bob", Enabled: true, Services: svcs})
	carol, _ := s.CreateUser(ctx, User{Name: "carol", Enabled: true})
	for _, svc := range svcs {
		if _, err := s.Credentials(ctx, svc, []int64{alice.ID, bob.ID}, NewUUID); err != nil {
			t.Fatal(err)
		}
	}
	// A rotation in flight on alice's: a next published, then a previous
	// in its grace on one of them.
	start := time.Now()
	r := Rotation{Period: 30 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Grace: 2 * 24 * time.Hour}
	if _, err := s.RotateCredentials(ctx, start.Add(28*24*time.Hour), r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE credentials SET prev_secret = 'old', prev_until = ? WHERE user_id = ? AND service_id = ?`,
		start.Add(time.Hour).Unix(), alice.ID, svcs[0]); err != nil {
		t.Fatal(err)
	}
	before, bobBefore := creds(t, s, alice.ID), creds(t, s, bob.ID)
	if len(before) != 3 || before[svcs[1]][1] == "" {
		t.Fatalf("before: %v", before)
	}
	phone, _, _ := s.CreateDevice(ctx, "alice", "phone", "user")
	laptop, _, _ := s.CreateDevice(ctx, "alice", "laptop", "admin")
	lone, _, _ := s.CreateDevice(ctx, "carol", "phone", "user")

	later := start.Add(time.Minute).Truncate(time.Second)
	s.SetClock(func() time.Time { return later })
	rev, err := s.RevokeDevice(ctx, phone.ID)
	if err != nil || rev != (Revocation{User: "alice", Device: "phone", Credentials: 3}) {
		t.Fatalf("revoke: %+v %v", rev, err)
	}
	after := creds(t, s, alice.ID)
	for svc, c := range after {
		old := before[svc]
		if c[0] == old[0] || c[0] == old[1] || c[0] == old[2] || !isUUID(c[0]) {
			t.Errorf("service %d: the new secret %q is one the device knew (%v)", svc, c[0], old)
		}
		if c[1] != "" || c[2] != "" || c[3] != "" {
			t.Errorf("service %d: a next or previous secret stays: %v", svc, c)
		}
		if c[4] != later.String() {
			t.Errorf("service %d: rotated at %s, not at the revocation", svc, c[4])
		}
	}
	if after[svcs[0]][0] == after[svcs[1]][0] {
		t.Error("two services got the same secret")
	}
	if got := creds(t, s, bob.ID); len(got) != 3 || got[svcs[0]] != bobBefore[svcs[0]] || got[svcs[2]] != bobBefore[svcs[2]] {
		t.Errorf("bob's credentials changed: %v, were %v", got, bobBefore)
	}
	// What a server takes now: the new secrets only.
	sets, err := s.CredentialSets(ctx, svcs[0], nil, nil)
	if err != nil || len(sets[alice.ID].Accepted(later)) != 1 || sets[alice.ID].Accepted(later)[0] != after[svcs[0]][0] {
		t.Fatalf("accepted: %v %v", sets[alice.ID].Accepted(later), err)
	}

	// A repeat: done already, nothing changes, not the credentials again.
	again, err := s.RevokeDevice(ctx, phone.ID)
	if err != nil || again != (Revocation{User: "alice", Device: "phone", Already: true}) {
		t.Fatalf("repeat: %+v %v", again, err)
	}
	if got := creds(t, s, alice.ID); got[svcs[0]] != after[svcs[0]] || got[svcs[2]] != after[svcs[2]] {
		t.Fatal("a repeated revoke changed the credentials")
	}
	if _, err := s.RevokeDevice(ctx, "0000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown device: %v", err)
	}
	// An admin device the same; and a user with no credentials yet: none.
	if rev, err := s.RevokeDevice(ctx, laptop.ID); err != nil || rev.Credentials != 3 || creds(t, s, alice.ID)[svcs[1]] == after[svcs[1]] {
		t.Fatalf("the admin device: %+v %v", rev, err)
	}
	if rev, err := s.RevokeDevice(ctx, lone.ID); err != nil || rev.Credentials != 0 || len(creds(t, s, carol.ID)) != 0 {
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

func isUUID(s string) bool {
	return len(s) == 36 && s[14] == '4' && strings.Count(s, "-") == 4
}

// rayctl restore: the devices revoked in the current database since the
// backup stay revoked in it, and their users get new credentials there,
// not those of the backup (which the revoked device knew); the rest of the
// backup stays as it was, a user disabled since included.
func TestCarryDeviceRevocations(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	current, saved := filepath.Join(dir, "rayd.db"), filepath.Join(dir, "backup.db")
	s, err := Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := s.CreateService(ctx, Service{Kind: "reality", Name: "reality", Enabled: true, Settings: "{}"})
	alice, _ := s.CreateUser(ctx, User{Name: "alice", Enabled: true, Services: []int64{svc.ID}})
	bob, _ := s.CreateUser(ctx, User{Name: "bob", Enabled: true, Services: []int64{svc.ID}})
	if _, err := s.Credentials(ctx, svc.ID, []int64{alice.ID, bob.ID}, NewUUID); err != nil {
		t.Fatal(err)
	}
	phone, _, _ := s.CreateDevice(ctx, "alice", "phone", "user")
	tablet, _, _ := s.CreateDevice(ctx, "alice", "tablet", "user")
	bobPhone, _, _ := s.CreateDevice(ctx, "bob", "phone", "user")
	backup := creds(t, s, alice.ID)[svc.ID][0]
	bobs := creds(t, s, bob.ID)[svc.ID][0]
	s.Close()
	copyFile(t, current, saved)

	s, err = Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeDevice(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	must(t, s.SetUserEnabled(ctx, "bob", false))
	s.Close()

	carried, unknown, err := CarryDeviceRevocations(ctx, saved, current)
	if err != nil || len(unknown) != 0 || len(carried) != 1 || carried[0] != (CarriedDevice{ID: phone.ID, User: "alice", Name: "phone"}) {
		t.Fatalf("carried %+v %v", carried, err)
	}
	s, err = Open(ctx, saved)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	devs, _ := s.ListDevices(ctx, "")
	for _, d := range devs {
		if (d.RevokedAt != nil) != (d.ID == phone.ID) {
			t.Errorf("device %s/%s revoked %v", d.UserName, d.Name, d.RevokedAt)
		}
	}
	if got := creds(t, s, alice.ID)[svc.ID][0]; got == backup || !isUUID(got) {
		t.Errorf("alice's credential is the backup's: %s", got)
	}
	if got := creds(t, s, bob.ID)[svc.ID][0]; got != bobs {
		t.Error("bob's credential changed")
	}
	if u, _ := s.UserByName(ctx, "bob"); !u.Enabled {
		t.Error("restore carried more than the devices: bob disabled")
	}
	// Another node's database (a new host): it knows none of the backup's
	// devices, and a device it does not know is not taken for revoked.
	other := filepath.Join(dir, "other.db")
	o, err := Open(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	o.Close()
	fresh := filepath.Join(dir, "fresh.db")
	s.Close()
	copyFile(t, saved, fresh)
	if carried, unknown, err := CarryDeviceRevocations(ctx, fresh, other); err != nil || len(carried) != 0 || len(unknown) != 2 {
		t.Fatalf("against another node: %+v %+v %v", carried, unknown, err)
	}
	f, err := Open(ctx, fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, id := range []string{tablet.ID, bobPhone.ID} {
		if _, _, err := f.ActiveDevice(ctx, id); err != nil {
			t.Errorf("device %s revoked against another node: %v", id, err)
		}
	}
}

// A rollback's carry (CarryRevocations) renews the credentials of the
// users of devices revoked since the copy too.
func TestCarryRevocationsRenewsCredentials(t *testing.T) {
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
	s, _ = Open(ctx, current)
	if _, err := s.RevokeDevice(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	must(t, CarryRevocations(ctx, saved, current))
	s, _ = Open(ctx, saved)
	defer s.Close()
	if got := creds(t, s, alice.ID)[svc.ID][0]; got == old {
		t.Fatal("the rollback brings back the credential the revoked device knew")
	}
	if _, _, err := s.ActiveDevice(ctx, phone.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the phone is back: %v", err)
	}
}
