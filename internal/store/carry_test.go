package store

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A rollback puts back the database copied before an update. What was
// taken away since stays taken away: revoked and deleted devices, disabled
// and deleted users, an earlier expiry, a withdrawn invite, and the admin
// addresses as they are now.
func TestCarryRevocations(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	saved, current := filepath.Join(dir, "saved.db"), filepath.Join(dir, "current.db")
	s, err := Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	for _, u := range []User{{Name: "alice", Enabled: true, ExpiresAt: &later}, {Name: "bob", Enabled: true}, {Name: "carol", Enabled: true}} {
		if _, err := s.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	d1, _, _ := s.CreateDevice(ctx, "alice", "phone", "user")
	d2, _, _ := s.CreateDevice(ctx, "alice", "laptop", "user")
	d3, _, _ := s.CreateDevice(ctx, "carol", "phone", "admin")
	inv, _, err := s.CreateInvite(ctx, "bob", "tablet", "user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.SetSetting(ctx, "admin_access", []byte(`["198.51.100.7/32","203.0.113.0/24"]`))
	s.Close()
	copyFile(t, current, saved)

	// After the update: taken away, and something new.
	s, err = Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	sooner := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET expires_at = ? WHERE name = 'alice'`, sooner.Unix()); err != nil {
		t.Fatal(err)
	}
	must(t, s.RevokeDevice(ctx, d1.ID))
	must(t, s.SetUserEnabled(ctx, "bob", false))
	must(t, s.DeleteUser(ctx, "carol")) // and with her d3
	must(t, s.DeleteInvite(ctx, inv.ID))
	if _, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, d2.ID); err != nil {
		t.Fatal(err)
	}
	d4, _, _ := s.CreateDevice(ctx, "alice", "watch", "user")
	s.SetSetting(ctx, "admin_access", []byte(`["198.51.100.7/32"]`))
	s.Close()

	if err := CarryRevocations(ctx, saved, current, "admin_access"); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, saved)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	devs := map[string]Device{}
	for _, u := range []string{"alice", "carol"} {
		ds, err := s.ListDevices(ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range ds {
			devs[d.ID] = d
		}
	}
	for _, id := range []string{d1.ID, d2.ID, d3.ID} {
		if d, ok := devs[id]; !ok || d.RevokedAt == nil {
			t.Errorf("device %s (%s) not revoked: %+v", id, d.Name, d)
		}
	}
	if _, ok := devs[d4.ID]; ok {
		t.Error("a device made after the copy came back")
	}
	for name, want := range map[string]bool{"alice": true, "bob": false, "carol": false} {
		u, err := s.UserByName(ctx, name)
		if err != nil || u.Enabled != want {
			t.Errorf("user %s: enabled %v, want %v (%v)", name, u.Enabled, want, err)
		}
		if name == "alice" && (u.ExpiresAt == nil || !u.ExpiresAt.Equal(sooner)) {
			t.Errorf("alice expires %v, want %v", u.ExpiresAt, sooner)
		}
	}
	if invs, err := s.ListInvites(ctx); err != nil || len(invs) != 0 {
		t.Errorf("invites %v %v", invs, err)
	}
	if v, err := s.GetSetting(ctx, "admin_access"); err != nil || string(v) != `["198.51.100.7/32"]` {
		t.Errorf("admin access %s %v", v, err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// What else a rollback must not give back: a deleted user whose ID went to
// a new one, a relay removed, a service taken from a user or disabled, a
// REALITY no longer open, and certificates replaced.
func TestCarryRevocationsMore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	saved, current := filepath.Join(dir, "saved.db"), filepath.Join(dir, "current.db")
	s, err := Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []User{{Name: "alice", Enabled: true}, {Name: "mallory", Enabled: true}} {
		if _, err := s.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	r1, _ := s.CreateService(ctx, Service{Kind: "reality", Name: "r1", Enabled: true, Settings: `{"open":true}`})
	r2, _ := s.CreateService(ctx, Service{Kind: "naive", Name: "n1", Enabled: true})
	must(t, s.SetUserServices(ctx, "alice", []int64{r1.ID, r2.ID}))
	d, _, _ := s.CreateDevice(ctx, "alice", "phone", "user")
	if _, err := s.db.ExecContext(ctx, `UPDATE devices SET cert_pin = 'old-pin' WHERE id = ?`, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRelay(ctx, "relay1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	must(t, s.SetRelayCertPin(ctx, "relay1", "relay-old"))
	s.Close()
	copyFile(t, current, saved)

	s, err = Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	mallory, _ := s.UserByName(ctx, "mallory")
	must(t, s.DeleteUser(ctx, "mallory"))
	bob, err := s.CreateUser(ctx, User{Name: "bob", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if bob.ID != mallory.ID {
		t.Logf("bob got ID %d, mallory had %d: the case below is weaker", bob.ID, mallory.ID)
	}
	must(t, s.SetUserServices(ctx, "alice", []int64{r1.ID}))
	must(t, s.SetServiceEnabled(ctx, "n1", false))
	if _, err := s.db.ExecContext(ctx, `UPDATE services SET settings_json = json_remove(settings_json, '$.open') WHERE id = ?`, r1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE devices SET cert_pin = 'new-pin' WHERE id = ?`, d.ID); err != nil {
		t.Fatal(err)
	}
	must(t, s.DeleteRelay(ctx, "relay1"))
	s.Close()

	if err := CarryRevocations(ctx, saved, current); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, saved)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if u, err := s.UserByName(ctx, "mallory"); err != nil || u.Enabled {
		t.Errorf("deleted mallory (her ID reused): enabled %v %v", u.Enabled, err)
	}
	if rs, _ := s.ListRelays(ctx); len(rs) != 0 {
		t.Errorf("removed relay back: %v", rs)
	}
	var n int
	s.db.QueryRowContext(ctx, `SELECT count(*) FROM user_services us JOIN users u ON u.id = us.user_id WHERE u.name = 'alice'`).Scan(&n)
	if n != 1 {
		t.Errorf("alice has %d services, want 1", n)
	}
	if svc, _ := s.ServiceByName(ctx, "n1"); svc.Enabled {
		t.Error("disabled service enabled again")
	}
	if svc, _ := s.ServiceByName(ctx, "r1"); strings.Contains(svc.Settings, "open") {
		t.Errorf("REALITY open again: %s", svc.Settings)
	}
	var pin string
	s.db.QueryRowContext(ctx, `SELECT cert_pin FROM devices WHERE id = ?`, d.ID).Scan(&pin)
	if pin != "new-pin" {
		t.Errorf("device certificate pin %q, want the new one", pin)
	}
}
