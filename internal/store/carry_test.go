package store

import (
	"context"
	"os"
	"path/filepath"
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
