package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenTwiceAndMode(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sub", "rayd.db")
	for range 2 {
		s, err := Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestUsersServicesDevices(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	if _, err := s.CreateUser(ctx, User{Name: "Bad Name"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad name accepted: %v", err)
	}
	if _, err := s.CreateService(ctx, Service{Kind: "trojan", Name: "t"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown kind accepted: %v", err)
	}

	alice, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if _, err := s.CreateUser(ctx, User{Name: "bob", Enabled: true, ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, User{Name: "alice"}); err == nil {
		t.Fatal("duplicate user accepted")
	}

	reality, err := s.CreateService(ctx, Service{Kind: "reality", Name: "reality", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	dns, err := s.CreateService(ctx, Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if reality.ID != 1 || dns.ID != 2 {
		t.Fatalf("ids %d %d", reality.ID, dns.ID)
	}
	// IDs are never reused.
	if err := s.DeleteService(ctx, "dns"); err != nil {
		t.Fatal(err)
	}
	dns, err = s.CreateService(ctx, Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil || dns.ID != 3 {
		t.Fatalf("recreated id %d, err %v", dns.ID, err)
	}

	for _, u := range []string{"alice", "bob"} {
		if err := s.SetUserServices(ctx, u, []int64{reality.ID, dns.ID}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.UserByName(ctx, "alice")
	if err != nil || !slices.Equal(got.Services, []int64{reality.ID, dns.ID}) || got.ID != alice.ID {
		t.Fatalf("alice = %+v, %v", got, err)
	}

	phone, key, err := s.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateDevice(ctx, "bob", "phone", "user"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateDevice(ctx, "alice", "laptop", "root"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad role accepted: %v", err)
	}

	// Bob is expired, so only Alice's phone passes SPA.
	devs, err := s.SPADevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 || devs[0].ID != phone.ID || devs[0].Key != key || !slices.Equal(devs[0].Allowed, []uint16{1, 3}) {
		t.Fatalf("spa devices = %+v", devs)
	}

	if err := s.SetServiceEnabled(ctx, "reality", false); err != nil {
		t.Fatal(err)
	}
	devs, _ = s.SPADevices(ctx)
	if len(devs) != 1 || !slices.Equal(devs[0].Allowed, []uint16{3}) {
		t.Fatalf("after disabling reality: %+v", devs)
	}

	if err := s.SetUserEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if devs, _ = s.SPADevices(ctx); len(devs) != 0 {
		t.Fatalf("disabled user still passes SPA: %+v", devs)
	}
	if err := s.SetUserEnabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeDevice(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeDevice(ctx, phone.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	if devs, _ = s.SPADevices(ctx); len(devs) != 0 {
		t.Fatalf("revoked device still passes SPA: %+v", devs)
	}

	if err := s.DeleteUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListDevices(ctx, "")
	if err != nil || len(list) != 1 || list[0].UserName != "bob" {
		t.Fatalf("devices after delete = %+v, %v", list, err)
	}
	if err := s.DeleteUser(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestSettingsAndAudit(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.GetSetting(ctx, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing setting: %v", err)
	}
	for _, v := range []string{"1", "2"} {
		if err := s.SetSetting(ctx, "x", []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := s.GetSetting(ctx, "x"); string(v) != "2" {
		t.Fatalf("setting = %q", v)
	}

	s.now = func() time.Time { return time.Unix(1000, 0) }
	s.Audit(ctx, "root", "user.create", "alice", "ok")
	s.now = func() time.Time { return time.Unix(2000, 0) }
	s.Audit(ctx, "root", "user.delete", "alice", "ok")
	entries, err := s.ListAudit(ctx, 10)
	if err != nil || len(entries) != 2 || entries[0].Action != "user.delete" {
		t.Fatalf("audit = %+v, %v", entries, err)
	}
	if err := s.PruneAudit(ctx, time.Unix(1500, 0)); err != nil {
		t.Fatal(err)
	}
	if entries, _ = s.ListAudit(ctx, 10); len(entries) != 1 {
		t.Fatalf("after prune: %+v", entries)
	}
}
