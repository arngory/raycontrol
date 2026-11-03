package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInvites(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	if _, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateInvite(ctx, "alice", "phone", "user", 8*24*time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an invite for 8 days: %v", err)
	}
	inv, key, err := s.CreateInvite(ctx, "alice", "phone", "user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, k, err := s.ActiveInvite(ctx, inv.ID); err != nil || k != key {
		t.Fatalf("active: %v", err)
	}
	d, devKey, err := s.UseInvite(ctx, inv.ID, "pin-a")
	if err != nil || d.Name != "phone" || d.Role != "user" || devKey == key {
		t.Fatalf("use: %+v %v", d, err)
	}
	if _, _, err := s.UseInvite(ctx, inv.ID, "pin-b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("used twice: %v", err)
	}
	if got, err := s.DeviceByCertPin(ctx, "pin-a"); err != nil || got.ID != d.ID {
		t.Fatalf("by pin: %+v %v", got, err)
	}
	// The name is the device's now; another invite for it is refused.
	if _, _, err := s.CreateInvite(ctx, "alice", "phone", "user", time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an invite for a taken name: %v", err)
	}
	// Expiry, and a disabled user.
	late, _, err := s.CreateInvite(ctx, "alice", "tablet", "admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if _, _, err := s.UseInvite(ctx, late.ID, "pin-c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
	soon, _, err := s.CreateInvite(ctx, "alice", "watch", "user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UseInvite(ctx, soon.ID, "pin-d"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled user: %v", err)
	}
	if _, err := s.DeviceByCertPin(ctx, "pin-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a disabled user's device: %v", err)
	}
	if err := s.SetUserEnabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	// Rotation of the client key.
	if err := s.SetCertPin(ctx, d.ID, "pin-x", "pin-e"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotation from a wrong key: %v", err)
	}
	if err := s.SetCertPin(ctx, d.ID, "pin-a", "pin-e"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeviceByCertPin(ctx, "pin-a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the old key still works")
	}
	list, err := s.ListInvites(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("unused invites: %v %v", list, err)
	}
	if err := s.PruneInvites(ctx, now); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListInvites(ctx); len(list) != 1 || list[0].ID != soon.ID {
		t.Fatalf("after prune: %v", list)
	}
}
