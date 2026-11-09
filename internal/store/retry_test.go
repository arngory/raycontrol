package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A retried CreateInvite (its answer lost) leaves one invite for the
// device, the latest: the earlier one could never register anyway, the
// name being the device's.
func TestCreateInviteRetry(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	first, _, err := s.CreateInvite(ctx, "alice", "phone", "user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := s.CreateInvite(ctx, "alice", "tablet", "user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := s.CreateInvite(ctx, "alice", "phone", "admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.ListInvites(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, inv := range list {
		ids[inv.ID] = true
	}
	if len(list) != 2 || !ids[again.ID] || !ids[other.ID] {
		t.Fatalf("invites after a retry: %+v", list)
	}
	if _, _, err := s.ActiveInvite(ctx, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the replaced invite: %v", err)
	}
	// A used invite stays (its device has the name, so no new one).
	if _, _, err := s.UseInvite(ctx, again.ID, "pin-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateInvite(ctx, "alice", "phone", "user", time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an invite for a registered name: %v", err)
	}
}

// CreateUser makes the user and its services in one write: services that
// fail leave no user behind, so the retry is not "already exists".
func TestCreateUserAtomic(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true, Services: []int64{999}}); err == nil {
		t.Fatal("a user with a service that does not exist")
	}
	if _, err := s.UserByName(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a user left behind by a failed create: %v", err)
	}
	svc, err := s.CreateService(ctx, Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true, Services: []int64{svc.ID}}); err != nil {
		t.Fatal(err)
	}
	if u, err := s.UserByName(ctx, "alice"); err != nil || len(u.Services) != 1 || u.Services[0] != svc.ID {
		t.Fatalf("alice: %+v %v", u, err)
	}
}
