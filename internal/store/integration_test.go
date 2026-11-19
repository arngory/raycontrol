package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// Service users (integrations-v1 §2.2) are out of an integration's sight
// and reach, by the statement that reads or changes; the user of an
// integration has no services; SetUserExpiry; an integration's device
// passes SPA to the API alone.
func TestIntegrationUsers(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	svc := map[string]Service{}
	for _, k := range []string{"api", "ssh", "reality", "subscription"} {
		v, err := s.CreateService(ctx, Service{Kind: k, Name: k, Enabled: true, Settings: "{}"})
		if err != nil {
			t.Fatal(err)
		}
		svc[k] = v
	}
	user := func(name string, services ...string) {
		t.Helper()
		var ids []int64
		for _, k := range services {
			ids = append(ids, svc[k].ID)
		}
		if _, err := s.CreateUser(ctx, User{Name: name, Enabled: true, Services: ids}); err != nil {
			t.Fatal(err)
		}
	}
	user("alice", "reality") // regular
	user("bob", "reality")   // regular, with a user device
	user("root-ssh", "ssh")  // service: ssh
	user("ops")              // service: an admin device
	user("pending")          // service: an admin invite not used
	user("integrations")     // service: integration devices
	if _, _, err := s.CreateDevice(ctx, "bob", "phone", "user"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateDevice(ctx, "ops", "laptop", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateInvite(ctx, "pending", "laptop", "admin", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateDevice(ctx, "integrations", "bot", "billing"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a billing device without an invite: %v", err)
	}
	if _, _, err := s.CreateInvite(ctx, "alice", "bot", "billing", time.Hour); !errors.Is(err, ErrIntegrationUser) {
		t.Fatalf("an integration's invite to a user with services: %v", err)
	}
	if _, _, err := s.CreateInvite(ctx, "alice", "bot", "owner", time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an unknown role: %v", err)
	}
	inv, _, err := s.CreateInvite(ctx, "integrations", "billing", "billing", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Not even with its invite unused, nor once it is a device.
	if err := s.SetUserServices(ctx, "integrations", []int64{svc["reality"].ID}); !errors.Is(err, ErrIntegrationUser) {
		t.Fatalf("services to the user of an integration's invite: %v", err)
	}
	dev, _, err := s.UseInvite(ctx, inv.ID, "pin-billing")
	if err != nil || dev.Role != "billing" {
		t.Fatalf("register: %+v %v", dev, err)
	}
	if err := s.SetUserServices(ctx, "integrations", []int64{svc["reality"].ID}); !errors.Is(err, ErrIntegrationUser) {
		t.Fatalf("services to the user of an integration's device: %v", err)
	}
	if err := s.SetUserServices(ctx, "integrations", nil); err != nil {
		t.Fatalf("no services to the user of an integration: %v", err)
	}

	// The node's own calls see everyone.
	all, err := s.ListUsers(ctx)
	if err != nil || len(all) != 6 {
		t.Fatalf("users: %d %v", len(all), err)
	}
	// An integration's: regular users only.
	ictx := RegularOnly(ctx)
	users, err := s.ListUsers(ictx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, u := range users {
		names = append(names, u.Name)
	}
	if !slices.Equal(names, []string{"alice", "bob"}) {
		t.Fatalf("regular users: %v", names)
	}
	if u, err := s.UserByName(ictx, "bob"); err != nil || len(u.Services) != 1 {
		t.Fatalf("a regular user: %+v %v", u, err)
	}
	for _, name := range []string{"root-ssh", "ops", "pending", "integrations"} {
		if _, err := s.UserByName(ictx, name); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s by name: %v", name, err)
		}
		if err := s.SetUserEnabled(ictx, name, false); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s disabled: %v", name, err)
		}
		if err := s.DeleteUser(ictx, name); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s deleted: %v", name, err)
		}
		if err := s.SetUserServices(ictx, name, nil); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s services: %v", name, err)
		}
		if _, err := s.RenewUser(ictx, name); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s renewed: %v", name, err)
		}
		limit := int64(1 << 30)
		if _, err := s.SetUserTraffic(ictx, name, TrafficChange{Limit: &limit}); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s limit: %v", name, err)
		}
		if _, err := s.SetUserExpiry(ictx, name, nil); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s expiry: %v", name, err)
		}
		if _, _, err := s.CreateInvite(ictx, name, "x", "user", time.Hour); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s invited: %v", name, err)
		}
	}
	devices, err := s.ListDevices(ictx, "")
	if err != nil || len(devices) != 1 || devices[0].UserName != "bob" {
		t.Fatalf("an integration's devices: %+v %v", devices, err)
	}
	if devices, err := s.ListDevices(ictx, "ops"); err != nil || len(devices) != 0 {
		t.Fatalf("a service user's devices: %+v %v", devices, err)
	}
	if _, err := s.RevokeDevice(ictx, dev.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an integration revokes itself: %v", err)
	}
	invites, err := s.ListInvites(ictx)
	if err != nil || len(invites) != 0 {
		t.Fatalf("an integration's invites: %+v %v", invites, err)
	}
	pending, err := s.ListInvites(ctx)
	if err != nil || len(pending) != 1 {
		t.Fatalf("invites: %+v %v", pending, err)
	}
	if err := s.DeleteInvite(ictx, pending[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an integration withdraws an admin's invite: %v", err)
	}
	// A user who turns into a service user is out of reach at once.
	if _, _, err := s.CreateInvite(ctx, "bob", "laptop", "admin", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserEnabled(ictx, "bob", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob with an admin invite: %v", err)
	}
	if err := s.SetUserEnabled(ictx, "alice", false); err != nil {
		t.Fatal(err)
	}

	// SetUserExpiry: a time, never, now; expired stays as it was.
	now := s.now().Truncate(time.Second)
	later := now.Add(48 * time.Hour)
	if u, err := s.SetUserExpiry(ictx, "alice", &later); err != nil || !u.ExpiresAt.Equal(later) {
		t.Fatalf("later: %+v %v", u.ExpiresAt, err)
	}
	if u, err := s.SetUserExpiry(ictx, "alice", nil); err != nil || u.ExpiresAt != nil {
		t.Fatalf("never: %+v %v", u.ExpiresAt, err)
	}
	past := time.Unix(1, 0)
	u, err := s.SetUserExpiry(ictx, "alice", &past)
	if err != nil || u.ExpiresAt == nil || u.ExpiresAt.Before(now) || u.ExpiresAt.After(time.Now()) {
		t.Fatalf("now: %+v %v", u.ExpiresAt, err)
	}
	expired := *u.ExpiresAt
	time.Sleep(1100 * time.Millisecond)
	if u, err := s.SetUserExpiry(ictx, "alice", &past); err != nil || !u.ExpiresAt.Equal(expired) {
		t.Fatalf("again: %v, want %v (%v)", u.ExpiresAt, expired, err)
	}
	far := time.Unix(maxExpiry+1, 0)
	if _, err := s.SetUserExpiry(ctx, "alice", &far); !errors.Is(err, ErrInvalid) {
		t.Fatalf("after 9999: %v", err)
	}

	// An integration's invite does not register once its user is a
	// service user, and the device one made reaches data services only,
	// whatever its user gets later (integrations-v1 §2.2).
	user("carol", "reality")
	user("dave", "reality")
	late, _, err := s.CreateInvite(ictx, "carol", "phone", "user", time.Hour)
	if err != nil || !late.ByIntegration {
		t.Fatalf("an integration's invite: %+v %v", late, err)
	}
	early, _, err := s.CreateInvite(ictx, "dave", "phone", "user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	daveDev, _, err := s.UseInvite(ctx, early.ID, "pin-dave")
	if err != nil || !daveDev.ByIntegration {
		t.Fatalf("an integration's invite used: %+v %v", daveDev, err)
	}
	for _, name := range []string{"carol", "dave"} {
		if err := s.SetUserServices(ctx, name, []int64{svc["reality"].ID, svc["ssh"].ID}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.ActiveInvite(ctx, late.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an integration's invite of a service user: %v", err)
	}
	if _, _, err := s.UseInvite(ctx, late.ID, "pin-carol"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an integration's invite of a service user used: %v", err)
	}
	// billing keeps what it does not give: the subscription stays.
	user("erin", "reality", "subscription")
	if err := s.SetUserServices(ictx, "erin", []int64{svc["reality"].ID}); err != nil {
		t.Fatal(err)
	}
	if u, err := s.UserByName(ctx, "erin"); err != nil || len(u.Services) != 2 {
		t.Fatalf("erin's services after billing's: %+v %v", u.Services, err)
	}

	// SPA: an integration's device to the API alone, without the
	// subscription; an admin's with it; a user's device that came of an
	// integration's invite without ssh, whatever its user has.
	spaDevices, err := s.SPADevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range spaDevices {
		if d.ID == dev.ID && !slices.Equal(d.Allowed, []uint16{uint16(svc["api"].ID)}) {
			t.Errorf("billing's scope: %v", d.Allowed)
		}
		if d.ID == daveDev.ID && (slices.Contains(d.Allowed, uint16(svc["ssh"].ID)) || !slices.Contains(d.Allowed, uint16(svc["reality"].ID))) {
			t.Errorf("the scope of a device of an integration's invite: %v", d.Allowed)
		}
	}
}
