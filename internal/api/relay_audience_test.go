package api

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

func audienceRelayNode(t *testing.T) (*Server, nodev1Client, *PerimeterServer, context.Context) {
	t.Helper()
	srv, sock, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c := NewUnixClient(sock)
	for _, s := range []*nodev1.CreateServiceRequest{
		{Kind: "reality", Name: "reality", SettingsJson: `{"target":"www.example.org:443"}`},
		{Kind: "ssh", Name: "ssh", SettingsJson: `{"ports":["tcp/2222"]}`},
	} {
		if _, err := c.CreateService(ctx, connect.NewRequest(s)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := srv.Store.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	per := &PerimeterServer{Server: srv, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour, TCPCarrier: true}
	return srv, c, per, ctx
}

type nodev1Client = interface {
	CreateUser(context.Context, *connect.Request[nodev1.CreateUserRequest]) (*connect.Response[nodev1.CreateUserResponse], error)
	DeleteUser(context.Context, *connect.Request[nodev1.DeleteUserRequest]) (*connect.Response[nodev1.DeleteUserResponse], error)
	SetRelayAccess(context.Context, *connect.Request[nodev1.SetRelayAccessRequest]) (*connect.Response[nodev1.SetRelayAccessResponse], error)
	ListRelays(context.Context, *connect.Request[nodev1.ListRelaysRequest]) (*connect.Response[nodev1.ListRelaysResponse], error)
	CreateService(context.Context, *connect.Request[nodev1.CreateServiceRequest]) (*connect.Response[nodev1.CreateServiceResponse], error)
}

// relay-v1 §4.1: a relay for bob; bob deleted; a new user may get bob's
// SQLite rowid, and must not get the relay with it.
func TestRelayAudienceRelayUserIDReuse(t *testing.T) {
	srv, c, per, ctx := audienceRelayNode(t)
	for _, n := range []string{"alice", "bob"} {
		if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: n, Services: []string{"reality"}})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.SetRelayAccess(ctx, connect.NewRequest(&nodev1.SetRelayAccessRequest{Name: "r1", SetUsers: true, Users: []string{"bob"}})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteUser(ctx, connect.NewRequest(&nodev1.DeleteUserRequest{Name: "bob"})); err != nil {
		t.Fatal(err)
	}
	alice, _, err := srv.Store.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	// Its only user gone: for no one, not for every user.
	list, _ := c.ListRelays(ctx, connect.NewRequest(&nodev1.ListRelaysRequest{}))
	if r := list.Msg.Relays[0]; len(r.Users) != 0 || !r.UsersNone {
		t.Errorf("after bob deleted: users %v, none %v", r.Users, r.UsersNone)
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "mallory", Services: []string{"reality"}})); err != nil {
		t.Fatal(err)
	}
	mdev, _, err := srv.Store.CreateDevice(ctx, "mallory", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	list, _ = c.ListRelays(ctx, connect.NewRequest(&nodev1.ListRelaysRequest{}))
	snap, err := per.RelaySnapshot(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range snap.Devices {
		if d.Id == mdev.ID || d.Id == alice.ID {
			t.Errorf("a relay for no one knows device %s", d.Id)
		}
	}
	if r := list.Msg.Relays[0]; slices.Contains(r.Users, "mallory") || !r.UsersNone {
		t.Errorf("mallory inherited bob's relay: users %v, none %v", r.Users, r.UsersNone)
	}
}

// relay-v1 §3.1 and §4.1: a device allowed the exit's SSH keeps the relay
// host's SSH by SPA on a relay for other users, and nothing else there.
func TestRelayAudienceRelayAdminSSHLockout(t *testing.T) {
	srv, c, per, ctx := audienceRelayNode(t)
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "admin", Services: []string{"ssh"}})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"reality"}})); err != nil {
		t.Fatal(err)
	}
	adev, _, err := srv.Store.CreateDevice(ctx, "admin", "laptop", "admin")
	if err != nil {
		t.Fatal(err)
	}
	has := func() bool {
		snap, err := per.RelaySnapshot(ctx, "r1")
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range snap.Devices {
			if d.Id == adev.ID {
				return true
			}
		}
		return false
	}
	if !has() {
		t.Fatal("admin's device not in snapshot of a relay for all")
	}
	if _, err := c.SetRelayAccess(ctx, connect.NewRequest(&nodev1.SetRelayAccessRequest{Name: "r1", SetUsers: true, Users: []string{"alice"}})); err != nil {
		t.Fatal(err)
	}
	if !has() {
		t.Errorf("relay for alice: the admin's device, allowed the exit's SSH, lost the relay host's SSH by SPA")
	}
}

// SetRelayAccess: a list with a user that does not exist changes nothing,
// nothing to set is refused, and renew_names forgets the relay's names.
func TestRelayAudienceSetRelayAccess(t *testing.T) {
	srv, c, _, ctx := audienceRelayNode(t)
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"reality"}})); err != nil {
		t.Fatal(err)
	}
	users := func() []int64 {
		t.Helper()
		r, err := srv.Store.RelayByName(ctx, "r1")
		if err != nil {
			t.Fatal(err)
		}
		return r.Users
	}
	if _, err := c.SetRelayAccess(ctx, connect.NewRequest(&nodev1.SetRelayAccessRequest{Name: "r1", SetUsers: true, Users: []string{"alice", "carol"}})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("alice and carol, who does not exist: %v", err)
	}
	if u := users(); u != nil {
		t.Fatalf("a refused list set users %v", u)
	}
	if _, err := c.SetRelayAccess(ctx, connect.NewRequest(&nodev1.SetRelayAccessRequest{Name: "r1"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("nothing to set: %v", err)
	}
	if err := srv.Store.SetSetting(ctx, "relay_names", []byte(`{"r1":{"1":"abc.example.com"},"r2":{"1":"def.example.com"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetRelayAccess(ctx, connect.NewRequest(&nodev1.SetRelayAccessRequest{Name: "r1", RenewNames: true})); err != nil {
		t.Fatal(err)
	}
	if b, err := srv.Store.GetSetting(ctx, "relay_names"); err != nil || string(b) != `{"r2":{"1":"def.example.com"}}` {
		t.Fatalf("relay names after renew of r1: %s (%v)", b, err)
	}
}
