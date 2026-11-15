package api

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
)

// RenewUser (rayctl user renew): the user's credentials new at once, on
// the node and from an admin device, audited without them; an unknown
// user is not_found (R4-36).
func TestRenewUser(t *testing.T) {
	srv, sock, changes := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "reality",
		SettingsJson: `{"target":"www.example.org:443"}`})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"reality"}})); err != nil {
		t.Fatal(err)
	}
	links := func() []string {
		t.Helper()
		r, err := c.ExportUser(ctx, connect.NewRequest(&nodev1.ExportUserRequest{Name: "alice"}))
		if err != nil || len(r.Msg.Profiles) == 0 {
			t.Fatalf("export: %v", err)
		}
		var out []string
		for _, p := range r.Msg.Profiles {
			out = append(out, p.Link)
		}
		return out
	}
	before := links()
	n := changes.Load()
	r, err := c.RenewUser(ctx, connect.NewRequest(&nodev1.RenewUserRequest{Name: "alice"}))
	if err != nil || r.Msg.Name != "alice" || r.Msg.Credentials == 0 {
		t.Fatalf("renew: %v %v", r, err)
	}
	after := links()
	if slices.Equal(before, after) || changes.Load() == n {
		t.Fatalf("nothing changed: %v, %d changes", after, changes.Load()-n)
	}
	if _, err := c.RenewUser(ctx, connect.NewRequest(&nodev1.RenewUserRequest{Name: "nobody"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("an unknown user: %v", err)
	}

	// From an admin device: the same.
	addr, pin := startRemote(t, srv)
	inv, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: "laptop", Role: "admin"}))
	if err != nil {
		t.Fatal(err)
	}
	admin := newRemoteDevice(t, addr, pin)
	if _, err := admin.register(ctx, inv.Msg.InviteCode, time.Now().Unix()/60); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.node.RenewUser(ctx, connect.NewRequest(&nodev1.RenewUserRequest{Name: "alice"})); err != nil {
		t.Fatalf("from an admin device: %v", err)
	}
	if slices.Equal(after, links()) {
		t.Fatal("the admin device's renewal changed nothing")
	}
	// From a user device: refused, and nothing changes.
	inv, err = c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: "phone", Role: "user"}))
	if err != nil {
		t.Fatal(err)
	}
	user := newRemoteDevice(t, addr, pin)
	if _, err := user.register(ctx, inv.Msg.InviteCode, time.Now().Unix()/60); err != nil {
		t.Fatal(err)
	}
	now := links()
	if _, err := user.node.RenewUser(ctx, connect.NewRequest(&nodev1.RenewUserRequest{Name: "alice"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("from a user device: %v", err)
	}
	if !slices.Equal(now, links()) {
		t.Fatal("a user device's call renewed")
	}

	entries, err := srv.Store.ListAudit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	var renewals []store.AuditEntry
	for _, e := range entries {
		if e.Action == "user.renew" {
			renewals = append(renewals, e)
		}
		for _, l := range append(before, after...) {
			id := strings.SplitN(strings.TrimPrefix(l, "vless://"), "@", 2)[0]
			if strings.Contains(e.Target, id) || strings.Contains(e.Result, id) {
				t.Errorf("a credential in the audit: %+v", e)
			}
		}
	}
	if len(renewals) != 3 || !strings.HasPrefix(renewals[0].Actor, "alice/laptop") || !strings.Contains(renewals[2].Target, "credentials new") ||
		renewals[1].Target != "nobody" {
		t.Fatalf("audit: %+v", renewals)
	}
}
