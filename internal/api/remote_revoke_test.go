package api

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// An admin device revoked while its call runs gets no secret the call made
// or read after the revocation: here a new device's bundle (R4-36). A call
// whose answer holds none still answers.
func TestRemoteRevokedDuringCall(t *testing.T) {
	// Revoked from inside the call: OnChange runs as the call finishes,
	// after its write, before its answer.
	var revoke atomic.Pointer[string]
	srv, sock, _ := startServerWith(t, func(s *Server) []func() (string, http.Handler) {
		s.OnChange = func() {
			if id := revoke.Swap(nil); id != nil {
				if _, err := s.Store.RevokeDevice(context.Background(), *id); err != nil {
					t.Error(err)
				}
			}
		}
		return nil
	})
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice"})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"})); err != nil {
		t.Fatal(err)
	}
	addr, pin := startRemote(t, srv)
	now := time.Now().Unix() / 60
	register := func(name string) (remoteDevice, string) {
		t.Helper()
		inv, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: name, Role: "admin"}))
		if err != nil {
			t.Fatal(err)
		}
		rd := newRemoteDevice(t, addr, pin)
		reg, err := rd.register(ctx, inv.Msg.InviteCode, now)
		if err != nil {
			t.Fatal(err)
		}
		return rd, reg.DeviceId
	}

	laptop, id := register("laptop")
	revoke.Store(&id)
	if r, err := laptop.node.CreateDevice(ctx, connect.NewRequest(&nodev1.CreateDeviceRequest{User: "alice", Name: "spare"})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("a device made by a device revoked during the call: %v %v", r, err)
	}
	if revoke.Load() != nil {
		t.Fatal("the hook did not run")
	}

	// Disabling its own user: the answer holds nothing secret, and the
	// call did what it was asked.
	tablet, _ := register("tablet")
	if _, err := tablet.node.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "alice", Enabled: false})); err != nil {
		t.Fatalf("an admin disables its own user: %v", err)
	}
	if _, err := tablet.node.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("after: %v", err)
	}
}
