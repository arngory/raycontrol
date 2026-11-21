package api

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// An invite of admin or billing without a PIN says so to whoever made it
// (protocol review 2026-11, L4); with one, or of another role, nothing.
func TestInviteNoPINWarning(t *testing.T) {
	_, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	for _, u := range []string{"alice", "integrations"} {
		if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: u})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"})); err != nil {
		t.Fatal(err)
	}
	for i, x := range []struct {
		user, role string
		pin, warn  bool
	}{
		{"alice", "admin", false, true},
		{"alice", "admin", true, false},
		{"integrations", "billing", false, true},
		{"integrations", "billing", true, false},
		{"integrations", "support", false, false},
		{"alice", "user", false, false},
	} {
		r, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: x.user, Name: "d" + string(rune('a'+i)), Role: x.role, Pin: x.pin}))
		if err != nil {
			t.Fatalf("%s, PIN %v: %v", x.role, x.pin, err)
		}
		warned := slices.ContainsFunc(r.Msg.Warnings, func(w string) bool { return strings.Contains(w, "has no PIN") })
		if warned != x.warn {
			t.Errorf("%s, PIN %v: warnings %q", x.role, x.pin, r.Msg.Warnings)
		}
	}
}
