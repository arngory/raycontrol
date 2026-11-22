package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// accessNode records SetRelayAccess and, when it takes users, keeps them
// on its relay, as a rayd of v0.36.0 does; one that does not take them is
// an older rayd, which ignores the fields.
type accessNode struct {
	nodev1connect.NodeServiceClient
	relay *nodev1.Relay
	take  bool
	got   *nodev1.SetRelayAccessRequest
}

func (n *accessNode) SetRelayAccess(_ context.Context, r *connect.Request[nodev1.SetRelayAccessRequest]) (*connect.Response[nodev1.SetRelayAccessResponse], error) {
	n.got = r.Msg
	if n.take && r.Msg.SetUsers {
		n.relay.Users = slices.Clone(r.Msg.Users)
	}
	return connect.NewResponse(&nodev1.SetRelayAccessResponse{}), nil
}

func (n *accessNode) ListRelays(context.Context, *connect.Request[nodev1.ListRelaysRequest]) (*connect.Response[nodev1.ListRelaysResponse], error) {
	return connect.NewResponse(&nodev1.ListRelaysResponse{Relays: []*nodev1.Relay{n.relay}}), nil
}

// rayctl relay set -users and -renew-names reach the request; the relay is
// read back, and a node that kept it for everyone is an error, not "for
// bob only".
func TestRelaySetUsers(t *testing.T) {
	ctx := context.Background()

	n := &accessNode{relay: &nodev1.Relay{Name: "msk"}, take: true}
	out, err := captureStdout(t, func() error {
		return (&cli{c: n}).relay(ctx, "set", []string{"-users", "bob,alice", "-renew-names", "msk"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !n.got.SetUsers || !slices.Equal(n.got.Users, []string{"bob", "alice"}) || !n.got.RenewNames || n.got.Name != "msk" {
		t.Fatalf("request: %+v", n.got)
	}
	if !strings.Contains(out, "for bob, alice only") || !strings.Contains(out, "new names") {
		t.Fatalf("output: %q", out)
	}

	n = &accessNode{relay: &nodev1.Relay{Name: "msk", Users: []string{"bob"}}, take: true}
	if _, err := captureStdout(t, func() error { return (&cli{c: n}).relay(ctx, "set", []string{"-users", "all", "msk"}) }); err != nil {
		t.Fatal(err)
	}
	if !n.got.SetUsers || len(n.got.Users) != 0 || len(n.relay.Users) != 0 {
		t.Fatalf("all: request %+v, relay %+v", n.got, n.relay)
	}

	// Neither flag: the fields stay unset, so a node keeps what it has.
	n = &accessNode{relay: &nodev1.Relay{Name: "msk"}, take: true}
	if _, err := captureStdout(t, func() error { return (&cli{c: n}).relay(ctx, "set", []string{"-ssh-port", "2222", "msk"}) }); err != nil {
		t.Fatal(err)
	}
	if n.got.SetUsers || n.got.RenewNames || n.got.SshPort != 2222 {
		t.Fatalf("ssh only: %+v", n.got)
	}

	old := &accessNode{relay: &nodev1.Relay{Name: "msk"}}
	out, err = captureStdout(t, func() error { return (&cli{c: old}).relay(ctx, "set", []string{"-users", "bob", "msk"}) })
	if err == nil || !strings.Contains(err.Error(), "did not take -users") || !strings.Contains(err.Error(), "for all") {
		t.Fatalf("older node: err %v", err)
	}
	if strings.Contains(out, "only") {
		t.Fatalf("older node: said %q", out)
	}

	gone := &accessNode{relay: &nodev1.Relay{Name: "spb"}, take: true}
	if _, err := captureStdout(t, func() error { return (&cli{c: gone}).relay(ctx, "set", []string{"-users", "bob", "msk"}) }); err == nil {
		t.Fatal("relay gone: no error")
	}
}
