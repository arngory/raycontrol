package api

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// The last enabled ssh service is what the perimeter admits SSH on: it is
// not disabled or deleted by accident (failed_precondition, saying what
// follows and the flag), with force it is, and audited so; while another
// enabled one is there, or for any other service, nothing is in the way.
func TestLastSSHService(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	for _, s := range []*nodev1.CreateServiceRequest{
		{Kind: "ssh", Name: "ssh", SettingsJson: `{"ports":["tcp/22"]}`},
		{Kind: "dnstt", Name: "dns"},
	} {
		if _, err := c.CreateService(ctx, connect.NewRequest(s)); err != nil {
			t.Fatal(err)
		}
	}
	refused := func(what string, err error, flag string) {
		t.Helper()
		if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "closed to everyone") ||
			!strings.Contains(err.Error(), flag) {
			t.Errorf("%s: %v", what, err)
		}
	}
	disable := func(name string, force bool) error {
		_, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: name, Enabled: false, Force: force}))
		return err
	}
	del := func(name string, force bool) error {
		_, err := c.DeleteService(ctx, connect.NewRequest(&nodev1.DeleteServiceRequest{Name: name, Force: force}))
		return err
	}
	refused("disable the only ssh", disable("ssh", false), "rayctl service disable ssh -force")
	refused("delete the only ssh", del("ssh", false), "rayctl service del ssh -force")
	if err := disable("dns", false); err != nil {
		t.Errorf("another kind: %v", err)
	}
	// A second one on another port: the first may go.
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "ssh", Name: "ssh2",
		SettingsJson: `{"ports":["tcp/2222"]}`})); err != nil {
		t.Fatal(err)
	}
	if err := disable("ssh", false); err != nil {
		t.Fatalf("disable ssh beside ssh2: %v", err)
	}
	// ssh2 is the last enabled one now; a disabled one counts for nothing.
	refused("delete ssh2 with ssh disabled", del("ssh2", false), "rayctl service del ssh2 -force")
	if err := del("ssh", false); err != nil {
		t.Errorf("delete a disabled ssh: %v", err)
	}
	if err := disable("ssh2", true); err != nil {
		t.Fatalf("-force: %v", err)
	}
	if err := del("ssh2", true); err != nil {
		t.Fatalf("-force: %v", err)
	}
	entries, err := srv.Store.ListAudit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		if e.Target == "ssh2" && strings.HasPrefix(e.Result, "ok") && strings.HasPrefix(e.Action, "service.") && !strings.HasPrefix(e.Action, "service.create") {
			actions = append(actions, e.Action)
		}
	}
	slices.Sort(actions)
	if !slices.Equal(actions, []string{"service.delete force", "service.enable=false force"}) {
		t.Errorf("audit %q", actions)
	}
}
