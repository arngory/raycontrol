package api

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
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
			!strings.HasPrefix(err.Error(), "failed_precondition: not now: "+flag+" does it anyway (rayctl before v0.27.0 has no -force)") {
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

// Two calls at once, each taking out one of the last two ssh services:
// one goes, the other is refused, and an ssh service stays enabled.
func TestLastSSHServiceAtOnce(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	for round := range 10 {
		a, b := fmt.Sprintf("ssh-a%d", round), fmt.Sprintf("ssh-b%d", round)
		for i, name := range []string{a, b} {
			if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "ssh", Name: name,
				SettingsJson: fmt.Sprintf(`{"ports":["tcp/%d"]}`, 2000+2*round+i)})); err != nil {
				t.Fatal(err)
			}
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		wg.Go(func() {
			_, errs[0] = c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: a, Enabled: false}))
		})
		wg.Go(func() {
			_, errs[1] = c.DeleteService(ctx, connect.NewRequest(&nodev1.DeleteServiceRequest{Name: b}))
		})
		wg.Wait()
		if (errs[0] == nil) == (errs[1] == nil) {
			t.Fatalf("round %d: %v, %v", round, errs[0], errs[1])
		}
		services, err := srv.Store.ListServices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(services, func(s store.Service) bool { return s.Kind == "ssh" && s.Enabled }) {
			t.Fatalf("round %d: no ssh service enabled", round)
		}
		// The one left makes the next round's pair the last two.
		for _, s := range services {
			if s.Kind == "ssh" && s.Enabled {
				if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: s.Name, Enabled: false, Force: true})); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

// The refusal as rayctl gets it, for a name of 64 bytes (the longest):
// well inside the 512 bytes rayctl prints, the command first with the
// name once, and nothing cut at the end.
func TestLastSSHMessageLength(t *testing.T) {
	_, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	name := strings.Repeat("s", 64)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "ssh", Name: name, SettingsJson: `{"ports":["tcp/22"]}`})); err != nil {
		t.Fatal(err)
	}
	_, errDisable := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: name, Enabled: false}))
	_, errDelete := c.DeleteService(ctx, connect.NewRequest(&nodev1.DeleteServiceRequest{Name: name}))
	for verb, err := range map[string]error{"disable": errDisable, "del": errDelete} {
		if err == nil {
			t.Fatalf("%s: not refused", verb)
		}
		msg := err.Error()
		if len(msg) > 300 {
			t.Errorf("%s: %d bytes: %s", verb, len(msg), msg)
		}
		if !strings.Contains(msg, "rayctl service "+verb+" "+name+" -force does it anyway") || strings.Count(msg, name) != 1 ||
			!strings.HasSuffix(msg, "open sessions go on") {
			t.Errorf("%s: %s", verb, msg)
		}
	}
}
