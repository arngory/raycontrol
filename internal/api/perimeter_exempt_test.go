package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
)

// The snapshot's exemptions of the local part (spec/egress-policy-v1.md
// §10): each enabled REALITY service with a target on a local address, by
// that address, TCP and port, for the service's UID; nothing else.
func TestLocalExempt(t *testing.T) {
	services := []store.Service{
		{Kind: "reality", Name: "steal", Enabled: true, UID: 9120, Settings: `{"target":"127.0.0.1:8443","sni":"www.example.org"}`},
		{Kind: "reality", Name: "lan", Enabled: true, UID: 9121, Settings: `{"target":"[fd00::7]:443","sni":"www.example.org"}`},
		{Kind: "reality", Name: "public", Enabled: true, UID: 9122, Settings: `{"target":"www.example.org:443"}`},
		{Kind: "reality", Name: "off", Enabled: false, UID: 9123, Settings: `{"target":"127.0.0.1:9443","sni":"www.example.org"}`},
		{Kind: "reality", Name: "nouid", Enabled: true, Settings: `{"target":"127.0.0.1:9443","sni":"www.example.org"}`},
		{Kind: "naive", Name: "naive", Enabled: true, UID: 9124, Settings: `{"target":"127.0.0.1:9443"}`},
	}
	got := localExempt(services)
	if len(got) != 2 || got[0].Addr != "127.0.0.1" || got[0].Port.Port != 8443 || got[0].Port.Proto != "tcp" || got[0].Uid != 9120 ||
		got[1].Addr != "fd00::7" || got[1].Port.Port != 443 || got[1].Uid != 9121 {
		t.Fatalf("%v", got)
	}
	// localhost (a local nginx, as nodes before v0.27.0 were made): both
	// loopbacks, as Xray's resolver may take either; 0.0.0.0, which the
	// kernel makes 127.0.0.1, none.
	got = localExempt([]store.Service{
		{Kind: "reality", Name: "nginx", Enabled: true, UID: 9125, Settings: `{"target":"localhost:8443","sni":"www.example.org"}`},
		{Kind: "reality", Name: "any", Enabled: true, UID: 9126, Settings: `{"target":"0.0.0.0:8443","sni":"www.example.org"}`},
	})
	if len(got) != 2 || got[0].Addr != "127.0.0.1" || got[1].Addr != "::1" || got[0].Uid != 9125 || got[1].Uid != 9125 ||
		got[0].Port.Port != 8443 || got[1].Port.Port != 8443 {
		t.Fatalf("localhost: %v", got)
	}
}

// rayctl service set NAME target=HOST:PORT: the new target is checked
// from the node as a new service's is, with the service's server name;
// refused, nothing changes and nothing is audited, as at creation; taken,
// it is audited as the other options.
func TestSetRealityTarget(t *testing.T) {
	var (
		mu      sync.Mutex
		checked []string
	)
	srv, sock, _ := startServerWith(t, func(s *Server) []func() (string, http.Handler) {
		s.CheckRealityTarget = func(_ context.Context, target, sni string) error {
			mu.Lock()
			defer mu.Unlock()
			checked = append(checked, target+" "+sni)
			if target == "127.0.0.1:9443" {
				return errors.New("reality target 127.0.0.1:9443 does not speak HTTP/2")
			}
			return nil
		}
		return nil
	})
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "r",
		SettingsJson: `{"target":"localhost:8443","sni":"www.example.org"}`})); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	checked = nil // the creation's
	mu.Unlock()
	set := func(value string) error {
		_, err := c.SetServiceOption(ctx, connect.NewRequest(&nodev1.SetServiceOptionRequest{Name: "r", Key: "target", Value: value}))
		return err
	}
	if err := set("127.0.0.1:9443"); connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "HTTP/2") {
		t.Fatalf("a target the check refuses: %v", err)
	}
	if svc, _ := srv.Store.ServiceByName(ctx, "r"); !strings.Contains(svc.Settings, `"target":"localhost:8443"`) {
		t.Fatalf("changed after a refusal: %s", svc.Settings)
	}
	if err := set("127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
	if svc, _ := srv.Store.ServiceByName(ctx, "r"); !strings.Contains(svc.Settings, `"target":"127.0.0.1:8443"`) ||
		!strings.Contains(svc.Settings, `"sni":"www.example.org"`) {
		t.Fatalf("not set: %s", svc.Settings)
	}
	mu.Lock()
	if !slices.Equal(checked, []string{"127.0.0.1:9443 www.example.org", "127.0.0.1:8443 www.example.org"}) {
		t.Fatalf("checked %v", checked)
	}
	checked = nil
	mu.Unlock()
	entries, _ := srv.Store.ListAudit(ctx, 5)
	if len(entries) == 0 || entries[0].Action != "service.set target=127.0.0.1:8443" || entries[0].Target != "r" ||
		slices.ContainsFunc(entries, func(e store.AuditEntry) bool { return strings.Contains(e.Action, "9443") }) {
		t.Fatalf("audit %+v", entries)
	}
	// Other options are not checked as targets.
	if _, err := c.SetServiceOption(ctx, connect.NewRequest(&nodev1.SetServiceOptionRequest{Name: "r", Key: "rotate_sni", Value: "false"})); err != nil {
		t.Fatalf("rotate_sni: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if checked != nil {
		t.Fatalf("rotate_sni checked %v", checked)
	}
}
