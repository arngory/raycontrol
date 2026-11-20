package api

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
)

// ListRelays names each relay's names (relay-names-v1 §3) with their
// service and whether rayd's check found them ready; a relay removed and
// added again by its name has none of the names of the one before.
func TestListRelayNames(t *testing.T) {
	// The name rayd's check found ready, set before the server serves.
	var ready atomic.Value
	srv, sock, _ := startServerWith(t, func(s *Server) []func() (string, http.Handler) {
		s.RelayNameStatus = func(name string) (bool, string) {
			if r, _ := ready.Load().(string); r == name {
				return true, ""
			}
			return false, "not checked yet"
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := provision.Init(ctx, srv.Store, provision.Options{Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	c := NewUnixClient(sock)
	for _, s := range []*nodev1.CreateServiceRequest{{Kind: "reality", Name: "reality"}, {Kind: "hy2-obfs", Name: "obfs"}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(s)); err != nil {
			t.Fatal(s.Name, err)
		}
	}
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r1", Address: "198.51.100.20"})); err != nil {
		t.Fatal(err)
	}
	names := func() []*nodev1.RelayName {
		t.Helper()
		r, err := c.ListRelays(ctx, connect.NewRequest(&nodev1.ListRelaysRequest{}))
		if err != nil || len(r.Msg.Relays) != 1 {
			t.Fatalf("list %v %v", r, err)
		}
		return r.Msg.Relays[0].Names
	}
	if n := names(); len(n) != 0 {
		t.Fatalf("before the bundle: %v", n)
	}
	if err := srv.Store.SetRelayCertPin(ctx, "r1", "pin"); err != nil {
		t.Fatal(err)
	}
	n := names()
	if len(n) != 1 || n[0].Service != "reality" || n[0].Ready || n[0].Problem != "not checked yet" {
		t.Fatalf("names %v", n)
	}
	first := n[0].Name
	ready.Store(first)
	if n := names(); len(n) != 1 || n[0].Name != first || !n[0].Ready {
		t.Fatalf("ready: %v", n)
	}

	// Removed, then added again before a render: the names went with it.
	if _, err := c.RemoveRelay(ctx, connect.NewRequest(&nodev1.RemoveRelayRequest{Name: "r1"})); err != nil {
		t.Fatal(err)
	}
	if b, err := srv.Store.GetSetting(ctx, node.RelayNamesSetting); err != nil || string(b) != "{}" {
		t.Fatalf("after the removal: %s %v", b, err)
	}
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r1", Address: "198.51.100.20"})); err != nil {
		t.Fatal(err)
	}
	if err := srv.Store.SetRelayCertPin(ctx, "r1", "pin"); err != nil {
		t.Fatal(err)
	}
	if n := names(); len(n) != 1 || n[0].Name == first {
		t.Fatalf("added again: %v, before %s", n, first)
	}
}
