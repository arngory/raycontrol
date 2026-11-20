package api

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
)

// relay-names-v1 §6 on the exit: a relay's rayspa says in its feed that it
// forwards TCP 80 (kept, its change news); while the node's ACME window is
// open for an order with the relay's names, the relay's snapshot carries
// the window's end, and the feed sends it at once, and its close; another
// relay's snapshot and an order without the relay's names have none. The
// relay's ports list TCP 80 while the node has no DNS provider.
func TestRelayACMEForward(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := provision.Init(ctx, srv.Store, provision.Options{Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	c := NewUnixClient(sock)
	for _, s := range []*nodev1.CreateServiceRequest{{Kind: "api", Name: "api"}, {Kind: "reality", Name: "reality"}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(s)); err != nil {
			t.Fatal(s.Name, err)
		}
	}
	var bundle node.RelayBundle
	for i, name := range []string{"r1", "r2"} {
		if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: name, Address: fmt.Sprintf("198.51.100.%d", 20+i)})); err != nil {
			t.Fatal(err)
		}
		r, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: name, ExitAddress: "203.0.113.7", Admin: []string{"192.0.2.7"}})
		if err != nil {
			t.Fatal(err)
		}
		if name == "r1" {
			if bundle, err = node.DecodeRelayBundle(r.Bundle); err != nil {
				t.Fatal(err)
			}
		}
		if !slices.ContainsFunc(r.Ports, func(p *nodev1.RelayPort) bool { return p.Name == "acme" && p.From == 80 && p.Access == "acme" }) {
			t.Errorf("%s: bundle's ports without TCP 80 for the window: %v", name, r.Ports)
		}
	}
	names, err := provision.RelayNames(ctx, srv.Store)
	if err != nil || len(names) != 2 {
		t.Fatalf("relay names %v %v", names, err)
	}
	nameOf := map[string]string{}
	for _, rn := range names {
		nameOf[rn.Relay] = rn.Name
	}

	if srv.RelayACMEForward("r1") {
		t.Fatal("r1 forwards before it said so")
	}
	addr, _ := serveRemoteFrom(t, srv, "198.51.100.20:40000")
	cert, err := DecodeClientCertificate([]byte(bundle.Cert))
	if err != nil {
		t.Fatal(err)
	}
	rev, _ := srv.changes()
	feed := perimeterv1connect.NewRelayServiceClient(remoteHTTP(bundle.API.Pin, cert), "https://"+addr)
	s, err := feed.WatchRelay(ctx, connect.NewRequest(&perimeterv1.WatchRelayRequest{SpaVersions: []uint32{2, 3}, AcmeForward: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.Receive() || s.Msg().Snapshot.AcmeForwardUntil != 0 {
		t.Fatalf("first snapshot: %v %v", s.Msg(), s.Err())
	}
	if again, _ := srv.changes(); !srv.RelayACMEForward("r1") || again == rev {
		t.Fatalf("r1 said it forwards: kept %v, news %v", srv.RelayACMEForward("r1"), again != rev)
	}
	rev, _ = srv.changes()
	srv.setRelayACME("r1", true)
	if again, _ := srv.changes(); again != rev {
		t.Fatal("the same word again is news")
	}

	// An order without r1's names: nothing for it.
	until := time.Now().Add(3 * time.Minute).Truncate(time.Second)
	per := &PerimeterServer{Server: srv}
	srv.SetACMEWindow(18080, until, []string{nameOf["r2"], "site.example.com"})
	if snap, err := per.RelaySnapshot(ctx, "r1"); err != nil || snap.AcmeForwardUntil != 0 {
		t.Fatalf("r1 in an order of r2's names: %v %v", snap.GetAcmeForwardUntil(), err)
	}
	// With them: the feed sends the window's end at once.
	srv.SetACMEWindow(18080, until, []string{nameOf["r1"], "site.example.com"})
	for s.Receive() && s.Msg().Snapshot.AcmeForwardUntil == 0 {
	}
	if got := s.Msg().Snapshot.GetAcmeForwardUntil(); got != until.Unix() {
		t.Fatalf("r1's feed in its window: %d, want %d (%v)", got, until.Unix(), s.Err())
	}
	if snap, err := per.RelaySnapshot(ctx, "r2"); err != nil || snap.AcmeForwardUntil != 0 {
		t.Fatalf("r2 in an order of r1's names: %v %v", snap.GetAcmeForwardUntil(), err)
	}
	// The window closes: the feed says so.
	srv.SetACMEWindow(0, time.Time{}, nil)
	if !s.Receive() || s.Msg().Snapshot.AcmeForwardUntil != 0 {
		t.Fatalf("after the window: %v %v", s.Msg(), s.Err())
	}

	// With a DNS provider: no TCP 80 among the relay's ports (the
	// certificate is a wildcard).
	ports := func() []*nodev1.RelayPort {
		t.Helper()
		r, err := c.ListRelays(ctx, connect.NewRequest(&nodev1.ListRelaysRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.Relays[0].Ports
	}
	acme := func(p *nodev1.RelayPort) bool { return p.Name == "acme" }
	if !slices.ContainsFunc(ports(), acme) {
		t.Fatal("ListRelays without TCP 80 for the window")
	}
	for k, v := range map[string]string{"dns_provider": "cloudflare", "cloudflare_token": "t", "cloudflare_zone": `{"id":"z1","name":"example.com"}`} {
		if err := srv.Store.SetSetting(ctx, k, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	if slices.ContainsFunc(ports(), acme) {
		t.Fatal("TCP 80 for the window with a DNS provider")
	}
}
