package api

import (
	"context"
	"fmt"
	"net/http"
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
// forwards TCP 80, open while the feed is, the word kept after it, a
// change news; while the node's ACME window is open for an order with the
// relay's names, the relay's snapshot carries the window's end, and the
// feed sends it at once, and its close; another relay's snapshot and an
// order without the relay's names have none. The relay's ports list TCP 80
// while the node orders certificates and has no DNS provider, as a port
// the relay does not forward yet until its rayspa said so.
func TestRelayACMEForward(t *testing.T) {
	srv, sock, _ := startServerWith(t, func(s *Server) []func() (string, http.Handler) {
		s.Certificates = true
		return nil
	})
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
		if !slices.ContainsFunc(r.Ports, func(p *nodev1.RelayPort) bool { return p.Name == "acme" && p.From == 80 && p.Access == "acme-old" }) {
			t.Errorf("%s: bundle's ports without TCP 80 not forwarded yet: %v", name, r.Ports)
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

	if said, open := srv.RelayACMEForward("r1"); said || open {
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
	if said, open := srv.RelayACMEForward("r1"); !said || !open {
		t.Fatalf("r1 said it forwards, its feed open: %v %v", said, open)
	}
	if again, _ := srv.changes(); again == rev {
		t.Fatal("r1's word is not news")
	}
	// A second feed of the same word (one ending, a new one): no news.
	rev, _ = srv.changes()
	done := srv.relayACMEFeed("r1", true)
	done()
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
	if !slices.ContainsFunc(ports(), func(p *nodev1.RelayPort) bool { return acme(p) && p.Access == "acme" }) {
		t.Fatal("ListRelays without TCP 80 for the window")
	}
	// The feed gone: the word stays, nothing open.
	s.Close()
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if said, open := srv.RelayACMEForward("r1"); said && !open {
			break
		}
		if time.Now().After(end) {
			t.Fatal("r1's feed still open after it closed")
		}
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

// No TCP 80 for a relay of a node that orders no certificates
// (-acme-directory empty): no window ever opens.
func TestRelayACMEPortNoCertificates(t *testing.T) {
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
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r1", Address: "198.51.100.20"})); err != nil {
		t.Fatal(err)
	}
	r, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: "203.0.113.7", Admin: []string{"192.0.2.7"}})
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(r.Ports, func(p *nodev1.RelayPort) bool { return p.Name == "acme" }) {
		t.Fatalf("TCP 80 on a node without certificates: %v", r.Ports)
	}
}

// Review: the count of a relay's open feeds across a reconnect (a new
// rayspa feed ends the old one), and a downgrade to a rayspa that says no.
// Right before this round too: it guards the count.
func TestRelayACMEFeedCount(t *testing.T) {
	srv, sock, _ := startServerWith(t, func(s *Server) []func() (string, http.Handler) {
		s.Certificates = true
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := provision.Init(ctx, srv.Store, provision.Options{Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	c := NewUnixClient(sock)
	for _, s := range []*nodev1.CreateServiceRequest{{Kind: "api", Name: "api"}, {Kind: "reality", Name: "reality"}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(s)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r1", Address: "198.51.100.20"})); err != nil {
		t.Fatal(err)
	}
	r, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: "203.0.113.7", Admin: []string{"192.0.2.7"}})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := node.DecodeRelayBundle(r.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := DecodeClientCertificate([]byte(bundle.Cert))
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := serveRemoteFrom(t, srv, "198.51.100.20:40000")
	open := func(said bool) *connect.ServerStreamForClient[perimeterv1.WatchRelayResponse] {
		feed := perimeterv1connect.NewRelayServiceClient(remoteHTTP(bundle.API.Pin, cert), "https://"+addr)
		s, err := feed.WatchRelay(ctx, connect.NewRequest(&perimeterv1.WatchRelayRequest{AcmeForward: said}))
		if err != nil {
			t.Fatal(err)
		}
		if !s.Receive() {
			t.Fatal(s.Err())
		}
		return s
	}
	settle := func(wantSaid, wantOpen bool, what string) {
		t.Helper()
		for end := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			said, o := srv.RelayACMEForward("r1")
			if said == wantSaid && o == wantOpen {
				srv.mu.Lock()
				t.Logf("%s: %+v", what, srv.relayACME["r1"])
				srv.mu.Unlock()
				return
			}
			if time.Now().After(end) {
				t.Fatalf("%s: said %v open %v, want %v %v", what, said, o, wantSaid, wantOpen)
			}
		}
	}
	a := open(true)
	settle(true, true, "one feed")
	b := open(true) // ends a
	time.Sleep(300 * time.Millisecond)
	settle(true, true, "reconnected, the old one ended")
	a.Close()
	time.Sleep(200 * time.Millisecond)
	settle(true, true, "the old one closed by its client too")
	b.Close()
	settle(true, false, "all closed")
	// A downgrade: the new rayspa says nothing while the old feed is open.
	a = open(true)
	settle(true, true, "again")
	d := open(false)
	time.Sleep(300 * time.Millisecond)
	settle(false, false, "an older rayspa now")
	d.Close()
	a.Close()
	settle(false, false, "closed")
}

// A downgrade's overlap (review 2): the older rayspa's feed says no while
// the newer one's has not ended yet. The relay forwards TCP 80 no more from
// that word on, not once the newer feed ends.
func TestRelayACMEDowngradeOverlap(t *testing.T) {
	srv := &Server{}
	newer := srv.relayACMEFeed("r1", true)
	if said, open := srv.RelayACMEForward("r1"); !said || !open {
		t.Fatalf("the newer rayspa: %v %v", said, open)
	}
	older := srv.relayACMEFeed("r1", false)
	if said, open := srv.RelayACMEForward("r1"); said || open {
		t.Fatalf("the older rayspa's word, the newer feed still open: said %v, forwards %v", said, open)
	}
	newer()
	older()
	if said, open := srv.RelayACMEForward("r1"); said || open {
		t.Fatalf("both feeds ended: %v %v", said, open)
	}
}
