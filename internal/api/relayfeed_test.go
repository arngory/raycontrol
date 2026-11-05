package api

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// fromListener makes every connection look as if it came from one address,
// as the relay's would.
type fromListener struct {
	net.Listener
	from net.Addr
}

type fromConn struct {
	net.Conn
	from net.Addr
}

func (c fromConn) RemoteAddr() net.Addr { return c.from }

func (l fromListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return fromConn{c, l.from}, nil
}

// serveRemoteFrom serves srv's remote API, with relays, to connections that
// come from the given address.
func serveRemoteFrom(t *testing.T, srv *Server, from string) (string, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	svc, _ := srv.Store.ServiceByName(ctx, "api")
	secrets, _ := srv.Store.ServiceSecrets(ctx, svc.ID)
	cfg, err := RemoteTLSConfig(secrets[provision.SecretTLSCert], secrets[provision.SecretTLSKey])
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := provision.SPKIPin(secrets[provision.SecretTLSCert])
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &Remote{Server: srv, Log: slog.New(slog.DiscardHandler),
		Perimeter: &PerimeterServer{Server: srv, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour, Refresh: time.Minute}}
	done := make(chan error, 1)
	go func() {
		done <- r.Serve(ctx, fromListener{ln, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(from))}, cfg)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ln.Addr().String(), pin
}

// A relay takes its perimeter from the exit's API with the certificate of
// its bundle, from its own address; a new bundle cuts the old one off, and
// nobody else gets anything.
func TestRelayFeed(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r1", Address: "198.51.100.20"})); err != nil {
		t.Fatal(err)
	}
	// Root only: the bundle holds the relay's key.
	_, err := c.IssueRelayBundle(ctx, connect.NewRequest(&nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: "203.0.113.7", Admin: []string{"192.0.2.7"}}))
	if (os.Getuid() == 0) != (err == nil) || os.Getuid() != 0 && connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("bundle as uid %d: %v", os.Getuid(), err)
	}
	// A relay with no admin addresses yet, on a node without SSH as a
	// service; and the API's port, which relays forward.
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r2", Address: "198.51.100.21"})); err != nil {
		t.Fatal(err)
	}
	apiSvc, _ := srv.apiEndpoint(ctx)
	for name, req := range map[string]*nodev1.IssueRelayBundleRequest{
		"a name for the exit":       {Name: "r1", ExitAddress: "exit.example.com", Admin: []string{"192.0.2.7"}},
		"an exit of another family": {Name: "r1", ExitAddress: "2001:db8::7", Admin: []string{"192.0.2.7"}},
		"nobody for its SSH":        {Name: "r2", ExitAddress: "203.0.113.7"},
		"SSH on a forwarded port":   {Name: "r1", ExitAddress: "203.0.113.7", Admin: []string{"192.0.2.7"}, SshPort: uint32(apiSvc.endpoint.Port)},
		"a wide admin prefix":       {Name: "r1", ExitAddress: "203.0.113.7", Admin: []string{"192.0.0.0/8"}},
	} {
		if _, err := srv.issueRelayBundle(ctx, req); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("bundle with %s: %v", name, err)
		}
	}
	issue := func() node.RelayBundle {
		t.Helper()
		r, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: "203.0.113.7", SshPort: 2200,
			Admin: []string{"192.0.2.7"}})
		if err != nil {
			t.Fatal(err)
		}
		b, err := node.DecodeRelayBundle(r.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b := issue()
	if b.Name != "r1" || b.Exit != netip.MustParseAddr("203.0.113.7") || b.API.Port == 0 {
		t.Fatalf("bundle %+v", b)
	}
	addr, pin := serveRemoteFrom(t, srv, "198.51.100.20:40000")
	if pin != b.API.Pin {
		t.Fatalf("bundle pin %s, the API's %s", b.API.Pin, pin)
	}
	watch := func(bundle node.RelayBundle, at string) *connect.ServerStreamForClient[perimeterv1.WatchRelayResponse] {
		t.Helper()
		cert, err := DecodeClientCertificate([]byte(bundle.Cert))
		if err != nil {
			t.Fatal(err)
		}
		feed := perimeterv1connect.NewRelayServiceClient(remoteHTTP(bundle.API.Pin, cert), "https://"+at)
		s, err := feed.WatchRelay(ctx, connect.NewRequest(&perimeterv1.WatchRelayRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := watch(b, addr)
	if !s.Receive() {
		t.Fatalf("no relay snapshot: %v", s.Err())
	}
	params, _ := provision.RelayParams(ctx, srv.Store, "r1")
	snap := s.Msg().Snapshot
	if string(snap.Spa.NodeId) != string(params.NodeID[:]) || len(snap.AdminPorts) != 1 || snap.AdminPorts[0].Port != 2200 {
		t.Fatalf("relay snapshot %v", snap)
	}

	// A new bundle: the old certificate is cut off at the next change.
	b2 := issue()
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "bob"})); err != nil {
		t.Fatal(err)
	}
	for s.Receive() {
	}
	if connect.CodeOf(s.Err()) != connect.CodeNotFound {
		t.Fatalf("old certificate after a new bundle: %v", s.Err())
	}
	s.Close()
	s2 := watch(b2, addr)
	if !s2.Receive() {
		t.Fatalf("new bundle: %v", s2.Err())
	}
	// A new bundle is a new SPA for the relay, and so new device keys there.
	if again := s2.Msg().Snapshot; string(again.Spa.NodeId) == string(snap.Spa.NodeId) ||
		len(again.Devices) > 0 && len(snap.Devices) > 0 && string(again.Devices[0].Key) == string(snap.Devices[0].Key) {
		t.Fatal("the relay kept its SPA and keys across a new bundle")
	}
	s2.Close()

	// The right certificate from another address, and the old one: nothing.
	other, _ := serveRemoteFrom(t, srv, "198.51.100.99:40000")
	for _, c := range []struct {
		b  node.RelayBundle
		at string
	}{{b2, other}, {b, addr}} {
		s := watch(c.b, c.at)
		if s.Receive() || connect.CodeOf(s.Err()) != connect.CodeNotFound {
			t.Fatalf("watch from %s: %v", c.at, s.Err())
		}
		s.Close()
	}
}

// One relay gets at most two feeds at once.
func TestRelayFeedStreams(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := NewUnixClient(sock)
	c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"}))
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r1", Address: "198.51.100.20"})); err != nil {
		t.Fatal(err)
	}
	enc, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: "203.0.113.7", Admin: []string{"192.0.2.7"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := node.DecodeRelayBundle(enc.Bundle)
	addr, _ := serveRemoteFrom(t, srv, "198.51.100.20:40000")
	cert, _ := DecodeClientCertificate([]byte(b.Cert))
	feed := perimeterv1connect.NewRelayServiceClient(remoteHTTP(b.API.Pin, cert), "https://"+addr)
	var open []*connect.ServerStreamForClient[perimeterv1.WatchRelayResponse]
	for range 2 {
		s, err := feed.WatchRelay(ctx, connect.NewRequest(&perimeterv1.WatchRelayRequest{}))
		if err != nil || !s.Receive() {
			t.Fatalf("feed: %v %v", err, s.Err())
		}
		open = append(open, s)
	}
	s, _ := feed.WatchRelay(ctx, connect.NewRequest(&perimeterv1.WatchRelayRequest{}))
	if s.Receive() || connect.CodeOf(s.Err()) != connect.CodeResourceExhausted {
		t.Fatalf("a third feed: %v", s.Err())
	}
	open[0].Close()
	time.Sleep(200 * time.Millisecond)
	s, _ = feed.WatchRelay(ctx, connect.NewRequest(&perimeterv1.WatchRelayRequest{}))
	if !s.Receive() {
		t.Fatalf("a feed after one closed: %v", s.Err())
	}
}

// A refused bundle changes nothing of the relay; SetRelayAccess changes its
// SSH access and nothing else; a relay host is IPv4 for now.
func TestRelayAccess(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"}))
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r1", Address: "198.51.100.20"})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r6", Address: "2001:db8::20"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("an IPv6 relay added: %v", err)
	}
	// One an older version added.
	if _, err := srv.Store.CreateRelay(ctx, "r6", netip.MustParseAddr("2001:db8::20")); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: "r6", ExitAddress: "2001:db8::7", Admin: []string{"192.0.2.7"}}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("an IPv6 relay: %v", err)
	}
	// It cannot be a relay, so its address reaches nothing.
	if snap, err := (&PerimeterServer{Server: srv}).snapshot(ctx); err != nil || !slices.Equal(snap.RelayPrefixes, []string{"198.51.100.20/32"}) {
		t.Fatalf("relay prefixes %v %v", snap.GetRelayPrefixes(), err)
	}
	// rayctl's default admin list (its SSH session) only for a relay that
	// has none yet; a new bundle keeps the list the relay has.
	for i, want := range []struct {
		ifNone, admin string
		kept          bool
	}{{"192.0.2.7", "192.0.2.7/32", false}, {"192.0.2.99", "192.0.2.7/32", true}} {
		r, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: "203.0.113.7", AdminIfNone: []string{want.ifNone}})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(r.Admin, []string{want.admin}) || r.AdminKept != want.kept || r.SshPort != 22 {
			t.Fatalf("bundle %d: admin %v, kept %v, ssh %d", i, r.Admin, r.AdminKept, r.SshPort)
		}
	}
	before, _ := srv.Store.RelayByName(ctx, "r1")
	apiSvc, _ := srv.apiEndpoint(ctx)
	if _, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: "203.0.113.7", Admin: []string{"192.0.2.8"},
		SshPort: uint32(apiSvc.endpoint.Port)}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("SSH on a forwarded port: %v", err)
	}
	if after, _ := srv.Store.RelayByName(ctx, "r1"); string(after.SPA) != string(before.SPA) || after.CertPin != before.CertPin ||
		after.SSHPort != before.SSHPort || !slices.Equal(after.Admin, before.Admin) {
		t.Fatalf("a refused bundle changed the relay: %+v -> %+v", before, after)
	}
	if _, err := c.SetRelayAccess(ctx, connect.NewRequest(&nodev1.SetRelayAccessRequest{Name: "r1", SshPort: 2200, Admin: []string{"203.0.113.9"}})); err != nil {
		t.Fatal(err)
	}
	after, _ := srv.Store.RelayByName(ctx, "r1")
	if string(after.SPA) != string(before.SPA) || after.CertPin != before.CertPin || after.SSHPort != 2200 || !slices.Equal(after.Admin, []string{"203.0.113.9/32"}) {
		t.Fatalf("SetRelayAccess: %+v", after)
	}
	if _, err := c.SetRelayAccess(ctx, connect.NewRequest(&nodev1.SetRelayAccessRequest{Name: "r1", SshPort: uint32(apiSvc.endpoint.Port)})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("SetRelayAccess to a forwarded port: %v", err)
	}
	per := &PerimeterServer{Server: srv, DefaultTTL: time.Minute, MaxTTL: time.Hour}
	snap, err := per.RelaySnapshot(ctx, "r1")
	if err != nil || !slices.Equal(snap.AdminPrefixes, []string{"203.0.113.9/32"}) || snap.AdminPorts[0].Port != 2200 {
		t.Fatalf("relay snapshot after SetRelayAccess: %v %v", snap, err)
	}
	// A port public anyway (REALITY open=true) is no relay port at the exit:
	// the relay's flows there are nobody's to cut.
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "reality",
		SettingsJson: `{"target":"www.example.org:443","ports":["tcp/443","udp/443"],"open":true}`})); err != nil {
		t.Fatal(err)
	}
	exit, err := per.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	has := func(ports []*perimeterv1.Port, proto string, n uint32) bool {
		return slices.ContainsFunc(ports, func(p *perimeterv1.Port) bool { return p.Proto == proto && p.Port == n })
	}
	if !has(exit.PublicPorts, "tcp", 443) || has(exit.RelayPorts, "tcp", 443) || !has(exit.RelayPorts, "udp", 443) {
		t.Fatalf("open REALITY: public %v, relay ports %v", exit.PublicPorts, exit.RelayPorts)
	}
}
