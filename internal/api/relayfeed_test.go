package api

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
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
	if _, err := c.IssueRelayBundle(ctx, connect.NewRequest(&nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: "exit.example.com"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a bundle with a name for the exit: %v", err)
	}
	issue := func() node.RelayBundle {
		t.Helper()
		r, err := c.IssueRelayBundle(ctx, connect.NewRequest(&nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: "203.0.113.7", SshPort: 2200}))
		if err != nil {
			t.Fatal(err)
		}
		b, err := node.DecodeRelayBundle(r.Msg.Bundle)
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
