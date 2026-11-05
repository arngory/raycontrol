package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/summary"
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
func serveRemoteFrom(t *testing.T, srv *Server, from string, with ...func(*Remote)) (string, string) {
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
	for _, f := range with {
		f(r)
	}
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
	// Its probe endpoint (relay-v1 §9.1): the exit keeps the pin of the
	// certificate it gave, on a port clear of the relay's others.
	if b.Probe == nil {
		t.Fatal("a bundle without a probe endpoint")
	}
	probeCert, err := DecodeClientCertificate([]byte(b.Probe.Cert))
	if err != nil {
		t.Fatal(err)
	}
	r1, _ := srv.Store.RelayByName(ctx, "r1")
	rp, _ := provision.RelayParams(ctx, srv.Store, "r1")
	if r1.ProbePin != CertPin(probeCert.Leaf) || r1.ProbePort != b.Probe.Port || b.Probe.Port == 2200 || b.Probe.Port == b.API.Port ||
		int(b.Probe.Port) >= int(rp.PortBase) && int(b.Probe.Port) < int(rp.PortBase)+int(rp.PortRange) {
		t.Fatalf("probe endpoint %d (pin %s), relay %+v, SPA range %d+%d", b.Probe.Port, CertPin(probeCert.Leaf), r1, rp.PortBase, rp.PortRange)
	}
	// SSH cannot move onto it.
	if _, err := c.SetRelayAccess(ctx, connect.NewRequest(&nodev1.SetRelayAccessRequest{Name: "r1", SshPort: uint32(b.Probe.Port)})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("SSH onto the probe endpoint: %v", err)
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
	// A port public now (REALITY open=true) stays a relay port: the relay's
	// flows there are marked, and end with the relay once open is off.
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
	if !has(exit.PublicPorts, "tcp", 443) || !has(exit.RelayPorts, "tcp", 443) || !has(exit.RelayPorts, "udp", 443) {
		t.Fatalf("open REALITY: public %v, relay ports %v", exit.PublicPorts, exit.RelayPorts)
	}
}

// A relay passes on its devices' reports (relay-v1 §9.3): about a /24 or a
// /48, for a device it knows, from its own address with its certificate;
// the summary's refusals come back as codes the relay can answer with.
func TestRelayReport(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := NewUnixClient(sock)
	for _, s := range []*nodev1.CreateServiceRequest{
		{Kind: "api", Name: "api"},
		{Kind: "reality", Name: "reality", SettingsJson: `{"target":"www.example.org:443"}`},
	} {
		if _, err := c.CreateService(ctx, connect.NewRequest(s)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"reality"}})); err != nil {
		t.Fatal(err)
	}
	dev, _, err := srv.Store.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	gone, _, _ := srv.Store.CreateDevice(ctx, "alice", "old", "user")
	if err := srv.Store.RevokeDevice(ctx, gone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r1", Address: "198.51.100.20"})); err != nil {
		t.Fatal(err)
	}
	enc, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: "203.0.113.7", Admin: []string{"192.0.2.7"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := node.DecodeRelayBundle(enc.Bundle)
	cert, _ := DecodeClientCertificate([]byte(b.Cert))

	type call struct {
		device  string
		network netip.Prefix
		body    string
	}
	var (
		mu      sync.Mutex
		calls   []call
		answer  error
		block   chan struct{}
		entered = make(chan struct{}, 16)
	)
	take := func(_ context.Context, device string, network netip.Prefix, body io.Reader) error {
		b, _ := io.ReadAll(body)
		mu.Lock()
		calls = append(calls, call{device, network, string(b)})
		err, wait := answer, block
		mu.Unlock()
		if wait != nil {
			entered <- struct{}{}
			<-wait
		}
		return err
	}
	addr, _ := serveRemoteFrom(t, srv, "198.51.100.20:40000", func(r *Remote) { r.RelayReport = take })
	feed := perimeterv1connect.NewRelayServiceClient(remoteHTTP(b.API.Pin, cert), "https://"+addr)
	report := func(device, network, body string) error {
		_, err := feed.Report(ctx, connect.NewRequest(&perimeterv1.ReportRequest{Device: device, Network: network, Body: []byte(body)}))
		return err
	}

	if err := report(dev.ID, "203.0.113.0/24", `{"v":1}`); err != nil {
		t.Fatal(err)
	}
	if err := report(dev.ID, "2001:db8:5::/48", `{"v":1}`); err != nil {
		t.Fatal(err)
	}
	want := []call{{dev.ID, netip.MustParsePrefix("203.0.113.0/24"), `{"v":1}`}, {dev.ID, netip.MustParsePrefix("2001:db8:5::/48"), `{"v":1}`}}
	if !slices.Equal(calls, want) {
		t.Fatalf("taken %v", calls)
	}

	for name, c := range map[string]struct {
		device, network, body string
		code                  connect.Code
	}{
		"an address":             {dev.ID, "203.0.113.7/32", "{}", connect.CodeInvalidArgument},
		"an address as a /24":    {dev.ID, "203.0.113.7/24", "{}", connect.CodeInvalidArgument},
		"a /23":                  {dev.ID, "203.0.112.0/23", "{}", connect.CodeInvalidArgument},
		"a /64":                  {dev.ID, "2001:db8:5::/64", "{}", connect.CodeInvalidArgument},
		"loopback":               {dev.ID, "127.0.0.0/24", "{}", connect.CodeInvalidArgument},
		"IPv4 in IPv6":           {dev.ID, "::ffff:203.0.113.0/120", "{}", connect.CodeInvalidArgument},
		"no network":             {dev.ID, "", "{}", connect.CodeInvalidArgument},
		"a body over the limit":  {dev.ID, "203.0.113.0/24", strings.Repeat(" ", summary.MaxBody+1), connect.CodeInvalidArgument},
		"a device it never knew": {"nope", "203.0.113.0/24", "{}", connect.CodePermissionDenied},
		"a revoked device":       {gone.ID, "203.0.113.0/24", "{}", connect.CodePermissionDenied},
	} {
		if err := report(c.device, c.network, c.body); connect.CodeOf(err) != c.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(calls) != 2 {
		t.Fatalf("refused reports reached the summary: %v", calls[2:])
	}

	// The summary's refusals.
	for err, code := range map[error]connect.Code{
		summary.ErrDisabled:                     connect.CodeFailedPrecondition,
		summary.ErrRepeated:                     connect.CodeResourceExhausted,
		fmt.Errorf("%w: x", summary.ErrInvalid): connect.CodeInvalidArgument,
		store.ErrNotFound:                       connect.CodePermissionDenied,
		errors.New("disk full"):                 connect.CodeInternal,
	} {
		mu.Lock()
		answer = err
		mu.Unlock()
		if got := report(dev.ID, "203.0.113.0/24", "{}"); connect.CodeOf(got) != code || code == connect.CodeInternal && strings.Contains(got.Error(), "disk") {
			t.Errorf("%v: %v", err, got)
		}
	}
	mu.Lock()
	answer = nil
	mu.Unlock()

	// At most four at once from one relay.
	mu.Lock()
	block = make(chan struct{})
	mu.Unlock()
	var wg sync.WaitGroup
	for range maxRelayReports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := report(dev.ID, "203.0.113.0/24", "{}"); err != nil {
				t.Error(err)
			}
		}()
	}
	for range maxRelayReports {
		<-entered
	}
	if err := report(dev.ID, "203.0.113.0/24", "{}"); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a fifth at once: %v", err)
	}
	mu.Lock()
	close(block)
	block = nil
	mu.Unlock()
	wg.Wait()
	if err := report(dev.ID, "203.0.113.0/24", "{}"); err != nil {
		t.Errorf("after the others: %v", err)
	}

	// The certificate from another address; a node without the summary.
	other, _ := serveRemoteFrom(t, srv, "198.51.100.99:40000", func(r *Remote) { r.RelayReport = take })
	stranger := perimeterv1connect.NewRelayServiceClient(remoteHTTP(b.API.Pin, cert), "https://"+other)
	if _, err := stranger.Report(ctx, connect.NewRequest(&perimeterv1.ReportRequest{Device: dev.ID, Network: "203.0.113.0/24", Body: []byte("{}")})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("from another address: %v", err)
	}
	plain, _ := serveRemoteFrom(t, srv, "198.51.100.20:40000")
	without := perimeterv1connect.NewRelayServiceClient(remoteHTTP(b.API.Pin, cert), "https://"+plain)
	if _, err := without.Report(ctx, connect.NewRequest(&perimeterv1.ReportRequest{Device: dev.ID, Network: "203.0.113.0/24", Body: []byte("{}")})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("without the summary: %v", err)
	}
}

// The subscription lists a relay's probe endpoint while its rayd relay is
// there (relay-v1 §9.2): while its feed is open, and a while after for a
// reconnect; rayspa's feed does not count.
func TestRelayProbeUp(t *testing.T) {
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
	var (
		mu  sync.Mutex
		now = time.Now()
		r   *Remote
	)
	addr, _ := serveRemoteFrom(t, srv, "198.51.100.20:40000", func(rr *Remote) {
		r = rr
		rr.now = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}
	})
	cert, _ := DecodeClientCertificate([]byte(b.Cert))
	feed := perimeterv1connect.NewRelayServiceClient(remoteHTTP(b.API.Pin, cert), "https://"+addr)
	open := func(probe bool) *connect.ServerStreamForClient[perimeterv1.WatchRelayResponse] {
		t.Helper()
		s, err := feed.WatchRelay(ctx, connect.NewRequest(&perimeterv1.WatchRelayRequest{Probe: probe}))
		if err != nil || !s.Receive() {
			t.Fatalf("feed: %v %v", err, s.Err())
		}
		return s
	}
	waitFor := func(want bool) {
		t.Helper()
		for range 100 {
			if r.RelayProbeUp("r1") == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("probe up: want %v", want)
	}
	rayspa := open(false)
	if r.RelayProbeUp("r1") {
		t.Fatal("rayspa's feed taken for rayd relay's")
	}
	rayd := open(true)
	if !r.RelayProbeUp("r1") || r.RelayProbeUp("r2") {
		t.Fatal("rayd relay's feed not seen, or seen for another relay")
	}
	rayd.Close()
	for range 100 {
		r.relayMu.Lock()
		n := r.relayProbes["r1"]
		r.relayMu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Gone a moment ago: still listed, for a reconnect.
	if !r.RelayProbeUp("r1") {
		t.Fatal("rayd relay dropped at once, with no time to reconnect")
	}
	mu.Lock()
	now = now.Add(relayProbeGrace + time.Second)
	mu.Unlock()
	waitFor(false)
	rayspa.Close()
}
