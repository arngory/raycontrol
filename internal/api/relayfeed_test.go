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
	"github.com/arngory/raycontrol/internal/nodeupdate"
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
		// A zone is any text after "%"; the relay's rayspa would write it
		// into nft (node.DecodeRelayBundle refuses it there too).
		"an exit with a zone":     {Name: "r1", ExitAddress: "::ffff:203.0.113.7%x\nflush ruleset", Admin: []string{"192.0.2.7"}},
		"nobody for its SSH":      {Name: "r2", ExitAddress: "203.0.113.7"},
		"SSH on a forwarded port": {Name: "r1", ExitAddress: "203.0.113.7", Admin: []string{"192.0.2.7"}, SshPort: uint32(apiSvc.endpoint.Port)},
		"a wide admin prefix":     {Name: "r1", ExitAddress: "203.0.113.7", Admin: []string{"192.0.0.0/8"}},
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
	watch := func(probe bool) *connect.ServerStreamForClient[perimeterv1.WatchRelayResponse] {
		t.Helper()
		s, err := feed.WatchRelay(ctx, connect.NewRequest(&perimeterv1.WatchRelayRequest{Probe: probe}))
		if err != nil || !s.Receive() {
			t.Fatalf("feed (probe %v): %v %v", probe, err, s.Err())
		}
		return s
	}
	// rayspa's feed and rayd relay's, side by side.
	old, probe := watch(false), watch(true)
	// A relay that restarted leaves its old connection up on the exit
	// (its FIN dropped by its perimeter going down): its new feed of the
	// same kind ends the old one, it is not refused.
	fresh := watch(false)
	ended := make(chan bool, 1)
	go func() { ended <- !old.Receive() }()
	select {
	case gone := <-ended:
		if !gone {
			t.Fatal("the old feed got a message after a new one of its kind")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the old feed of the kind is still open")
	}
	// The other kind stays, and so does the new one: neither ends.
	gone := make(chan string, 2)
	for name, s := range map[string]*connect.ServerStreamForClient[perimeterv1.WatchRelayResponse]{"probe": probe, "new": fresh} {
		go func() {
			for s.Receive() {
			}
			gone <- name
		}()
	}
	select {
	case name := <-gone:
		t.Fatalf("the %s feed ended", name)
	case <-time.After(time.Second):
	}
	probe.Close()
	fresh.Close()
}

// Only streams still ending fill a relay's place: too many of them at once
// are refused, a new one of a kind ends the open ones of that kind.
func TestAdmitRelayStream(t *testing.T) {
	var r Remote
	ended := map[int]int{}
	stream := func(i int, probe bool) *relayStream {
		return &relayStream{probe: probe, end: func() { ended[i]++ }}
	}
	s0, s1 := stream(0, false), stream(1, true)
	if !r.admitRelayStream("r1", s0) || !r.admitRelayStream("r1", s1) || len(ended) != 0 {
		t.Fatalf("rayspa's and rayd relay's: %v", ended)
	}
	s2 := stream(2, false)
	if !r.admitRelayStream("r1", s2) || ended[0] != 1 || ended[1] != 0 {
		t.Fatalf("a new rayspa feed: ended %v", ended)
	}
	// s0 has not returned yet (its connection is half dead): one more.
	if !r.admitRelayStream("r1", stream(3, false)) {
		t.Fatal("a fourth stream refused")
	}
	if r.admitRelayStream("r1", stream(4, true)) {
		t.Fatalf("a fifth stream at once admitted: %d open", len(r.relayStreams["r1"]))
	}
	if !r.admitRelayStream("r2", stream(5, true)) {
		t.Fatal("another relay's stream refused")
	}
	r.dropRelayStream("r1", s0)
	r.dropRelayStream("r1", s2)
	if !r.admitRelayStream("r1", stream(6, true)) || ended[1] != 1 {
		t.Fatalf("after two ended: %v", ended)
	}
	for _, s := range slices.Clone(r.relayStreams["r1"]) {
		r.dropRelayStream("r1", s)
	}
	if _, ok := r.relayStreams["r1"]; ok {
		t.Fatal("a relay with no stream is still listed")
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
	if _, err := srv.Store.RevokeDevice(ctx, gone.ID); err != nil {
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
		"shared address space":   {dev.ID, "100.64.1.0/24", "{}", connect.CodeInvalidArgument},
		"reserved":               {dev.ID, "240.0.0.0/24", "{}", connect.CodeInvalidArgument},
		"private":                {dev.ID, "10.1.2.0/24", "{}", connect.CodeInvalidArgument},
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
	// Its word on its updates, beside (spec/relay-update-remote-v1.md
	// §3.2): its own bounds, none of the summary's.
	if _, err := feed.ReportUpdate(ctx, connect.NewRequest(&perimeterv1.ReportUpdateRequest{Update: &perimeterv1.RelayUpdate{State: "idle"}})); err != nil {
		t.Errorf("an update report: %v", err)
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
	// Just started: a relay's rayd relay may be reconnecting.
	if !r.RelayProbeUp("r1") {
		t.Fatal("no grace after the node's start")
	}
	mu.Lock()
	now = now.Add(relayProbeGrace + time.Second)
	mu.Unlock()
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

// A relay forgets its devices when the exit says it does not know the
// relay, so only the store's "no such relay" may say that: a store that
// failed for a moment is the exit away.
func TestRelayLookup(t *testing.T) {
	if got := connect.CodeOf(relayLookup(store.ErrNotFound)); got != connect.CodeNotFound {
		t.Errorf("no such relay: %v", got)
	}
	if got := connect.CodeOf(relayLookup(fmt.Errorf("listing relays: %w", store.ErrNotFound))); got != connect.CodeNotFound {
		t.Errorf("no such relay, wrapped: %v", got)
	}
	for _, err := range []error{errors.New("database is locked"), context.DeadlineExceeded, store.ErrInvalid} {
		got := relayLookup(err)
		if connect.CodeOf(got) != connect.CodeUnavailable {
			t.Errorf("%v: %v, want unavailable", err, connect.CodeOf(got))
		}
		if strings.Contains(got.Error(), err.Error()) {
			t.Errorf("%v: the store's words reach the relay: %v", err, got)
		}
	}
}

// feedMsgs follows a relay's feed: its answers as they come.
func feedMsgs(ctx context.Context, t *testing.T, b node.RelayBundle, addr string, req *perimeterv1.WatchRelayRequest) <-chan *perimeterv1.WatchRelayResponse {
	t.Helper()
	cert, err := DecodeClientCertificate([]byte(b.Cert))
	if err != nil {
		t.Fatal(err)
	}
	s, err := perimeterv1connect.NewRelayServiceClient(remoteHTTP(b.API.Pin, cert), "https://"+addr).WatchRelay(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan *perimeterv1.WatchRelayResponse, 16)
	go func() {
		defer close(out)
		for s.Receive() {
			out <- s.Msg()
		}
	}()
	t.Cleanup(func() { s.Close() })
	return out
}

// nextMsg is the feed's next answer, within a while.
func nextMsg(t *testing.T, msgs <-chan *perimeterv1.WatchRelayResponse, what string) *perimeterv1.WatchRelayResponse {
	t.Helper()
	select {
	case m, ok := <-msgs:
		if !ok {
			t.Fatalf("%s: the feed ended", what)
		}
		return m
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: nothing", what)
	}
	return nil
}

// quiet checks that the feeds send nothing for a while: over several of
// their looks, every 50 ms here.
func quiet(t *testing.T, what string, feeds ...<-chan *perimeterv1.WatchRelayResponse) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	for i, msgs := range feeds {
		select {
		case m := <-msgs:
			t.Errorf("%s: feed %d sent %v", what, i, m)
		default:
		}
	}
}

// The exit names its release to its relays in the feeds with updates only
// (spec/relay-update-remote-v1.md §3.2-§3.3), one relay at a time; a change
// of the offer is a new answer in the feeds it changes and in no other, and
// rayspa's feed, or an older rayd relay's, sends what it always did.
func TestRelayFeedOffer(t *testing.T) {
	srv, bundles, _, now, _ := relayNode(t, "v0.28.0", "r1", "r2")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fast := func(r *Remote) { r.Perimeter.Refresh = 50 * time.Millisecond }
	at1, _ := serveRemoteFrom(t, srv, "198.51.100.20:40000", fast)
	at2, _ := serveRemoteFrom(t, srv, "198.51.100.21:40000", fast)
	st := nodeupdate.Status{ID: "6f1c0e2a9b3d4c5e", State: nodeupdate.Done, From: "v0.27.0", To: "v0.28.0", Kind: nodeupdate.Remote, Ended: now()}
	if err := nodeupdate.WriteStatus(srv.NodeUpdate.Status, st); err != nil {
		t.Fatal(err)
	}
	want := func(m *perimeterv1.WatchRelayResponse, offer bool, what string) {
		t.Helper()
		if m.Snapshot == nil || (m.Update != nil) != offer || offer && (m.Update.Id != st.ID || m.Update.Version != "v0.28.0" || m.Update.EndedAt != st.Ended.Unix()) {
			t.Fatalf("%s: %v", what, m)
		}
	}
	rayspa1 := feedMsgs(ctx, t, bundles["r1"], at1, &perimeterv1.WatchRelayRequest{})
	want(nextMsg(t, rayspa1, "r1's rayspa"), false, "r1's rayspa")
	probe1 := feedMsgs(ctx, t, bundles["r1"], at1, &perimeterv1.WatchRelayRequest{Probe: true, Updates: true})
	want(nextMsg(t, probe1, "r1's rayd relay"), true, "r1's rayd relay")
	// An older rayd relay (no updates) on r2: it never has one, and r2
	// never reported, so r2 is not waited for.
	old2 := feedMsgs(ctx, t, bundles["r2"], at2, &perimeterv1.WatchRelayRequest{Probe: true})
	want(nextMsg(t, old2, "r2's older rayd relay"), false, "r2's older rayd relay")
	// r2's newer one waits for r1, which has not said a word yet.
	probe2 := feedMsgs(ctx, t, bundles["r2"], at2, &perimeterv1.WatchRelayRequest{Probe: true, Updates: true})
	want(nextMsg(t, probe2, "r2's rayd relay"), false, "r2's rayd relay")
	quiet(t, "nothing changed", rayspa1, probe1, old2, probe2)

	// r1 is done: r2's turn, a new answer in r2's feed only.
	setRecord(t, srv, "r1", relayRecord{Reported: nodeupdate.Done, UpdateID: st.ID, Target: "v0.28.0", Version: "v0.28.0", Remote: true, ChangedAt: now().Unix()})
	srv.kickRelayFeeds(ctx)
	want(nextMsg(t, probe2, "r2 after r1"), true, "r2 after r1")
	quiet(t, "r1 done", rayspa1, probe1, old2, probe2)

	// Another update asked for: no offer while it waits.
	if err := nodeupdate.WriteRequest(srv.NodeUpdate.Request, nodeupdate.Request{ID: "ab", Kind: nodeupdate.Remote, Version: "latest", By: "x", At: now()}, now()); err != nil {
		t.Fatal(err)
	}
	want(nextMsg(t, probe1, "r1, busy"), false, "r1, busy")
	want(nextMsg(t, probe2, "r2, busy"), false, "r2, busy")
	quiet(t, "busy", rayspa1, probe1, old2, probe2)
	if err := os.Remove(srv.NodeUpdate.Request); err != nil {
		t.Fatal(err)
	}
	want(nextMsg(t, probe1, "r1, again"), true, "r1, again")
	want(nextMsg(t, probe2, "r2, again"), true, "r2, again")
	quiet(t, "again", rayspa1, probe1, old2, probe2)

	// The node does not run what the update put in (another rayd installed
	// by hand since): it names nothing.
	other := st
	other.To = "v0.28.1"
	if err := nodeupdate.WriteStatus(srv.NodeUpdate.Status, other); err != nil {
		t.Fatal(err)
	}
	want(nextMsg(t, probe1, "r1, by hand"), false, "r1, by hand")
	want(nextMsg(t, probe2, "r2, by hand"), false, "r2, by hand")
	quiet(t, "by hand", rayspa1, probe1, old2, probe2)
}

// A relay given its turn holds the others back; its feed's going and
// coming moves the queue for a relay that never reported, and wakes only
// the feeds whose answer it changes.
func TestRelayFeedTurn(t *testing.T) {
	srv, bundles, advance, now, _ := relayNode(t, "v0.28.0", "r1", "r2", "r3")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	at := map[string]string{}
	for i, name := range []string{"r1", "r2", "r3"} {
		at[name], _ = serveRemoteFrom(t, srv, fmt.Sprintf("198.51.100.%d:40000", 20+i))
	}
	st := nodeupdate.Status{ID: "6f1c0e2a9b3d4c5e", State: nodeupdate.Done, From: "v0.27.0", To: "v0.28.0", Kind: nodeupdate.Local, Ended: now()}
	nodeupdate.WriteStatus(srv.NodeUpdate.Status, st)
	feed := func(name string) (<-chan *perimeterv1.WatchRelayResponse, context.CancelFunc) {
		fctx, fcancel := context.WithCancel(ctx)
		return feedMsgs(fctx, t, bundles[name], at[name], &perimeterv1.WatchRelayRequest{Probe: true, Updates: true}), fcancel
	}
	has := func(m *perimeterv1.WatchRelayResponse) bool { return m.Update != nil && m.Update.Id == st.ID }
	// r2 and r3 come first; r1 never reported and has no feed: r2's turn.
	f2, _ := feed("r2")
	if !has(nextMsg(t, f2, "r2")) {
		t.Fatal("r2 waits for a relay never heard of")
	}
	f3, _ := feed("r3")
	if has(nextMsg(t, f3, "r3")) {
		t.Fatal("r3 at once with r2")
	}
	// r1's newer rayd relay comes: it waits for r2, which holds its turn,
	// and nothing else changes.
	f1, close1 := feed("r1")
	if has(nextMsg(t, f1, "r1")) {
		t.Fatal("r1 before r2 ended")
	}
	quiet(t, "r1 came", f1, f2, f3)
	// r2's turn times out: r1's comes, the first by name, and r2's offer
	// goes with it.
	advance(TurnTimeout + time.Second)
	srv.kickRelayFeeds(ctx)
	if !has(nextMsg(t, f1, "r1 after r2's turn")) {
		t.Fatal("r1 after r2's turn")
	}
	if has(nextMsg(t, f2, "r2 after its turn")) {
		t.Fatal("r2 keeps the offer while r1 updates")
	}
	quiet(t, "r1's turn", f1, f2, f3)
	// r1 reports nothing and its feed goes (its rayd relay restarts): it
	// keeps its turn.
	close1()
	quiet(t, "r1 away", f2, f3)
}
