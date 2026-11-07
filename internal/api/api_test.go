package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"

	"github.com/arngory/raycontrol/internal/cloudflare/cftest"
	"github.com/arngory/raycontrol/internal/dnscheck"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

func startServer(t *testing.T) (*Server, string, *atomic.Int32) {
	t.Helper()
	return startServerWith(t, nil)
}

func startServerWith(t *testing.T, extra func(*Server) []func() (string, http.Handler)) (*Server, string, *atomic.Int32) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	params, err := provision.Init(ctx, st, provision.Options{Host: "n.example.com", Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	var changes atomic.Int32
	srv := &Server{Store: st, Params: params, Version: "test", OnChange: func() { changes.Add(1) }}
	sock := filepath.Join(dir, "rayd.sock")
	done := make(chan error, 1)
	var handlers []func() (string, http.Handler)
	if extra != nil {
		handlers = extra(srv)
	}
	go func() { done <- srv.ServeUnix(ctx, sock, PeerPolicy{}, handlers...) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		st.Close()
	})
	for range 100 {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return srv, sock, &changes
}

func TestEnrollAndPassSPA(t *testing.T) {
	srv, sock, changes := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)

	for _, svc := range [][3]string{{"reality", "reality", `{"target":"www.example.org:443"}`}, {"dnstt", "dns", ""}, {"ssh", "ssh", ""}, {"hy2-masq", "hy2", ""}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: svc[0], Name: svc[1], SettingsJson: svc[2]})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"reality", "dns", "hy2"}})); err != nil {
		t.Fatal(err)
	}
	dev, err := c.CreateDevice(ctx, connect.NewRequest(&nodev1.CreateDeviceRequest{User: "alice", Name: "phone"}))
	if err != nil {
		t.Fatal(err)
	}

	b, err := node.DecodeBundle(dev.Msg.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if b.Host != "n.example.com" || b.DeviceID != dev.Msg.Device.Id || len(b.Services) != 3 {
		t.Fatalf("bundle = %+v", b)
	}
	for _, s := range b.Services {
		rotates := len(s.PortKey) == 64 && s.PortRange >= 1024
		if rotates != (s.Kind == "hy2-masq") {
			t.Fatalf("rotation of %s: %+v", s.Kind, s)
		}
	}
	if b.Sub == nil || b.Sub.Port == 0 || len(b.Sub.Pin) != 43 || len(b.NodeKeys["ed25519"]) != 64 || b.NodeKeys["mldsa65"] == "" {
		t.Fatalf("bundle subscription/keys = %+v %v", b.Sub, b.NodeKeys)
	}
	params, err := b.SPA.Params()
	if err != nil || params != srv.Params {
		t.Fatalf("bundle params differ: %v", err)
	}

	// The client side: seal with what the bundle carries.
	var key [spa.KeySize]byte
	kb, _ := hex.DecodeString(b.DeviceKey)
	copy(key[:], kb)
	pkt, err := spa.SealRandom(params, key, spa.Request{Time: time.Now(), Scope: []uint16{b.Services[0].ID, 3}})
	if err != nil {
		t.Fatal(err)
	}

	// The server side: the verifier sees the devices the store allows.
	devices, err := srv.Store.SPADevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v := spa.NewVerifier(srv.Params, 10*time.Minute, time.Hour, 1000)
	v.SetDevices(devices)
	g, err := v.Verify(pkt)
	if err != nil {
		t.Fatal(err)
	}
	// ssh (ID 3) was requested but is not allowed for alice.
	if g.DeviceID != b.DeviceID || len(g.Scope) != 1 || g.Scope[0] != b.Services[0].ID {
		t.Fatalf("grant = %+v", g)
	}

	if _, err := c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: b.DeviceID})); err != nil {
		t.Fatal(err)
	}
	devices, _ = srv.Store.SPADevices(ctx)
	v.SetDevices(devices)
	pkt, _ = spa.SealRandom(params, key, spa.Request{Time: time.Now()})
	if _, err := v.Verify(pkt); !errors.Is(err, spa.ErrAuth) {
		t.Fatalf("revoked device: %v", err)
	}

	if n := changes.Load(); n != 7 {
		t.Fatalf("OnChange ran %d times, want 7", n)
	}
	audit, err := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{}))
	if err != nil || len(audit.Msg.Entries) != 7 || audit.Msg.Entries[0].Action != "device.revoke" {
		t.Fatalf("audit = %v, %v", audit.Msg.GetEntries(), err)
	}
}

func TestErrorCodes(t *testing.T) {
	_, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)

	_, err := c.DeleteUser(ctx, connect.NewRequest(&nodev1.DeleteUserRequest{Name: "nobody"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing user: %v", err)
	}
	_, err = c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "vmess", Name: "x"}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad kind: %v", err)
	}
	c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "bob"}))
	_, err = c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "bob"}))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate: %v", err)
	}
	st, err := c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
	if err != nil || st.Msg.Users != 1 || len(st.Msg.SpaPorts) == 0 {
		t.Fatalf("status = %v, %v", st.Msg, err)
	}
}

func TestPeerPolicy(t *testing.T) {
	ctx := context.WithValue(context.Background(), peerKey{}, &unix.Ucred{Uid: 0})
	if _, err := (PeerPolicy{}).actor(ctx); err != nil {
		t.Fatalf("root refused: %v", err)
	}
	other := uint32(os.Getuid() + 12345)
	ctx = context.WithValue(context.Background(), peerKey{}, &unix.Ucred{Uid: other})
	if _, err := (PeerPolicy{}).actor(ctx); err == nil {
		t.Fatal("foreign uid allowed without a group")
	}
	if _, err := (PeerPolicy{Group: "no-such-group-raycontrol"}).actor(ctx); err == nil {
		t.Fatal("foreign uid allowed with a missing group")
	}
	if _, err := (PeerPolicy{}).actor(context.Background()); err == nil {
		t.Fatal("call without credentials allowed")
	}
}

func TestPerimeterFeed(t *testing.T) {
	srv, sock, _ := startServerWith(t, func(s *Server) []func() (string, http.Handler) {
		per := &PerimeterServer{Server: s, RayspaUID: os.Getuid(), DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour, TCPCarrier: true, Refresh: time.Minute}
		return []func() (string, http.Handler){per.Handler}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := NewUnixClient(sock)
	feed := perimeterv1connect.NewPerimeterServiceClient(UnixHTTPClient(sock), BaseURL)

	c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "reality", SettingsJson: `{"target":"www.example.org:443"}`}))
	c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "dnstt", Name: "dns"}))
	c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "ssh", Name: "ssh", SettingsJson: `{"ports":["tcp/2222"]}`}))
	c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"reality", "ssh"}}))

	stream, err := feed.WatchPerimeter(ctx, connect.NewRequest(&perimeterv1.WatchPerimeterRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	first := stream.Msg().Snapshot
	ports := map[string]bool{}
	for _, s := range first.Services {
		for _, p := range s.Ports {
			ports[p.Proto+"/"+strconv.Itoa(int(p.Port))] = true
		}
	}
	// The subscription's TCP and UDP (the probe echo), REALITY, SSH.
	if len(first.Devices) != 0 || !ports["tcp/443"] || !ports["tcp/2222"] || len(ports) != 4 || len(first.PublicPorts) != 1 ||
		first.PublicPorts[0].Port != 53 || !first.Spa.TcpCarrier || first.Spa.LenMax != uint32(srv.Params.LenMax) ||
		len(first.AdminPorts) != 1 || first.AdminPorts[0].Port != 2222 {
		t.Fatalf("first snapshot: %v", first)
	}

	if _, err := c.CreateDevice(ctx, connect.NewRequest(&nodev1.CreateDeviceRequest{User: "alice", Name: "phone"})); err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	second := stream.Msg().Snapshot
	// reality, ssh and the subscription every device may reach.
	if second.Revision <= first.Revision || len(second.Devices) != 1 || len(second.Devices[0].Allowed) != 3 {
		t.Fatalf("second snapshot: %v", second)
	}

	if _, err := c.SetAdminAccess(ctx, connect.NewRequest(&nodev1.SetAdminAccessRequest{Cidrs: []string{"198.51.100.7", "2001:db8::/48"}})); err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	if a := stream.Msg().Snapshot.AdminPrefixes; len(a) != 2 || a[0] != "198.51.100.7/32" {
		t.Fatalf("admin prefixes %v", a)
	}
	// Nothing wider than /16 and /48: admin addresses reach SSH without SPA
	// (S-3). ::ffff:0:0/96 is 0.0.0.0/0.
	for _, bad := range []string{"nonsense", "0.0.0.0/0", "10.0.0.0/15", "::/0", "2001:db8::/32", "2001:db8::/47", "::ffff:0:0/96"} {
		if _, err := c.SetAdminAccess(ctx, connect.NewRequest(&nodev1.SetAdminAccessRequest{Cidrs: []string{bad}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("admin %s: %v", bad, err)
		}
	}
	if _, err := c.SetAdminAccess(ctx, connect.NewRequest(&nodev1.SetAdminAccessRequest{Cidrs: []string{"10.1.0.0/16", "::ffff:198.51.100.0/120"}})); err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	if a := stream.Msg().Snapshot.AdminPrefixes; len(a) != 2 || a[1] != "198.51.100.0/24" {
		t.Fatalf("admin prefixes %v", a)
	}

	// REALITY open to everyone (RAYCONTROL.md §22.2.2): its TCP 443 is public,
	// and the service stays in the SPA scopes.
	if _, err := c.SetServiceOption(ctx, connect.NewRequest(&nodev1.SetServiceOptionRequest{Name: "reality", Key: "open", Value: "true"})); err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	open := stream.Msg().Snapshot
	pub := map[string]bool{}
	for _, p := range open.PublicPorts {
		pub[fmt.Sprintf("%s/%d", p.Proto, p.Port)] = true
	}
	if !pub["tcp/443"] || !pub["udp/53"] || pub["tcp/2222"] || !slices.ContainsFunc(open.Services, func(s *perimeterv1.Service) bool { return len(s.Ports) == 1 && s.Ports[0].Port == 443 }) {
		t.Fatalf("open REALITY: public %v services %v", pub, open.Services)
	}
	// "open" publishes TCP 443 only, never another port the service was
	// given.
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "r2",
		SettingsJson: `{"target":"www.example.org:443","ports":["tcp/443","tcp/2223"],"open":true}`})); err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	for _, p := range stream.Msg().Snapshot.PublicPorts {
		if p.Port == 2223 {
			t.Fatalf("open REALITY published tcp/2223: %v", stream.Msg().Snapshot.PublicPorts)
		}
	}
	if _, err := c.DeleteService(ctx, connect.NewRequest(&nodev1.DeleteServiceRequest{Name: "r2"})); err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	if _, err := c.SetServiceOption(ctx, connect.NewRequest(&nodev1.SetServiceOptionRequest{Name: "reality", Key: "open", Value: "false"})); err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	if p := stream.Msg().Snapshot.PublicPorts; len(p) != 1 || p[0].Port != 53 {
		t.Fatalf("closed again: %v", p)
	}

	// A relay (relay-v1): its address reaches the service ports, not SSH,
	// not the public DNS port; removing it takes them away. Not inside an
	// admin prefix, which reaches SSH, nor an admin prefix around a relay.
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "msk", Address: "198.51.100.20"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a relay inside the admin prefix 198.51.100.0/24: %v", err)
	}
	if _, err := c.SetAdminAccess(ctx, connect.NewRequest(&nodev1.SetAdminAccessRequest{Cidrs: []string{"198.51.100.7"}})); err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "msk", Address: "198.51.100.20"})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetAdminAccess(ctx, connect.NewRequest(&nodev1.SetAdminAccessRequest{Cidrs: []string{"198.51.100.0/24"}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("an admin prefix around a relay: %v", err)
	}
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	rs := stream.Msg().Snapshot
	rports := map[string]bool{}
	for _, p := range rs.RelayPorts {
		rports[fmt.Sprintf("%s/%d", p.Proto, p.Port)] = true
	}
	if !slices.Equal(rs.RelayPrefixes, []string{"198.51.100.20/32"}) || !rports["tcp/443"] || rports["tcp/2222"] || rports["udp/53"] {
		t.Fatalf("relay: prefixes %v ports %v", rs.RelayPrefixes, rports)
	}
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "lan", Address: "10.0.0.5"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a private relay address: %v", err)
	}
	if _, err := c.RemoveRelay(ctx, connect.NewRequest(&nodev1.RemoveRelayRequest{Name: "msk"})); err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	if p := stream.Msg().Snapshot.RelayPrefixes; len(p) != 0 {
		t.Fatalf("relay still there: %v", p)
	}

	// An ACME order opens the window in the feed, its end closes it.
	srv.SetACMEWindow(18080, time.Now().Add(time.Minute))
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	if w := stream.Msg().Snapshot.Acme; w.GetPort() != 18080 || w.GetUntil() <= time.Now().Unix() {
		t.Fatalf("acme window %v", w)
	}
	srv.SetACMEWindow(0, time.Time{})
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	if w := stream.Msg().Snapshot.Acme; w != nil {
		t.Fatalf("acme window still open: %v", w)
	}

	dep, err := c.GetDeployment(ctx, connect.NewRequest(&nodev1.GetDeploymentRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(dep.Msg.Units) != 6 || len(dep.Msg.Warnings) != 0 || len(dep.Msg.HostPorts) == 0 {
		t.Fatalf("deployment units %v warnings %v host ports %v", dep.Msg.Units, dep.Msg.Warnings, dep.Msg.HostPorts)
	} // From outside the ACME window is TCP 80 (no DNS provider here); the
	// rest is the same.
	has := func(rs []*nodev1.PortRange, proto string, port uint32) bool {
		return slices.ContainsFunc(rs, func(r *nodev1.PortRange) bool { return r.Proto == proto && r.From <= port && port <= r.To })
	}
	// The front answers DNS tunnels when they are there: rayctl's apply
	// warns about UDP 53 by it.
	if !dep.Msg.FrontDns || !has(dep.Msg.HostPorts, "udp", 53) {
		t.Fatalf("front_dns %v with host ports %v", dep.Msg.FrontDns, dep.Msg.HostPorts)
	}
	check := func() {
		t.Helper()
		dep, err := c.GetDeployment(ctx, connect.NewRequest(&nodev1.GetDeploymentRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = srv.Store.ServiceByName(ctx, "site")
		site := err == nil
		acme, _ := provision.ACMEPort(ctx, srv.Store)
		if has(dep.Msg.OutsidePorts, "tcp", 80) != site || has(dep.Msg.HostPorts, "tcp", uint32(acme)) != site ||
			has(dep.Msg.OutsidePorts, "tcp", uint32(acme)) || len(dep.Msg.OutsidePorts) != len(dep.Msg.HostPorts) {
			t.Fatalf("site %v: outside %v, host %v (acme %d)", site, dep.Msg.OutsidePorts, dep.Msg.HostPorts, acme)
		}
	}
	check()
	// With a site (REALITY brings it on a node with a domain).
	if _, err := provision.CreateService(ctx, srv.Store, store.Service{Kind: "site", Name: "site", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	check()
}

func TestPerimeterFeedDenied(t *testing.T) {
	per := &PerimeterServer{Server: &Server{}, RayspaUID: 4242}
	ctx := context.WithValue(context.Background(), peerKey{}, &unix.Ucred{Uid: uint32(os.Getuid() + 777)})
	err := per.WatchPerimeter(ctx, nil, nil)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("foreign uid: %v", err)
	}
}

func TestRotateService(t *testing.T) {
	srv, sock, _ := startServer(t)
	srv.RealityLead = 72 * time.Hour
	rotated := 0
	srv.Rotate = func() { rotated++ }
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "nothing"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing service: %v", err)
	}
	if _, err := c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: provision.SubscriptionService})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("not REALITY: %v", err)
	}
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "r",
		SettingsJson: `{"target":"www.example.org:443"}`})); err != nil {
		t.Fatal(err)
	}
	r, err := c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "r", Now: true}))
	if err != nil || rotated != 1 || r.Msg.SwitchAt > time.Now().Unix() {
		t.Fatalf("rotate: %v %d %v", r, rotated, err)
	}
	svc, _ := srv.Store.ServiceByName(ctx, "r")
	if provision.ParseRealityState(svc).RotateAt == 0 {
		t.Fatalf("no request stored: %s", svc.Settings)
	}

	// dnstt: the seal key switches at once (spec/dnsseal-v1.md §8); the
	// previous one is accepted for the grace, or not at all with now.
	srv.CredGrace = 48 * time.Hour
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "dnstt", Name: "dns"})); err != nil {
		t.Fatal(err)
	}
	dns, _ := srv.Store.ServiceByName(ctx, "dns")
	before, _ := srv.Store.ServiceSecrets(ctx, dns.ID)
	start := time.Now().Unix()
	r, err = c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "dns"}))
	if err != nil || !r.Msg.Seal || r.Msg.SwitchAt < start || r.Msg.PrevUntil < start+48*3600 || r.Msg.PrevUntil > time.Now().Add(48*time.Hour).Unix() {
		t.Fatalf("rotate dnstt: %v %v", r, err)
	}
	after, _ := srv.Store.ServiceSecrets(ctx, dns.ID)
	if bytes.Equal(after[provision.SecretSealKey], before[provision.SecretSealKey]) ||
		!bytes.Equal(after[provision.PrevSecret(provision.SecretSealKey)], before[provision.SecretSealKey]) {
		t.Fatal("the seal key did not switch, or the previous one is not kept")
	}
	r, err = c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "dns", Now: true}))
	if err != nil || !r.Msg.Seal || r.Msg.PrevUntil != 0 {
		t.Fatalf("rotate dnstt now: %v %v", r, err)
	}
	if now, _ := srv.Store.ServiceSecrets(ctx, dns.ID); now[provision.PrevSecret(provision.SecretSealKey)] != nil {
		t.Fatal("the previous seal key kept after a switch at once")
	}
}

func TestDNSProvider(t *testing.T) {
	srv, sock, _ := startServer(t)
	api, cf := cftest.New(t)
	old := provision.CloudflareAPI
	provision.CloudflareAPI = cf.BaseURL
	defer func() { provision.CloudflareAPI = old }()
	ctx := context.Background()
	c := NewUnixClient(sock)

	if _, err := c.SetDNSProvider(ctx, connect.NewRequest(&nodev1.SetDNSProviderRequest{Provider: "route53", Token: "x"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("other provider: %v", err)
	}
	if _, err := c.SetDNSProvider(ctx, connect.NewRequest(&nodev1.SetDNSProviderRequest{Provider: "cloudflare", Token: "wrong"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad token: %v", err)
	}
	r, err := c.SetDNSProvider(ctx, connect.NewRequest(&nodev1.SetDNSProviderRequest{Provider: "cloudflare", Token: "good"}))
	if err != nil {
		t.Fatal(err)
	}
	// The test node's host is a name: nothing can point to it.
	st := r.Msg.Status
	if st.Provider != "cloudflare" || st.Zone != "example.com" || len(st.Problems) != 1 || len(api.List()) != 0 {
		t.Fatalf("status %v, records %v", st, api.List())
	}
	entries, _ := srv.Store.ListAudit(ctx, 20)
	for _, e := range entries {
		if strings.Contains(e.Action+e.Target+e.Result, "good") {
			t.Fatalf("token in the audit log: %+v", e)
		}
	}
	if _, err := c.RemoveDNS(ctx, connect.NewRequest(&nodev1.RemoveDNSRequest{})); err != nil {
		t.Fatal(err)
	}
	if g, _ := c.GetDNS(ctx, connect.NewRequest(&nodev1.GetDNSRequest{})); g.Msg.Status.Provider != "" {
		t.Fatal("provider kept")
	}
}

func TestExportUser(t *testing.T) {
	_, sock, changes := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)

	for _, svc := range [][3]string{{"reality", "reality", `{"target":"www.example.org:443"}`}, {"hy2-masq", "hy2", ""}, {"ssh", "ssh", ""}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: svc[0], Name: svc[1], SettingsJson: svc[2]})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"reality", "hy2", "ssh"}})); err != nil {
		t.Fatal(err)
	}
	before := changes.Load()
	r, err := c.ExportUser(ctx, connect.NewRequest(&nodev1.ExportUserRequest{Name: "alice"}))
	if err != nil {
		t.Fatal(err)
	}
	// ssh has no profile; the others are the subscription's links.
	got := map[string]string{}
	for _, p := range r.Msg.Profiles {
		got[p.Service] = p.Link
	}
	if len(got) != 2 || !strings.HasPrefix(got["reality"], "vless://") || !strings.HasPrefix(got["hy2"], "hysteria2://") {
		t.Fatalf("profiles = %v", r.Msg.Profiles)
	}
	if changes.Load() != before {
		t.Fatal("export changed the node")
	}
	audit, err := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{}))
	if err != nil || audit.Msg.Entries[0].Action != "user.export" || audit.Msg.Entries[0].Target != "alice" {
		t.Fatalf("audit = %v, %v", audit.Msg.GetEntries(), err)
	}

	if _, err := c.ExportUser(ctx, connect.NewRequest(&nodev1.ExportUserRequest{Name: "nobody"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing user: %v", err)
	}
	if _, err := c.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "alice"})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExportUser(ctx, connect.NewRequest(&nodev1.ExportUserRequest{Name: "alice"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("disabled user: %v", err)
	}
}

func TestSummaryAPI(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	SummaryDBs = [][2]string{{"operator", filepath.Join(t.TempDir(), "none.mmdb")}}

	r, err := c.GetSummary(ctx, connect.NewRequest(&nodev1.GetSummaryRequest{}))
	if err != nil || r.Msg.Enabled || r.Msg.Api != "" || r.Msg.Days != 7 || r.Msg.K != 10 || len(r.Msg.Dbs) != 1 || r.Msg.Dbs[0].Present {
		t.Fatalf("summary while off: %+v %v", r.Msg, err)
	}
	if _, err := c.SetSummary(ctx, connect.NewRequest(&nodev1.SetSummaryRequest{Enabled: "on"})); err != nil {
		t.Fatal(err)
	}
	if r, _ := c.GetSummary(ctx, connect.NewRequest(&nodev1.GetSummaryRequest{Days: 30})); !r.Msg.Enabled || r.Msg.Days != 30 {
		t.Fatalf("after on: %+v", r.Msg)
	}
	// A network's counts by service: the resolvers and the zones of a DNS
	// tunnel among them.
	today := time.Now().Unix() / 86400
	rows := []store.SummaryCount{{Day: today, ASN: 64500, Field: "reports", N: 10}}
	for field, buckets := range map[string]map[string]int64{"result": {"works": 10}, "dns": {"udp": 10}, "zone": {"0": 3, "1": 7}} {
		for b, n := range buckets {
			rows = append(rows, store.SummaryCount{Day: today, ASN: 64500, Svc: 9, Field: field, Bucket: b, N: n})
		}
	}
	if err := srv.Store.AddSummary(ctx, rows, "Mobile One", "KZ"); err != nil {
		t.Fatal(err)
	}
	r, err = c.GetSummary(ctx, connect.NewRequest(&nodev1.GetSummaryRequest{}))
	if err != nil || len(r.Msg.Networks) != 1 || len(r.Msg.Networks[0].Services) != 1 {
		t.Fatalf("summary with a network: %+v %v", r.Msg, err)
	}
	if s := r.Msg.Networks[0].Services[0]; s.Id != 9 || s.Dns["udp"] != 10 || s.Zone["0"] != 3 || s.Zone["1"] != 7 || len(s.Zone) != 2 {
		t.Fatalf("service counts %+v", s)
	}
	if _, err := c.SetSummary(ctx, connect.NewRequest(&nodev1.SetSummaryRequest{Enabled: "maybe"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad switch: %v", err)
	}
	if _, err := c.SetSummary(ctx, connect.NewRequest(&nodev1.SetSummaryRequest{Api: "geoip", Token: "secret-token"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unknown provider: %v", err)
	}
	audit, _ := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{}))
	for _, e := range audit.Msg.Entries {
		if strings.Contains(e.Target, "secret-token") || strings.Contains(e.Result, "secret-token") {
			t.Fatalf("token in the audit log: %+v", e)
		}
	}
	if _, err := c.SetSummary(ctx, connect.NewRequest(&nodev1.SetSummaryRequest{Enabled: "off"})); err != nil {
		t.Fatal(err)
	}
}

// A service others work through stays while they are on (Q-1): without
// inner the DNS tunnels cannot be rendered.
func TestServiceDependents(t *testing.T) {
	_, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "dnstt", Name: "dns"})); err != nil {
		t.Fatal(err)
	}
	_, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "inner", Enabled: false}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "dns works through inner") {
		t.Fatalf("disable inner under dnstt: %v", err)
	}
	if _, err := c.DeleteService(ctx, connect.NewRequest(&nodev1.DeleteServiceRequest{Name: "inner"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("delete inner under dnstt: %v", err)
	}
	if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "dns", Enabled: false})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "inner", Enabled: false})); err != nil {
		t.Fatalf("disable inner after dnstt: %v", err)
	}
	// Nor does one come on, or get made, while its stage is off.
	_, err = c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "dns", Enabled: true}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "inner, which is disabled") {
		t.Fatalf("enable dnstt without inner: %v", err)
	}
	for _, kind := range []string{"masterdns", "olcrtc"} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: kind, Name: kind})); err == nil || !strings.Contains(err.Error(), "inner, which is disabled") {
			t.Fatalf("create %s without inner: %v", kind, err)
		}
	}
	if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "inner", Enabled: true})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "dns", Enabled: true})); err != nil {
		t.Fatalf("enable dnstt with inner: %v", err)
	}
	// A REALITY whose decoy site is off.
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "reality"})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "reality", Enabled: false})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "site", Enabled: false})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "reality2"})); err == nil || !strings.Contains(err.Error(), "site, which is disabled") {
		t.Fatalf("create reality on a disabled site: %v", err)
	}
	if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "reality", Enabled: true})); err == nil || !strings.Contains(err.Error(), "site, which is disabled") {
		t.Fatalf("enable reality on a disabled site: %v", err)
	}
}

// The debug window: root only, up to a day, in the status and in the
// perimeter snapshot while open, audited; closing it clears both.
func TestDebugWindow(t *testing.T) {
	srv, sock, changes := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	as := func(uid uint32) context.Context {
		return context.WithValue(context.WithValue(ctx, peerKey{}, &unix.Ucred{Uid: uid}), actorKey{}, "test")
	}
	set := func(uid uint32, sec int64) (*nodev1.SetDebugResponse, error) {
		r, err := srv.SetDebug(as(uid), connect.NewRequest(&nodev1.SetDebugRequest{Seconds: sec}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	if _, err := set(1000, 60); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("not root: %v", err)
	}
	// 9223372037 s overflows a Duration: refused, not a closed window.
	for _, sec := range []int64{-1, 24*3600 + 1, 9223372037} {
		if _, err := set(0, sec); !errors.Is(err, store.ErrInvalid) && connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("a window of %ds: %v", sec, err)
		}
	}
	before := changes.Load()
	r, err := set(0, 1800)
	if err != nil || r.Until < time.Now().Add(29*time.Minute).Unix() || r.Until > time.Now().Add(31*time.Minute).Unix() {
		t.Fatalf("open: %+v %v", r, err)
	}
	if changes.Load() == before {
		t.Fatal("no change: the data plane is not rendered again")
	}
	if st, _ := c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{})); st.Msg.DebugUntil != r.Until {
		t.Fatalf("status: %d, want %d", st.Msg.DebugUntil, r.Until)
	}
	p := &PerimeterServer{Server: srv, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour}
	if snap, err := p.snapshot(ctx); err != nil || snap.DebugUntil != r.Until {
		t.Fatalf("snapshot: %v %v", snap.GetDebugUntil(), err)
	}
	// A window that ended is none.
	srv.Store.SetDebugUntil(ctx, time.Now().Add(-time.Minute))
	if st, _ := c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{})); st.Msg.DebugUntil != 0 {
		t.Fatalf("status after the end: %d", st.Msg.DebugUntil)
	}
	if r, err := set(0, 0); err != nil || r.Until != 0 {
		t.Fatalf("close: %+v %v", r, err)
	}
	if !srv.Store.DebugUntil(ctx).IsZero() {
		t.Fatal("still set after closing")
	}
	audit, _ := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{}))
	if !slices.ContainsFunc(audit.Msg.Entries, func(e *nodev1.AuditEntry) bool { return e.Action == "debug" && e.Target == "30m0s" }) {
		t.Fatalf("not audited: %+v", audit.Msg.Entries)
	}
}

// The node's name: set as kept, in the status, audited; refused names leave
// it as it was; "" takes it away.
func TestNodeName(t *testing.T) {
	_, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	name := func() string {
		t.Helper()
		st, err := c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return st.Msg.Name
	}
	if n := name(); n != "" {
		t.Fatalf("a new node is named %q", n)
	}
	r, err := c.SetNodeName(ctx, connect.NewRequest(&nodev1.SetNodeNameRequest{Name: "  Амстердам  1 "}))
	if err != nil || r.Msg.Name != "Амстердам 1" || name() != "Амстердам 1" {
		t.Fatalf("set: %+v %v, status %q", r, err, name())
	}
	for _, bad := range []string{"x" + string(rune(0x202E)) + "y", "a\nb", strings.Repeat("n", 49)} {
		if _, err := c.SetNodeName(ctx, connect.NewRequest(&nodev1.SetNodeNameRequest{Name: bad})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("%+q: %v", bad, err)
		}
	}
	if n := name(); n != "Амстердам 1" {
		t.Fatalf("after refused names: %q", n)
	}
	if r, err := c.SetNodeName(ctx, connect.NewRequest(&nodev1.SetNodeNameRequest{})); err != nil || r.Msg.Name != "" || name() != "" {
		t.Fatalf("remove: %+v %v, status %q", r, err, name())
	}
	audit, _ := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{}))
	if !slices.ContainsFunc(audit.Msg.Entries, func(e *nodev1.AuditEntry) bool { return e.Action == "node name" && e.Target == "Амстердам 1" }) {
		t.Fatalf("not audited: %+v", audit.Msg.Entries)
	}
}

// Over the remote API (no peer of the node's socket), CheckDNSZones takes
// only named resolvers and public addresses on port 53 (review 7).
func TestCheckDNSZonesRemoteResolvers(t *testing.T) {
	srv := &Server{DNSCheck: &dnscheck.Monitor{}}
	for _, r := range []string{"tcp:127.0.0.1:22", "udp:10.0.0.1", "udp:169.254.169.254:80"} {
		_, err := srv.CheckDNSZones(context.Background(), connect.NewRequest(&nodev1.CheckDNSZonesRequest{Resolvers: []string{r}}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s over the remote API: %v", r, err)
		}
	}
}

// rayctl app-mirror (spec/app-update-v1.md §3): off by default, on with
// room for it, off again; the switch goes to the audit log.
func TestAppMirrorAPI(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	r, err := c.GetAppMirror(ctx, connect.NewRequest(&nodev1.GetAppMirrorRequest{}))
	if err != nil || r.Msg.Enabled || len(r.Msg.Releases) != 0 || r.Msg.Checked != 0 {
		t.Fatalf("by default: %+v %v", r.Msg, err)
	}
	_, err = c.SetAppMirror(ctx, connect.NewRequest(&nodev1.SetAppMirrorRequest{Enabled: true}))
	if err != nil {
		// Too little room where the mirror would be: refused, so said.
		if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "free") {
			t.Fatal(err)
		}
		t.Skip("less than 1 GiB free here:", err)
	}
	if r, _ := c.GetAppMirror(ctx, connect.NewRequest(&nodev1.GetAppMirrorRequest{})); !r.Msg.Enabled {
		t.Fatal("not on")
	}
	if _, err := c.SetAppMirror(ctx, connect.NewRequest(&nodev1.SetAppMirrorRequest{})); err != nil {
		t.Fatal(err)
	}
	if r, _ := c.GetAppMirror(ctx, connect.NewRequest(&nodev1.GetAppMirrorRequest{})); r.Msg.Enabled {
		t.Fatal("not off")
	}
	entries, err := srv.Store.ListAudit(ctx, 10)
	if err != nil || !slices.ContainsFunc(entries, func(e store.AuditEntry) bool { return e.Action == "app-mirror.set" && e.Target == "on" }) {
		t.Errorf("audit %+v %v", entries, err)
	}
}
