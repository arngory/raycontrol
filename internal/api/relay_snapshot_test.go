package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// A relay's perimeter (relay-v1 §3.1): its own SPA, kept; each device with
// its key for this relay only; the forwarded services with their IDs, not
// SSH and not the public DNS tunnel; the relay host's SSH by SPA for the
// devices allowed SSH, and for the relay's own admin addresses.
func TestRelaySnapshot(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := NewUnixClient(sock)
	for _, s := range []*nodev1.CreateServiceRequest{
		{Kind: "reality", Name: "reality", SettingsJson: `{"target":"www.example.org:443"}`},
		{Kind: "dnstt", Name: "dns"},
		{Kind: "ssh", Name: "ssh", SettingsJson: `{"ports":["tcp/2222"]}`},
	} {
		if _, err := c.CreateService(ctx, connect.NewRequest(s)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"reality", "ssh", "dns"}})); err != nil {
		t.Fatal(err)
	}
	dev, key, err := srv.Store.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetAdminAccess(ctx, connect.NewRequest(&nodev1.SetAdminAccessRequest{Cidrs: []string{"198.51.100.7"}})); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Store.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	per := &PerimeterServer{Server: srv, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour, TCPCarrier: true}
	if _, err := per.RelaySnapshot(ctx, "r9"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown relay: %v", err)
	}
	snap, err := per.RelaySnapshot(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := per.RelaySnapshot(ctx, "r1")
	if string(snap.Spa.NodeId) == string(srv.Params.NodeID[:]) || string(again.Spa.NodeId) != string(snap.Spa.NodeId) ||
		!snap.Spa.TcpCarrier || snap.Spa.MaxTtlS != 3600 {
		t.Fatalf("relay SPA %v, again %v", snap.Spa, again.Spa)
	}
	reality, _ := srv.Store.ServiceByName(ctx, "reality")
	ssh, _ := srv.Store.ServiceByName(ctx, "ssh")
	ids := map[uint32]bool{}
	for _, s := range snap.Services {
		ids[s.Id] = true
		// SSH: the relay host's own, a local scope for the devices allowed
		// the exit's SSH; never forwarded.
		if s.Id == uint32(ssh.ID) != s.Local || s.Rotation != nil ||
			s.Local && (len(s.Ports) != 1 || s.Ports[0].Port != 22) {
			t.Errorf("relay service %v", s)
		}
		for _, p := range s.Ports {
			if p.Proto == "udp" && p.Port == 53 {
				t.Errorf("the public DNS tunnel forwarded: %v", s)
			}
		}
	}
	if !ids[uint32(reality.ID)] {
		t.Fatalf("REALITY not forwarded: %v", snap.Services)
	}
	rp, _ := provision.RelayParams(ctx, srv.Store, "r1")
	want := spa.RelayKey(key, srv.Params.NodeID, rp.NodeID, "r1")
	if len(snap.Devices) != 1 || snap.Devices[0].Id != dev.ID || string(snap.Devices[0].Key) != string(want[:]) || string(snap.Devices[0].Key) == string(key[:]) {
		t.Fatalf("relay devices %v", snap.Devices)
	}
	for _, id := range snap.Devices[0].Allowed {
		if !ids[id] {
			t.Errorf("device allowed %d, which the relay has not", id)
		}
	}
	// The relay's own admin addresses, never the exit's.
	if len(snap.PublicPorts) != 0 || len(snap.RelayPrefixes) != 0 || len(snap.AdminPrefixes) != 0 ||
		len(snap.AdminPorts) != 1 || snap.AdminPorts[0].Port != 22 {
		t.Fatalf("relay snapshot %v", snap)
	}
}

// A relay's probe endpoint (relay-v1 §9.1): a local service of its own ID,
// TCP and UDP on its port, open to every device the relay knows; a service
// of the exit's on that port is not forwarded there.
func TestRelaySnapshotProbe(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "reality",
		SettingsJson: `{"target":"www.example.org:443"}`})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"reality"}})); err != nil {
		t.Fatal(err)
	}
	dev, _, err := srv.Store.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Store.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	per := &PerimeterServer{Server: srv, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour}
	issue := func(port uint16) {
		t.Helper()
		params, _ := provision.RelayParams(ctx, srv.Store, "r1")
		b, _ := json.Marshal(node.FromParams(params))
		if err := srv.Store.IssueRelay(ctx, "r1", store.RelayIssue{SPA: b, SSHPort: 22, Admin: []string{"192.0.2.7/32"}, CertPin: "pin",
			ProbePort: port, ProbePin: "probe"}); err != nil {
			t.Fatal(err)
		}
	}
	issue(31000)
	snap, err := per.RelaySnapshot(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	probeSvc := uint32(provision.RelayProbeSvc)
	var found bool
	for _, s := range snap.Services {
		if s.Id != probeSvc {
			continue
		}
		found = true
		if !s.Local || len(s.Ports) != 2 || s.Ports[0].Proto != "tcp" || s.Ports[1].Proto != "udp" ||
			s.Ports[0].Port != 31000 || s.Ports[1].Port != 31000 {
			t.Errorf("probe service %v", s)
		}
	}
	if !found || len(snap.Devices) != 1 || snap.Devices[0].Id != dev.ID || !slices.Contains(snap.Devices[0].Allowed, probeSvc) {
		t.Fatalf("relay snapshot without the probe endpoint for the device: %v", snap)
	}
	if known, err := per.RelayKnows(ctx, "r1", dev.ID); err != nil || !known {
		t.Fatalf("the relay does not know the device: %v %v", known, err)
	}
	if known, _ := per.RelayKnows(ctx, "r1", "nope"); known {
		t.Fatal("the relay knows a device that is not there")
	}

	// On REALITY's port: REALITY is not forwarded there (the subscription
	// still is).
	issue(443)
	reality, _ := srv.Store.ServiceByName(ctx, "reality")
	snap, _ = per.RelaySnapshot(ctx, "r1")
	for _, s := range snap.Services {
		for _, p := range s.Ports {
			if p.Port == 443 && s.Id != probeSvc {
				t.Errorf("service %d forwards the probe endpoint's port: %v", s.Id, s)
			}
		}
	}
	if len(snap.Devices) != 1 || slices.Contains(snap.Devices[0].Allowed, uint32(reality.ID)) {
		t.Errorf("REALITY through the relay on the probe endpoint's port: %v", snap.Devices)
	}
}
