package api

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// A relay's perimeter (relay-v1 §3.1): its own SPA, kept; each device with
// its key for this relay only; the forwarded services with their IDs, not
// SSH and not the public DNS tunnel; the relay host's SSH for the admin
// addresses.
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
		if s.Id == uint32(ssh.ID) || s.Rotation != nil {
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
	want := spa.RelayKey(key, srv.Params.NodeID, "r1")
	if len(snap.Devices) != 1 || snap.Devices[0].Id != dev.ID || string(snap.Devices[0].Key) != string(want[:]) || string(snap.Devices[0].Key) == string(key[:]) {
		t.Fatalf("relay devices %v", snap.Devices)
	}
	for _, id := range snap.Devices[0].Allowed {
		if !ids[id] {
			t.Errorf("device allowed %d, which the relay does not forward", id)
		}
	}
	if len(snap.PublicPorts) != 0 || len(snap.RelayPrefixes) != 0 ||
		len(snap.AdminPrefixes) != 1 || snap.AdminPrefixes[0] != "198.51.100.7/32" ||
		len(snap.AdminPorts) != 1 || snap.AdminPorts[0].Port != 22 {
		t.Fatalf("relay snapshot %v", snap)
	}
}
