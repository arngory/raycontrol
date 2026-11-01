package api

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/node"
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
	params, err := node.Init(ctx, st, "n.example.com")
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

	for _, svc := range [][2]string{{"reality", "reality"}, {"dnstt", "dns"}, {"ssh", "ssh"}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: svc[0], Name: svc[1]})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"reality", "dns"}})); err != nil {
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
	if b.Host != "n.example.com" || b.DeviceID != dev.Msg.Device.Id || len(b.Services) != 2 {
		t.Fatalf("bundle = %+v", b)
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

	if n := changes.Load(); n != 6 {
		t.Fatalf("OnChange ran %d times, want 6", n)
	}
	audit, err := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{}))
	if err != nil || len(audit.Msg.Entries) != 6 || audit.Msg.Entries[0].Action != "device.revoke" {
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

	c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "reality"}))
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
	if len(first.Devices) != 0 || len(first.Services) != 2 || len(first.PublicPorts) != 1 ||
		first.PublicPorts[0].Port != 53 || !first.Spa.TcpCarrier || first.Spa.LenMax != uint32(srv.Params.LenMax) {
		t.Fatalf("first snapshot: %v", first)
	}

	if _, err := c.CreateDevice(ctx, connect.NewRequest(&nodev1.CreateDeviceRequest{User: "alice", Name: "phone"})); err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatal(stream.Err())
	}
	second := stream.Msg().Snapshot
	if second.Revision <= first.Revision || len(second.Devices) != 1 || len(second.Devices[0].Allowed) != 2 {
		t.Fatalf("second snapshot: %v", second)
	}
}

func TestPerimeterFeedDenied(t *testing.T) {
	per := &PerimeterServer{Server: &Server{}, RayspaUID: 4242}
	ctx := context.WithValue(context.Background(), peerKey{}, &unix.Ucred{Uid: uint32(os.Getuid() + 777)})
	err := per.WatchPerimeter(ctx, nil, nil)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("foreign uid: %v", err)
	}
}
