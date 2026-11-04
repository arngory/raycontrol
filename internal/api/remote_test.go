package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	devicev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1/devicev1connect"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/spa"
)

// startRemote serves the remote API of srv on a loopback port and returns
// its address and pin.
func startRemote(t *testing.T, srv *Server) (string, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	svc, err := srv.Store.ServiceByName(ctx, "api")
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := srv.Store.ServiceSecrets(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := RemoteTLSConfig(secrets[provision.SecretTLSCert], secrets[provision.SecretTLSKey])
	if err != nil {
		t.Fatal(err)
	}
	pin, err := provision.SPKIPin(secrets[provision.SecretTLSCert])
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &Remote{Server: srv, Log: slog.New(slog.DiscardHandler)}
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, ln, cfg) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return ln.Addr().String(), pin
}

type remoteDevice struct {
	cert tls.Certificate
	node nodev1connect.NodeServiceClient
	dev  devicev1connect.DeviceServiceClient
}

func newRemoteDevice(t *testing.T, addr, pin string) remoteDevice {
	t.Helper()
	cert, err := NewClientCertificate()
	if err != nil {
		t.Fatal(err)
	}
	n, d := NewRemoteClients(addr, pin, cert)
	return remoteDevice{cert: cert, node: n, dev: d}
}

// register uses an invite code the way a client does.
func (rd remoteDevice) register(ctx context.Context, code string, minute int64) (*devicev1.RegisterResponse, error) {
	inv, err := node.DecodeInvite(code)
	if err != nil {
		return nil, err
	}
	k, err := hex.DecodeString(inv.DeviceKey)
	if err != nil {
		return nil, err
	}
	mac := RegisterMAC([spa.KeySize]byte(k), minute, CertPin(rd.cert.Leaf))
	resp, err := rd.dev.Register(ctx, connect.NewRequest(&devicev1.RegisterRequest{InviteId: inv.DeviceID, Minute: minute, Mac: mac}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func TestRemoteAPI(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	invite := func(user, name, role string) string {
		t.Helper()
		resp, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: user, Name: name, Role: role}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg.InviteCode
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice"})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: "laptop"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("an invite without an API service: %v", err)
	}
	for _, kind := range []string{"api", "api"} {
		_, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: kind, Name: kind}))
		if err != nil && !strings.Contains(err.Error(), "already") {
			t.Fatal(err)
		}
	}
	addr, pin := startRemote(t, srv)
	now := time.Now().Unix() / 60

	code := invite("alice", "laptop", "admin")
	inv, err := node.DecodeInvite(code)
	if err != nil {
		t.Fatal(err)
	}
	if inv.API == nil || inv.API.Pin != pin || len(inv.Services) != 1 || inv.Services[0].Kind != "api" || inv.NodeKeys != nil || len(code) > 700 {
		t.Fatalf("invite: %+v (%d characters)", inv, len(code))
	}
	// The invite passes SPA to the API only.
	scope := func(id string) []uint16 {
		devices, err := srv.Store.SPADevices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range devices {
			if d.ID == id {
				return d.Allowed
			}
		}
		return nil
	}
	if got := scope(inv.DeviceID); !slices.Equal(got, []uint16{inv.Services[0].ID}) {
		t.Fatalf("invite scope %v", got)
	}

	admin := newRemoteDevice(t, addr, pin)
	if _, err := admin.node.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("an unregistered certificate: %v", err)
	}
	// A wrong proof, a stale minute, an unknown invite: all the same answer.
	var wrongKey [spa.KeySize]byte
	if _, err := admin.dev.Register(ctx, connect.NewRequest(&devicev1.RegisterRequest{InviteId: inv.DeviceID, Minute: now,
		Mac: RegisterMAC(wrongKey, now, CertPin(admin.cert.Leaf))})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("a wrong key: %v", err)
	}
	if _, err := admin.dev.Register(ctx, connect.NewRequest(&devicev1.RegisterRequest{InviteId: "0000000000000000", Minute: now})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("an unknown invite: %v", err)
	}
	// The proof is for one client key: another certificate cannot use it.
	k, _ := hex.DecodeString(inv.DeviceKey)
	other := newRemoteDevice(t, addr, pin)
	if _, err := other.dev.Register(ctx, connect.NewRequest(&devicev1.RegisterRequest{InviteId: inv.DeviceID, Minute: now,
		Mac: RegisterMAC([spa.KeySize]byte(k), now, CertPin(admin.cert.Leaf))})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("a proof for another key: %v", err)
	}
	if _, err := admin.register(ctx, code, now-5); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("a stale minute: %v", err)
	}
	reg, err := admin.register(ctx, code, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := node.DecodeBundle(reg.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Role != "admin" || b.DeviceID != reg.DeviceId || b.API == nil || b.API.Pin != pin || b.Sub == nil || b.NodeKeys == nil {
		t.Fatalf("bundle %+v", b)
	}
	if _, err := newRemoteDevice(t, addr, pin).register(ctx, code, now); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("an invite used twice: %v", err)
	}
	if scope(inv.DeviceID) != nil || !slices.Contains(scope(reg.DeviceId), inv.Services[0].ID) {
		t.Fatalf("after registration: invite %v, device %v", scope(inv.DeviceID), scope(reg.DeviceId))
	}

	st, err := admin.node.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
	if err != nil || st.Msg.Version != "test" {
		t.Fatalf("admin status: %v", err)
	}
	if _, err := admin.node.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "bob"})); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.node.Backup(ctx, connect.NewRequest(&nodev1.BackupRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a remote backup: %v", err)
	}
	if _, err := admin.node.GetDeployment(ctx, connect.NewRequest(&nodev1.GetDeploymentRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("the rendered keys through the remote API: %v", err)
	}
	// A relay opens the service ports to an address: root on the node only.
	if _, err := admin.node.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r", Address: "198.51.100.20"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a remote relay: %v", err)
	}
	audit, err := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{Limit: 5}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(audit.Msg.Entries, func(e *nodev1.AuditEntry) bool {
		return e.Action == "user.create" && e.Actor == "alice/laptop (remote)"
	}) {
		t.Fatalf("audit %v", audit.Msg.Entries)
	}

	// A user device: itself only, no node administration, no API in SPA.
	phone := newRemoteDevice(t, addr, pin)
	reg2, err := phone.register(ctx, invite("bob", "phone", "user"), now)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := node.DecodeBundle(reg2.Bundle); b.API != nil || slices.Contains(scope(reg2.DeviceId), inv.Services[0].ID) {
		t.Fatalf("a user device gets the API: %+v %v", b.API, scope(reg2.DeviceId))
	}
	self, err := phone.dev.GetSelf(ctx, connect.NewRequest(&devicev1.GetSelfRequest{}))
	if err != nil || self.Msg.User != "bob" || self.Msg.Role != "user" {
		t.Fatalf("self %v %v", self, err)
	}
	if _, err := phone.node.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a user device administers: %v", err)
	}

	// The admin device moves to a new key; the old one stops working.
	next, err := NewClientCertificate()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(RotateMessage(CertPin(admin.cert.Leaf), CertPin(next.Leaf)))
	sig, err := ecdsa.SignASN1(rand.Reader, next.PrivateKey.(*ecdsa.PrivateKey), sum[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.dev.RotateCertificate(ctx, connect.NewRequest(&devicev1.RotateCertificateRequest{Certificate: next.Certificate[0], Signature: sig[1:]})); err == nil {
		t.Fatal("a bad signature rotated")
	}
	if _, err := admin.dev.RotateCertificate(ctx, connect.NewRequest(&devicev1.RotateCertificateRequest{Certificate: next.Certificate[0], Signature: sig})); err != nil {
		t.Fatal(err)
	}
	fresh := remoteDevice{cert: next}
	fresh.node, fresh.dev = NewRemoteClients(addr, pin, next)
	if _, err := fresh.node.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{})); err != nil {
		t.Fatalf("new key: %v", err)
	}
	old := newRemoteDevice(t, addr, pin)
	old.node, _ = NewRemoteClients(addr, pin, admin.cert)
	if _, err := old.node.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("old key after rotation: %v", err)
	}

	// Revocation ends it.
	if _, err := c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: reg.DeviceId})); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.node.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("revoked: %v", err)
	}

	// Invites are listed until used, and can be withdrawn.
	spare, err := node.DecodeInvite(invite("alice", "tablet", "user"))
	if err != nil {
		t.Fatal(err)
	}
	list, err := c.ListDevices(ctx, connect.NewRequest(&nodev1.ListDevicesRequest{}))
	if err != nil || len(list.Msg.Invites) != 1 || list.Msg.Invites[0].Id != spare.DeviceID {
		t.Fatalf("invites %v %v", list, err)
	}
	if _, err := c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: spare.DeviceID})); err != nil {
		t.Fatal(err)
	}
	if scope(spare.DeviceID) != nil {
		t.Fatal("a withdrawn invite passes SPA")
	}
	if _, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: "laptop"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("an invite for a taken name: %v", err)
	}
	if _, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: "x", TtlSeconds: 30 * 24 * 3600})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("an invite for a month: %v", err)
	}

	// No client certificate, no TLS.
	conn, err := tls.Dial("tcp", addr, PinnedTLS(pin, nil))
	if err == nil {
		_, err = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		if err == nil {
			_, err = conn.Read(make([]byte, 1))
		}
		conn.Close()
	}
	if err == nil {
		t.Fatal("a connection without a client certificate was served")
	}
}
