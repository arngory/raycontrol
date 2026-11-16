package api

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
)

// GetYggdrasilPeerKeys: the node's key in the mesh and its address, then
// the keys its users file lets in, by user (the user's own first, then the
// devices by name), named; a revoked device and a disabled user have none.
// Public keys only: neither the node's seed nor a device's key is in the
// answer. A service that is not Yggdrasil, an unknown one and a disabled
// one are refused. Admin devices may ask through the remote API, a user's
// device may not; it is not root's alone.
func TestGetYggdrasilPeerKeys(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := NewUnixClient(sock)
	for _, s := range []*nodev1.CreateServiceRequest{
		{Kind: "api", Name: "api"},
		{Kind: "reality", Name: "reality"}, // self-steal: the site Yggdrasil goes under
		{Kind: "yggdrasil", Name: "ygg"},
	} {
		if _, err := c.CreateService(ctx, connect.NewRequest(s)); err != nil {
			t.Fatal(s.Name, err)
		}
	}
	ids := map[string]string{}
	var deviceKeys []string
	for _, u := range []struct{ name, devices string }{{"bob", "phone"}, {"alice", "tablet,phone,gone"}, {"carol", "phone"}} {
		if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: u.name, Services: []string{"ygg"}})); err != nil {
			t.Fatal(err)
		}
		for _, name := range strings.Split(u.devices, ",") {
			d, key, err := srv.Store.CreateDevice(ctx, u.name, name, "user")
			if err != nil {
				t.Fatal(err)
			}
			ids[u.name+"/"+name] = d.ID
			deviceKeys = append(deviceKeys, hex.EncodeToString(key[:]))
		}
	}
	if _, err := c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: ids["alice/gone"]})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "carol"})); err != nil {
		t.Fatal(err)
	}

	r, err := c.GetYggdrasilPeerKeys(ctx, connect.NewRequest(&nodev1.GetYggdrasilPeerKeysRequest{Service: "ygg"}))
	if err != nil {
		t.Fatal(err)
	}
	m, err := render.CollectForRender(ctx, srv.Store)
	if err != nil {
		t.Fatal(err)
	}
	var ygg render.Service
	for _, s := range m.Services {
		if s.Name == "ygg" {
			ygg = s
		}
	}
	_, nodeKey, err := render.YggdrasilNode(ygg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Msg.Service != "ygg" || r.Msg.NodeKey != hex.EncodeToString(nodeKey) || r.Msg.NodeAddress != render.YggdrasilAddress(nodeKey).String() {
		t.Fatalf("node %q %q %q", r.Msg.Service, r.Msg.NodeKey, r.Msg.NodeAddress)
	}
	var got []string
	for _, k := range r.Msg.Keys {
		got = append(got, fmt.Sprintf("%s/%s %s %s", k.User, k.Device, k.DeviceId, k.Credential))
		raw, err := hex.DecodeString(k.PublicKey)
		if err != nil || len(raw) != 32 || k.Address != render.YggdrasilAddress(raw).String() || k.From != 0 || k.Until != 0 {
			t.Errorf("key %+v", k)
		}
	}
	want := []string{
		"alice/  current",
		"alice/phone " + ids["alice/phone"] + " current",
		"alice/tablet " + ids["alice/tablet"] + " current",
		"bob/  current",
		"bob/phone " + ids["bob/phone"] + " current",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("keys\n got %q\nwant %q", got, want)
	}
	// Public keys only.
	b, _ := protojson.Marshal(r.Msg)
	secrets := append(slices.Clone(deviceKeys), hex.EncodeToString(ygg.Secrets[provision.SecretYggdrasilSeed]))
	for _, u := range m.Users {
		secrets = append(secrets, hex.EncodeToString(render.YggdrasilKey(m.Inner[u.ID]).Seed()))
		for _, d := range m.Devices[u.ID] {
			secrets = append(secrets, hex.EncodeToString(render.YggdrasilDeviceKey(m.Inner[u.ID], d.Key[:]).Seed()))
		}
	}
	if len(secrets) != len(deviceKeys)+1+5 {
		t.Fatalf("%d secrets", len(secrets))
	}
	for _, sec := range secrets {
		if strings.Contains(string(b), sec) {
			t.Fatalf("a secret in the answer: %s", sec)
		}
	}
	for _, u := range m.Users {
		if strings.Contains(string(b), m.Inner[u.ID]) {
			t.Fatal("an inner UUID in the answer")
		}
	}

	for name, want := range map[string]connect.Code{"reality": connect.CodeInvalidArgument, "nope": connect.CodeNotFound} {
		if _, err := c.GetYggdrasilPeerKeys(ctx, connect.NewRequest(&nodev1.GetYggdrasilPeerKeysRequest{Service: name})); connect.CodeOf(err) != want {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}

	// The remote API: admin devices, not a user's.
	if nodeOnly[nodev1connect.NodeServiceGetYggdrasilPeerKeysProcedure] {
		t.Fatal("peer keys for root on the node only")
	}
	addr, pin := startRemote(t, srv)
	now := time.Now().Unix() / 60
	register := func(user, name, role string) remoteDevice {
		t.Helper()
		inv, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: user, Name: name, Role: role}))
		if err != nil {
			t.Fatal(err)
		}
		d := newRemoteDevice(t, addr, pin)
		if _, err := d.register(ctx, inv.Msg.InviteCode, now); err != nil {
			t.Fatal(err)
		}
		return d
	}
	admin := register("alice", "laptop", "admin")
	remote, err := admin.node.GetYggdrasilPeerKeys(ctx, connect.NewRequest(&nodev1.GetYggdrasilPeerKeysRequest{Service: "ygg"}))
	if err != nil || remote.Msg.NodeKey != r.Msg.NodeKey || len(remote.Msg.Keys) != len(r.Msg.Keys)+1 {
		t.Fatalf("an admin device: %v %v", remote, err)
	}
	user := register("bob", "watch", "user")
	if _, err := user.node.GetYggdrasilPeerKeys(ctx, connect.NewRequest(&nodev1.GetYggdrasilPeerKeysRequest{Service: "ygg"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a user's device: %v", err)
	}

	// Disabled: it lets no one in.
	if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "ygg"})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetYggdrasilPeerKeys(ctx, connect.NewRequest(&nodev1.GetYggdrasilPeerKeysRequest{Service: "ygg"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("disabled: %v", err)
	}
}
