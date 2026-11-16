package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

	r, err := c.GetYggdrasilPeerKeys(ctx, connect.NewRequest(&nodev1.GetYggdrasilPeerKeysRequest{Service: "ygg", Names: true}))
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
	// Without names: the same keys, labelled as in the users file, by the
	// users' numbers (bob is u1, alice u2); no name anywhere.
	bare, err := c.GetYggdrasilPeerKeys(ctx, connect.NewRequest(&nodev1.GetYggdrasilPeerKeysRequest{Service: "ygg"}))
	if err != nil {
		t.Fatal(err)
	}
	bob, _ := srv.Store.UserByName(ctx, "bob")
	alice, _ := srv.Store.UserByName(ctx, "alice")
	if bob.ID >= alice.ID {
		t.Fatalf("bob %d, alice %d", bob.ID, alice.ID)
	}
	byKey := map[string]*nodev1.YggdrasilPeerKey{}
	for _, k := range r.Msg.Keys {
		byKey[k.PublicKey] = k
	}
	var labels []string
	for _, k := range bare.Msg.Keys {
		named := byKey[k.PublicKey]
		if k.User != "" || k.Device != "" || named == nil || named.Label != k.Label || named.DeviceId != k.DeviceId {
			t.Errorf("bare %+v, named %+v", k, named)
		}
		labels = append(labels, k.Label)
	}
	alicePhone, aliceTablet := ids["alice/phone"], ids["alice/tablet"]
	if alicePhone > aliceTablet {
		alicePhone, aliceTablet = aliceTablet, alicePhone
	}
	u := func(id int64, rest string) string { return fmt.Sprintf("%s%s", render.InnerEmail(id), rest) }
	wantLabels := []string{u(bob.ID, ""), u(bob.ID, "-"+ids["bob/phone"]), u(alice.ID, ""), u(alice.ID, "-"+alicePhone), u(alice.ID, "-"+aliceTablet)}
	if !slices.Equal(labels, wantLabels) {
		t.Fatalf("labels %q, want %q", labels, wantLabels)
	}
	users := yggUsersFile(t, srv, "ygg")
	for _, k := range bare.Msg.Keys {
		if users[k.Label] != k.PublicKey {
			t.Errorf("%s: %s in the answer, %s in the users file", k.Label, k.PublicKey, users[k.Label])
		}
	}
	if len(users) != len(bare.Msg.Keys) {
		t.Errorf("%d keys, %d in the users file", len(bare.Msg.Keys), len(users))
	}
	if b, _ := protojson.Marshal(bare.Msg); strings.Contains(string(b), "alice") || strings.Contains(string(b), "phone") ||
		strings.Contains(string(b), "tablet") {
		t.Fatalf("a name without names: %s", b)
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

// yggUsersFile renders the node as rayd does (CollectForRender, Render)
// and returns the users file of a Yggdrasil service: label → public key.
// The site gets a certificate first: Yggdrasil waits for one.
func yggUsersFile(t *testing.T, srv *Server, name string) map[string]string {
	t.Helper()
	ctx := context.Background()
	site, err := srv.Store.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	keyDER, certDER, err := provision.SelfSigned("site.example.com")
	if err != nil {
		t.Fatal(err)
	}
	srv.Store.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	srv.Store.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, keyDER)
	m, err := render.CollectForRender(ctx, srv.Store)
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := render.Render(m, render.Paths{Rendered: "/r", Run: "/run/niko"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Path != "/r/"+name+"/"+render.YggdrasilUsers {
			continue
		}
		var file struct {
			Users []struct {
				Name      string
				Yggdrasil struct {
					PublicKey string `json:"public_key"`
				}
			}
		}
		if err := json.Unmarshal(f.Content, &file); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, u := range file.Users {
			out[u.Name] = u.Yggdrasil.PublicKey
		}
		return out
	}
	t.Fatalf("no users file of %s rendered", name)
	return nil
}
