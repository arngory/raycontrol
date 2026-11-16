package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand/v2"
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
	"github.com/arngory/raycontrol/internal/store"
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

// The keys of a credential switch reach the answer with their times: the
// next UUID's from its switch (from), once published; after the switch the
// previous UUID's until the end of its grace (until); the current ones
// with neither.
func TestGetYggdrasilPeerKeysRotation(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := NewUnixClient(sock)
	for _, s := range []*nodev1.CreateServiceRequest{{Kind: "reality", Name: "reality"}, {Kind: "yggdrasil", Name: "ygg"}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(s)); err != nil {
			t.Fatal(s.Name, err)
		}
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"ygg"}})); err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.Store.CreateDevice(ctx, "alice", "phone", "user"); err != nil {
		t.Fatal(err)
	}
	get := func() []*nodev1.YggdrasilPeerKey {
		t.Helper()
		r, err := c.GetYggdrasilPeerKeys(ctx, connect.NewRequest(&nodev1.GetYggdrasilPeerKeysRequest{Service: "ygg"}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.Keys
	}
	set := func() store.Credential {
		t.Helper()
		m, err := render.Collect(ctx, srv.Store)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range m.Services {
			if s.Kind == "inner" {
				return m.Sets[s.ID][m.Users[0].ID]
			}
		}
		t.Fatal("no inner")
		return store.Credential{}
	}
	// The credential a label names: "" current, "-n" next, "-p" previous.
	credOf := func(label string) string {
		for _, s := range []string{"-n", "-p"} {
			if strings.HasSuffix(label, s) {
				return s
			}
		}
		return ""
	}
	check := func(want map[string][2]int64) {
		t.Helper()
		got := map[string][2]int64{}
		n := map[string]int{}
		for _, k := range get() {
			if _, dup := got[k.Label]; dup {
				t.Fatalf("%s twice", k.Label)
			}
			got[k.Label] = [2]int64{k.From, k.Until}
			cred := credOf(k.Label)
			n[cred]++
			if map[string]string{"": "current", "-n": "next", "-p": "previous"}[cred] != k.Credential {
				t.Errorf("%s is %s", k.Label, k.Credential)
			}
			times, ok := want[cred]
			if !ok || [2]int64{k.From, k.Until} != times {
				t.Errorf("%s: from %d until %d, want %v", k.Label, k.From, k.Until, times)
			}
		}
		for cred := range want {
			if n[cred] != 2 { // the user's own key and the phone's
				t.Errorf("%d keys %q, want 2: %v", n[cred], cred, got)
			}
		}
		if len(got) != 2*len(want) {
			t.Errorf("keys %v, want %v", got, want)
		}
	}
	check(map[string][2]int64{"": {0, 0}})
	day := 24 * time.Hour
	r := store.Rotation{Period: 30 * day, Lead: 3 * day, Grace: 2 * day}
	now := time.Now()
	if n, err := srv.Store.RotateCredentials(ctx, now.Add(28*day), r, render.NewUUID); err != nil || n == 0 {
		t.Fatalf("publish: %d %v", n, err)
	}
	next := set().NextFrom.Unix()
	if next <= now.Unix() {
		t.Fatalf("next from %d", next)
	}
	check(map[string][2]int64{"": {0, 0}, "-n": {next, 0}})
	if n, err := srv.Store.RotateCredentials(ctx, now.Add(31*day), r, render.NewUUID); err != nil || n == 0 {
		t.Fatalf("switch: %d %v", n, err)
	}
	until := set().PrevUntil.Unix()
	if until <= next {
		t.Fatalf("previous until %d, next was from %d", until, next)
	}
	check(map[string][2]int64{"": {0, 0}, "-p": {0, until}})
}

// The answer's order whatever order the keys come in: with names, by the
// user's name, the user's own keys first, then the devices by name; without
// names, by the user's number, then the devices by ID; each device's
// current, next, previous.
func TestComparePeerKeys(t *testing.T) {
	row := func(userID int64, user, devID, dev, cred string) peerKeyRow {
		return peerKeyRow{pb: &nodev1.YggdrasilPeerKey{User: user, DeviceId: devID, Device: dev, Credential: cred,
			Label: fmt.Sprintf("u%d %s %s %s %s", userID, user, devID, dev, cred)}, userID: userID}
	}
	labels := func(rows []peerKeyRow) []string {
		var out []string
		for _, r := range rows {
			out = append(out, r.pb.Label)
		}
		return out
	}
	// Named: zoe (u1) after alice (u9); alice's devices by name, not ID.
	named := []peerKeyRow{
		row(9, "alice", "", "", "current"), row(9, "alice", "", "", "next"), row(9, "alice", "", "", "previous"),
		row(9, "alice", "ff01", "laptop", "current"), row(9, "alice", "ff01", "laptop", "next"),
		row(9, "alice", "0a02", "phone", "current"), row(9, "alice", "0a02", "phone", "next"), row(9, "alice", "0a02", "phone", "previous"),
		row(1, "zoe", "", "", "current"), row(1, "zoe", "77", "tablet", "current"),
	}
	// Bare: u1 before u9 (and u9 before u10, numbers not text); devices by ID.
	bare := []peerKeyRow{
		row(1, "", "", "", "current"), row(1, "", "77", "", "current"),
		row(9, "", "", "", "current"), row(9, "", "", "", "next"),
		row(9, "", "0a02", "", "current"), row(9, "", "0a02", "", "next"), row(9, "", "0a02", "", "previous"),
		row(9, "", "ff01", "", "current"), row(9, "", "ff01", "", "next"),
		row(10, "", "", "", "current"),
	}
	r := rand.New(rand.NewPCG(7, 11))
	for _, want := range [][]peerKeyRow{named, bare} {
		for range 200 {
			got := slices.Clone(want)
			r.Shuffle(len(got), func(i, j int) { got[i], got[j] = got[j], got[i] })
			slices.SortFunc(got, comparePeerKeys)
			if !slices.Equal(labels(got), labels(want)) {
				t.Fatalf("sorted\n%q\nwant\n%q", labels(got), labels(want))
			}
		}
	}
}
