package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
)

// RevokeDevice with overlap (rayctl device revoke -overlap, R4-43) rotates
// the user's credentials: the links the user's devices hold stay, each
// gets a next link from a lead later; the answer and the audit say so and
// when, with no secret; another user's links have no next. Without overlap
// the links are new at once, as before (R4-36), and the answer has no
// times. An admin device may revoke with overlap as root may.
func TestRevokeDeviceOverlap(t *testing.T) {
	srv, sock, changes := startServer(t)
	ctx := context.Background()
	r := store.Rotation{Period: 30 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Grace: 2 * 24 * time.Hour}
	if err := srv.Store.SetRotation(ctx, r); err != nil {
		t.Fatal(err)
	}
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "reality",
		SettingsJson: `{"target":"www.example.org:443"}`})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"})); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alice", "bob"} {
		if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: n, Services: []string{"reality"}})); err != nil {
			t.Fatal(err)
		}
	}
	phone, _, err := srv.Store.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	tablet, _, _ := srv.Store.CreateDevice(ctx, "alice", "tablet", "user")
	watch, _, _ := srv.Store.CreateDevice(ctx, "alice", "watch", "user")
	export := func(name string) *nodev1.Profile {
		t.Helper()
		r, err := c.ExportUser(ctx, connect.NewRequest(&nodev1.ExportUserRequest{Name: name}))
		if err != nil || len(r.Msg.Profiles) != 1 {
			t.Fatalf("export %s: %v %v", name, r, err)
		}
		return r.Msg.Profiles[0]
	}
	uuid := func(link string) string { return strings.SplitN(strings.TrimPrefix(link, "vless://"), "@", 2)[0] }
	before, bob := export("alice"), export("bob")
	if before.NextLink != "" {
		t.Fatalf("a next link before any rotation: %+v", before)
	}
	at := func(u int64) string { return time.Unix(u, 0).UTC().Format(time.RFC3339) }
	var seen []string // every secret alice had, for the audit
	seen = append(seen, uuid(before.Link))

	// With overlap: the link stays, a next one from a lead later.
	n := changes.Load()
	start := time.Now().Truncate(time.Second)
	rev, err := c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: phone.ID, Overlap: true}))
	if err != nil || rev.Msg.User != "alice" || rev.Msg.Device != "phone" || rev.Msg.Credentials != 1 || rev.Msg.Already ||
		rev.Msg.SwitchAt < start.Add(r.Lead).Unix() || rev.Msg.SwitchAt > time.Now().Add(r.Lead).Unix() ||
		rev.Msg.Until != rev.Msg.SwitchAt+int64(r.Grace/time.Second) {
		t.Fatalf("revoke with overlap: %v %v", rev, err)
	}
	if changes.Load() == n {
		t.Fatal("the revocation was not applied")
	}
	after := export("alice")
	if after.Link != before.Link || after.NextLink == "" || uuid(after.NextLink) == uuid(before.Link) || after.NextFrom != rev.Msg.SwitchAt {
		t.Fatalf("after the revocation with overlap: %+v, was %+v", after, before)
	}
	seen = append(seen, uuid(after.NextLink))
	if b := export("bob"); b.Link != bob.Link || b.NextLink != "" {
		t.Fatalf("bob's links: %+v", b)
	}
	again, err := c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: phone.ID, Overlap: true}))
	if err != nil || !again.Msg.Already || again.Msg.SwitchAt != 0 || export("alice").NextLink != after.NextLink {
		t.Fatalf("a repeat: %v %v", again, err)
	}

	// From an admin device, with overlap too: the next link replaced.
	addr, pin := startRemote(t, srv)
	inv, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "bob", Name: "laptop", Role: "admin"}))
	if err != nil {
		t.Fatal(err)
	}
	admin := newRemoteDevice(t, addr, pin)
	if _, err := admin.register(ctx, inv.Msg.InviteCode, time.Now().Unix()/60); err != nil {
		t.Fatal(err)
	}
	remote, err := admin.node.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: tablet.ID, Overlap: true}))
	if err != nil || remote.Msg.Credentials != 1 || remote.Msg.SwitchAt < rev.Msg.SwitchAt {
		t.Fatalf("with overlap from an admin device: %v %v", remote, err)
	}
	byAdmin := export("alice")
	if byAdmin.Link != before.Link || byAdmin.NextLink == "" || uuid(byAdmin.NextLink) == uuid(after.NextLink) {
		t.Fatalf("after the admin device's revocation: %+v", byAdmin)
	}
	seen = append(seen, uuid(byAdmin.NextLink))

	// Without overlap: the link new at once, no next, no times.
	plain, err := c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: watch.ID}))
	if err != nil || plain.Msg.Credentials != 1 || plain.Msg.SwitchAt != 0 || plain.Msg.Until != 0 {
		t.Fatalf("revoke without overlap: %v %v", plain, err)
	}
	final := export("alice")
	if final.Link == before.Link || final.NextLink != "" {
		t.Fatalf("after the revocation without overlap: %+v", final)
	}
	seen = append(seen, uuid(final.Link))

	entries, err := srv.Store.ListAudit(ctx, 30)
	if err != nil {
		t.Fatal(err)
	}
	var revokes []store.AuditEntry
	for _, e := range entries {
		if e.Action == "device.revoke" {
			revokes = append(revokes, e)
		}
		for _, sec := range seen {
			if strings.Contains(e.Target+e.Result, sec) {
				t.Errorf("a credential in the audit: %+v", e)
			}
		}
	}
	want := []string{ // newest first
		watch.ID + " alice/watch: 1 credentials of alice new",
		tablet.ID + " alice/tablet: with overlap: 1 credentials of alice rotate: next published, switch at " + at(remote.Msg.SwitchAt) +
			", the old ones accepted until " + at(remote.Msg.Until),
		phone.ID + " alice/phone: revoked already, nothing changed",
		phone.ID + " alice/phone: with overlap: 1 credentials of alice rotate: next published, switch at " + at(rev.Msg.SwitchAt) +
			", the old ones accepted until " + at(rev.Msg.Until),
	}
	if len(revokes) != 4 {
		t.Fatalf("audit %+v", revokes)
	}
	for i, w := range want {
		if revokes[i].Target != w {
			t.Errorf("audit %d: %q, want %q", i, revokes[i].Target, w)
		}
	}
	if !strings.HasPrefix(revokes[1].Actor, "bob/laptop") {
		t.Errorf("the admin device's revocation by %q", revokes[1].Actor)
	}
}
