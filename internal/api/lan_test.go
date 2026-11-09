package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// SetUserLAN (lan-v1 §1.1, §6): the administrator's consent in User.lan,
// a device's own in Device.lan; refused without a Yggdrasil service; every
// call audited, and a change wakes apply.
func TestSetUserLAN(t *testing.T) {
	srv, sock, changes := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	for _, s := range []store.Service{{Kind: "reality", Name: "reality"}, {Kind: "yggdrasil", Name: "ygg"}, {Kind: "hy2-masq", Name: "hy2"}} {
		s.Enabled = true
		if _, err := provision.CreateService(ctx, srv.Store, s); err != nil {
			t.Fatal(err)
		}
	}
	for name, svc := range map[string]string{"alice": "ygg", "bob": "hy2"} {
		if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: name, Services: []string{svc}})); err != nil {
			t.Fatal(err)
		}
	}
	d, err := c.CreateDevice(ctx, connect.NewRequest(&nodev1.CreateDeviceRequest{User: "alice", Name: "phone"}))
	if err != nil {
		t.Fatal(err)
	}
	before := changes.Load()
	r, err := c.SetUserLAN(ctx, connect.NewRequest(&nodev1.SetUserLANRequest{Name: "alice", Lan: true}))
	if err != nil || !r.Msg.User.Lan || r.Msg.User.Name != "alice" || changes.Load() != before+1 {
		t.Fatalf("on: %+v %v (changes %d)", r, err, changes.Load()-before)
	}
	if _, err := c.SetUserLAN(ctx, connect.NewRequest(&nodev1.SetUserLANRequest{Name: "bob", Lan: true})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bob without Yggdrasil: %v", err)
	}
	if _, err := c.SetUserLAN(ctx, connect.NewRequest(&nodev1.SetUserLANRequest{Name: "nobody", Lan: true})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("nobody: %v", err)
	}
	if changes.Load() != before+1 {
		t.Fatal("a refusal woke apply")
	}
	list, err := c.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range list.Msg.Users {
		if u.Lan != (u.Name == "alice") {
			t.Errorf("%s: lan %v", u.Name, u.Lan)
		}
	}
	devs, err := c.ListDevices(ctx, connect.NewRequest(&nodev1.ListDevicesRequest{User: "alice"}))
	if err != nil || len(devs.Msg.Devices) != 1 || devs.Msg.Devices[0].Lan {
		t.Fatalf("devices %+v %v", devs, err)
	}
	if _, err := srv.Store.SetDeviceLAN(ctx, d.Msg.Device.Id, true, store.LANShowEvery); err != nil {
		t.Fatal(err)
	}
	if devs, err = c.ListDevices(ctx, connect.NewRequest(&nodev1.ListDevicesRequest{User: "alice"})); err != nil || !devs.Msg.Devices[0].Lan {
		t.Fatalf("shown: %+v %v", devs, err)
	}
	if r, err = c.SetUserLAN(ctx, connect.NewRequest(&nodev1.SetUserLANRequest{Name: "alice"})); err != nil || r.Msg.User.Lan {
		t.Fatalf("off: %+v %v", r, err)
	}
	audit, err := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{Limit: 4}))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range audit.Msg.Entries {
		got = append(got, e.Action+" "+e.Target+" "+e.Result[:min(2, len(e.Result))])
	}
	want := []string{"user.lan=off alice ok", "user.lan=on nobody er", "user.lan=on bob er", "user.lan=on alice ok"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("audit %q, want %q", got, want)
		}
	}
}
