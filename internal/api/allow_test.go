package api

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	devicev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
)

// TestDeviceAllow: an integration's addresses (integrations-v1 §3.2). The
// remote API listens on 127.0.0.1 here, which the API refuses in a list:
// those lists go into the store directly.
func TestDeviceAllow(t *testing.T) {
	srv, sock, _ := startServer(t)
	srv.LocalAddrs = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("203.0.113.5")}, nil }
	ctx := context.Background()
	c := NewUnixClient(sock)
	for _, svc := range [][2]string{{"api", "api"}, {"reality", "r1"}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: svc[0], Name: svc[1]})); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"integrations", "ops", "alice"} {
		var services []string
		if name == "alice" {
			services = []string{"r1"}
		}
		if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: name, Services: services})); err != nil {
			t.Fatal(err)
		}
	}
	addr, pin := startRemote(t, srv)
	now := time.Now().Unix() / 60
	enroll := func(user, name, role string) (remoteDevice, string) {
		t.Helper()
		resp, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: user, Name: name, Role: role}))
		if err != nil {
			t.Fatalf("%s invite: %v", role, err)
		}
		d := newRemoteDevice(t, addr, pin)
		reg, err := d.register(ctx, resp.Msg.InviteCode, now)
		if err != nil {
			t.Fatalf("%s register: %v", role, err)
		}
		return d, reg.DeviceId
	}
	bill, billID := enroll("integrations", "billing", "billing")
	ops, opsID := enroll("ops", "laptop", "admin")
	phone, _ := enroll("alice", "phone", "user")
	selfOK := func(d remoteDevice) error {
		_, err := d.dev.GetSelf(ctx, connect.NewRequest(&devicev1.GetSelfRequest{}))
		return err
	}

	// What the API takes.
	set := func(id string, prefixes ...string) (*nodev1.SetDeviceAllowResponse, error) {
		r, err := c.SetDeviceAllow(ctx, connect.NewRequest(&nodev1.SetDeviceAllowRequest{Id: id, Prefixes: prefixes}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	for _, bad := range []string{"127.0.0.1", "203.0.113.0/28", "198.51.100.0/24", "billing.example.net"} {
		if _, err := set(billID, bad); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	if _, err := set(opsID, "198.51.100.7"); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("an admin's device: %v", err)
	}
	// The device and its role before the addresses (§3.3).
	if _, err := set(opsID, "203.0.113.5"); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("an admin's device with the node's address: %v", err)
	}
	if _, err := set("nope", "203.0.113.5"); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("no such device: %v", err)
	}
	r, err := set(billID, "198.51.100.7", "10.0.0.7")
	if err != nil || len(r.Device.Allow) != 2 || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "private") {
		t.Fatalf("set: %+v %v", r, err)
	}
	// The perimeter opens the API's TCP port to them; ports says so.
	p := &PerimeterServer{Server: srv, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour}
	snap, err := p.snapshot(ctx)
	if err != nil || !slices.Equal(snap.IntegPrefixes, []string{"10.0.0.7/32", "198.51.100.7/32"}) || len(snap.IntegPorts) != 1 || snap.IntegPorts[0].Proto != "tcp" {
		t.Fatalf("snapshot: %v %v %v", snap.GetIntegPrefixes(), snap.GetIntegPorts(), err)
	}
	for _, d := range snap.Devices {
		if d.Id == billID {
			t.Fatal("a device with addresses knocks no more: not in the snapshot")
		}
	}
	ports, _ := c.GetPorts(ctx, connect.NewRequest(&nodev1.GetPortsRequest{}))
	if !slices.ContainsFunc(ports.Msg.Ports, func(np *nodev1.NodePort) bool { return np.Name == "api" && np.Access == "spa,static" }) {
		t.Fatalf("ports: %v", ports.Msg.Ports)
	}
	// A relay inside an integration's addresses would lose its devices,
	// the integration's user disabled or not.
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "rl", Address: "198.51.100.7"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a relay at an integration's address: %v", err)
	}
	if _, err := c.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "integrations", Enabled: false})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "rl", Address: "198.51.100.7"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a relay at a disabled integration's address: %v", err)
	}
	if snap, _ := p.snapshot(ctx); len(snap.IntegPrefixes) != 0 {
		t.Fatalf("a disabled user's device's addresses in the perimeter: %v", snap.IntegPrefixes)
	}
	if _, err := c.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "integrations", Enabled: true})); err != nil {
		t.Fatal(err)
	}
	// Blank entries are no list; an invite of another role says so before
	// the addresses are looked at (they would tell the node's and the
	// relays').
	if _, err := set(billID, " ", ""); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("blank entries: %v", err)
	}
	if _, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: "tab", Role: "user", Allow: []string{"203.0.113.5"}})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a user's invite with the node's address: %v", err)
	}

	// Calling from elsewhere (127.0.0.1): refused, once in the audit; the
	// others go on.
	for range 3 {
		if err := selfOK(bill); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("billing from outside its addresses: %v", err)
		}
	}
	if _, err := bill.node.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("billing's NodeService from outside its addresses: %v", err)
	}
	if n := countAudit(t, srv, "api.address"); n != 2 { // GetSelf, ListUsers
		t.Fatalf("api.address lines: %d", n)
	}
	if err := selfOK(ops); err != nil {
		t.Fatalf("the admin from an address in no list: %v", err)
	}

	// The node's address in billing's list (the store: the API refuses
	// loopback): billing calls; the admin and the user from it do not.
	if _, err := srv.Store.SetDeviceAllow(ctx, billID, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}); err != nil {
		t.Fatal(err)
	}
	if err := selfOK(bill); err != nil {
		t.Fatalf("billing from its address: %v", err)
	}
	if _, err := bill.node.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{})); err != nil {
		t.Fatalf("billing's NodeService from its address: %v", err)
	}
	for name, d := range map[string]remoteDevice{"admin": ops, "user": phone} {
		if err := selfOK(d); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("the %s from an integration's address: %v", name, err)
		}
	}
	// Its last call is kept.
	ds, _ := c.ListDevices(ctx, connect.NewRequest(&nodev1.ListDevicesRequest{User: "integrations"}))
	if len(ds.Msg.Devices) != 1 || ds.Msg.Devices[0].LastCall == 0 || !slices.Equal(ds.Msg.Devices[0].Allow, []string{"127.0.0.1/32"}) {
		t.Fatalf("listed: %+v", ds.Msg.Devices)
	}

	// Register from an integration's address: only an invite whose list
	// holds it, and a refusal spends no PIN try.
	inv, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "ops", Name: "spare", Role: "admin", Pin: true}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newRemoteDevice(t, addr, pin).registerPIN(ctx, inv.Msg.InviteCode, now, inv.Msg.Pin); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("an admin's invite from an integration's address: %v", err)
	}
	lst, _ := c.ListDevices(ctx, connect.NewRequest(&nodev1.ListDevicesRequest{User: "ops"}))
	if len(lst.Msg.Invites) != 1 || lst.Msg.Invites[0].PinTries != store.InvitePinTries {
		t.Fatalf("the invite after the refusal: %+v", lst.Msg.Invites)
	}
	sup, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "integrations", Name: "support", Role: "support", Allow: []string{"198.51.100.8"}}))
	if err != nil || len(sup.Msg.Invite.Allow) != 1 {
		t.Fatalf("an invite with addresses: %+v %v", sup, err)
	}
	if _, err := newRemoteDevice(t, addr, pin).register(ctx, sup.Msg.InviteCode, now); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("an invite from outside its addresses: %v", err)
	}
	if _, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "ops", Name: "x", Role: "admin", Allow: []string{"198.51.100.9"}})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("an admin's invite with addresses: %v", err)
	}
	audit, _ := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{}))
	var allowLine, inviteLine bool
	for _, e := range audit.Msg.Entries {
		allowLine = allowLine || e.Action == "device.allow" && e.Target == billID+" integrations/billing: 10.0.0.7/32,198.51.100.7/32"
		inviteLine = inviteLine || e.Action == "invite.create:support:allow" && e.Target == "integrations/support: 198.51.100.8/32"
	}
	if !allowLine || !inviteLine {
		t.Fatalf("audit: device.allow %v, invite %v", allowLine, inviteLine)
	}

	// Cleared: billing knocks again, the admin calls from the address.
	if r, err := set(billID); err != nil || len(r.Device.Allow) != 0 {
		t.Fatalf("clear: %+v %v", r, err)
	}
	if err := selfOK(ops); err != nil {
		t.Fatalf("the admin after the list is cleared: %v", err)
	}
	if err := selfOK(bill); err != nil {
		t.Fatalf("billing in SPA mode: %v", err)
	}
	audit, _ = c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{}))
	if !slices.ContainsFunc(audit.Msg.Entries, func(e *nodev1.AuditEntry) bool {
		return e.Action == "device.allow" && e.Target == billID+" integrations/billing: cleared"
	}) {
		t.Fatal("no cleared line")
	}
}

func TestProcedureName(t *testing.T) {
	if got := procedureName("/raycontrol.node.v1.NodeService/ListUsers"); got != "ListUsers" {
		t.Fatal(got)
	}
	for _, junk := range []string{"/x/evil\nfake-line", "/raycontrol.node.v1.NodeService/Nope", ""} {
		if got := procedureName(junk); got != "other" {
			t.Fatalf("%q: %q", junk, got)
		}
	}
}

// TestCheckSourceNoAddress: while lists exist, a call with no address to
// check gets nowhere.
func TestCheckSourceNoAddress(t *testing.T) {
	srv, _, _ := startServer(t)
	ctx := context.Background()
	r := &Remote{Server: srv}
	if _, err := r.checkSource(ctx, "pipe", "", "/raycontrol.device.v1.DeviceService/GetSelf"); err != nil {
		t.Fatalf("no lists: %v", err)
	}
	if _, err := srv.Store.CreateUser(ctx, store.User{Name: "integrations", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.Store.CreateInviteAllow(ctx, "integrations", "billing", "billing", time.Hour,
		[]netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.checkSource(ctx, "pipe", "", "/raycontrol.device.v1.DeviceService/GetSelf"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("no address with lists: %v", err)
	}
	if _, err := r.checkSource(ctx, "[fe80::1%eth0]:443", "", "/raycontrol.device.v1.DeviceService/GetSelf"); err != nil {
		t.Fatalf("a zoned address in no list: %v", err)
	}
}

// TestIntegPort: the port the snapshot opens to integrations' servers is
// the one rayd serves the API on, never SSH's.
func TestIntegPort(t *testing.T) {
	ssh := map[store.Port]bool{{Proto: "tcp", Num: 22}: true}
	for _, tc := range []struct {
		svc  store.Service
		want string
	}{
		{store.Service{Kind: "api", Enabled: true, Settings: `{"ports":["tcp/48213","tcp/9443"]}`}, "tcp/48213"},
		{store.Service{Kind: "api", Enabled: true, Settings: `{"ports":["tcp/22","tcp/9443"]}`}, ""}, // an older store's
		{store.Service{Kind: "api", Enabled: true, Settings: `{"ports":["udp/48213"]}`}, ""},
		{store.Service{Kind: "api", Enabled: false, Settings: `{"ports":["tcp/48213"]}`}, ""},
		{store.Service{Kind: "subscription", Enabled: true, Settings: `{"ports":["tcp/48214"]}`}, ""},
	} {
		got := ""
		if p, ok := integPort(tc.svc, ssh); ok {
			got = p.String()
		}
		if got != tc.want {
			t.Errorf("%s: %q, want %q", tc.svc.Settings, got, tc.want)
		}
	}
}
