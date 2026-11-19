package api

import (
	"context"
	"flag"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"

	visibility "github.com/arngory/raycontrol/internal/gen/google/api"
	devicev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/store"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/integration-fields.txt")

// The roles of every method (integrations-v1 §2.3): each method names
// them in its proto, and the table here is the spec's. A new method fails
// this test until it is put in both.
func TestMethodRoles(t *testing.T) {
	const (
		all     = "ADMIN,BILLING,SUPPORT"
		billing = "ADMIN,BILLING"
		support = "ADMIN,SUPPORT"
		admin   = "ADMIN"
		root    = "NODE"
		anyone  = "ADMIN,BILLING,SUPPORT,USER"
	)
	want := map[string]string{
		"NodeService/GetStatus": all, "NodeService/ListUsers": all, "NodeService/GetUser": all,
		"NodeService/ListServices": all, "NodeService/ListDevices": all,
		"NodeService/CreateUser": billing, "NodeService/SetUserEnabled": billing, "NodeService/SetUserServices": billing,
		"NodeService/DeleteUser": billing, "NodeService/SetUserTraffic": billing, "NodeService/RenewUser": billing,
		"NodeService/SetUserExpiry": billing, "NodeService/RevokeDevice": billing, "NodeService/CreateInvite": billing,
		"NodeService/GetMetrics": support, "NodeService/GetUpdateStatus": support, "NodeService/GetStats": support,
		"NodeService/SetUserLAN": admin, "NodeService/ExportUser": admin, "NodeService/CreateService": admin,
		"NodeService/SetServiceEnabled": admin, "NodeService/DeleteService": admin, "NodeService/RotateService": admin,
		"NodeService/SetServiceOption": admin, "NodeService/GetYggdrasilPeerKeys": admin, "NodeService/CreateDevice": admin,
		"NodeService/ListAudit": admin, "NodeService/GetAdminAccess": admin, "NodeService/SetAdminAccess": admin,
		"NodeService/ListRelays": admin, "NodeService/SetRelayAccess": admin, "NodeService/SetDNSProvider": admin,
		"NodeService/GetDNS": admin, "NodeService/SyncDNS": admin, "NodeService/RemoveDNS": admin,
		"NodeService/CheckDNSZones": admin, "NodeService/GetSummary": admin, "NodeService/SetSummary": admin,
		"NodeService/GetAppMirror": admin, "NodeService/SetAppMirror": admin, "NodeService/StartUpdate": admin,
		"NodeService/SetNodeName": admin, "NodeService/SetNodeNote": admin, "NodeService/GetClientPolicy": admin,
		"NodeService/SetClientPolicy": admin, "NodeService/GetPorts": admin,
		"NodeService/GetIntegrationSettings": admin, "NodeService/SetIntegrationSettings": admin,
		"NodeService/SetCertificate": root, "NodeService/AddRelay": root, "NodeService/RemoveRelay": root,
		"NodeService/IssueRelayBundle": root, "NodeService/Backup": root, "NodeService/SetDebug": root,
		"NodeService/GetEgress": root, "NodeService/SetEgress": root, "NodeService/GetConnLimit": root,
		"NodeService/SetConnLimit": root, "NodeService/GetDeployment": root, "NodeService/GetDeployInputs": root,
		"DeviceService/Register": anyone, "DeviceService/GetSelf": anyone, "DeviceService/RotateCertificate": all,
	}
	seen := map[string]bool{}
	for _, fd := range []protoreflect.FileDescriptor{nodev1.File_raycontrol_node_v1_node_proto, devicev1.File_raycontrol_device_v1_device_proto} {
		services := fd.Services()
		for i := range services.Len() {
			svc := services.Get(i)
			for j := range svc.Methods().Len() {
				m := svc.Methods().Get(j)
				key := string(svc.Name()) + "/" + string(m.Name())
				seen[key] = true
				// Written out on every method, not left to the default.
				labels := ruleLabels(m.Options(), visibility.E_MethodVisibility)
				if got := strings.Join(labels, ","); got != want[key] {
					t.Errorf("%s: %q, the spec says %q", key, got, want[key])
				}
				if slices.Contains(labels, labelNode) && len(labels) != 1 {
					t.Errorf("%s: NODE with others: %v", key, labels)
				}
				procedure := "/" + string(svc.FullName()) + "/" + string(m.Name())
				if !slices.Equal(methodRoles[procedure], labels) {
					t.Errorf("%s: the table has %v", key, methodRoles[procedure])
				}
			}
		}
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("%s: no such method", key)
		}
	}
	if mayCall("/raycontrol.node.v1.NodeService/Backup", "admin") || !mayCall("/raycontrol.node.v1.NodeService/GetUser", "support") ||
		mayCall("/raycontrol.node.v1.NodeService/GetUser", "user") || mayCall("/raycontrol.node.v1.NodeService/GetUser", "") {
		t.Error("mayCall")
	}
}

// What billing and support see of every answer they may have, field by
// field: a field added to one of them fails this test until it is looked
// at, and the list rewritten (go test -run TestRoleFields -update). The
// list is the review of what an integration reads.
func TestRoleFields(t *testing.T) {
	known := []string{labelAdmin, labelBilling, labelSupport, labelUser, labelNode, labelNotes}
	var out []string
	for _, role := range []string{labelBilling, labelSupport} {
		seen := map[protoreflect.FullName]bool{}
		var walk func(md protoreflect.MessageDescriptor)
		walk = func(md protoreflect.MessageDescriptor) {
			if seen[md.FullName()] {
				return
			}
			seen[md.FullName()] = true
			for i := range md.Fields().Len() {
				fd := md.Fields().Get(i)
				labels := fieldLabels(fd)
				for _, l := range labels {
					if !slices.Contains(known, l) {
						t.Errorf("%s: unknown label %q", fd.FullName(), l)
					}
				}
				if labels != nil && !slices.Contains(labels, labelAdmin) {
					t.Errorf("%s: hidden from admins", fd.FullName())
				}
				line := role + " " + string(fd.FullName())
				switch {
				case labels == nil || slices.Contains(labels, role):
				case role == labelSupport && slices.Contains(labels, labelNotes):
					line += " (if the administrator allows)"
				default:
					continue
				}
				out = append(out, line)
				if fd.IsMap() {
					fd = fd.MapValue()
				}
				if fd.Message() != nil {
					walk(fd.Message())
				}
			}
		}
		for _, fd := range []protoreflect.FileDescriptor{nodev1.File_raycontrol_node_v1_node_proto, devicev1.File_raycontrol_device_v1_device_proto} {
			for i := range fd.Services().Len() {
				svc := fd.Services().Get(i)
				for j := range svc.Methods().Len() {
					m := svc.Methods().Get(j)
					if slices.Contains(methodRoles["/"+string(svc.FullName())+"/"+string(m.Name())], role) {
						walk(m.Output())
					}
				}
			}
		}
	}
	slices.Sort(out)
	got := strings.Join(out, "\n") + "\n"
	const path = "testdata/integration-fields.txt"
	if *updateGolden {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != got {
		t.Errorf("what integrations see changed: look at it, then go test -run TestRoleFields -update\n%s", lineDiff(string(b), got))
	}
}

// lineDiff lists the lines only one of a and b has.
func lineDiff(a, b string) string {
	as, bs := strings.Split(a, "\n"), strings.Split(b, "\n")
	var d []string
	for _, l := range as {
		if !slices.Contains(bs, l) {
			d = append(d, "- "+l)
		}
	}
	for _, l := range bs {
		if !slices.Contains(as, l) {
			d = append(d, "+ "+l)
		}
	}
	return strings.Join(d, "\n")
}

// Every kind the node knows is a data service billing may give, or one it
// may not: a new kind is a decision (integrations-v1 §2.2).
func TestDataKinds(t *testing.T) {
	notData := []string{"site", "subscription", "api", "ssh"}
	for _, k := range store.ServiceKinds {
		if dataKinds[k] == slices.Contains(notData, k) {
			t.Errorf("kind %s: data %v", k, dataKinds[k])
		}
	}
	for k := range dataKinds {
		if !slices.Contains(store.ServiceKinds, k) {
			t.Errorf("kind %s: unknown", k)
		}
	}
}

// billing and support through the remote API (integrations-v1 §2): by
// invite to a user without services, the API alone in their bundle and
// SPA scope; the methods of their role only, refusals in the audit once
// in ten minutes; regular users only, service users as unknown ones;
// billing gives data services and user invites only; the answers without
// what the role does not see.
func TestIntegrationRoles(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	for _, svc := range [][2]string{{"api", "api"}, {"reality", "r1"}, {"naive", "n1"}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: svc[0], Name: svc[1]})); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []struct{ name, note string }{{"integrations", ""}, {"alice", "Alice, +1 555 0100"}, {"carol", ""}, {"ops", ""}} {
		services := []string{"r1"}
		if u.name == "integrations" {
			services = nil
		}
		if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: u.name, Note: u.note, Services: services})); err != nil {
			t.Fatal(err)
		}
	}
	addr, pin := startRemote(t, srv)
	now := time.Now().Unix() / 60
	enroll := func(user, name, role string) (remoteDevice, *devicev1.RegisterResponse) {
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
		return d, reg
	}

	// The user of an integration has no services: no such invite to a
	// user with some, no services to a user with one.
	if _, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: "bot", Role: "billing"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a billing invite to a user with services: %v", err)
	}
	if _, err := c.CreateDevice(ctx, connect.NewRequest(&nodev1.CreateDeviceRequest{User: "integrations", Name: "bot", Role: "billing"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a billing device without an invite: %v", err)
	}
	bill, reg := enroll("integrations", "billing", "billing")
	sup, _ := enroll("integrations", "support", "support")
	_, _ = enroll("ops", "laptop", "admin")
	if _, err := c.SetUserServices(ctx, connect.NewRequest(&nodev1.SetUserServicesRequest{Name: "integrations", Services: []string{"r1"}})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("services to an integration's user: %v", err)
	}

	// The API alone: in the bundle and in the SPA scope.
	b, err := node.DecodeBundle(reg.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Role != "billing" || b.API == nil || b.Sub != nil || len(b.Services) != 1 || b.Services[0].Kind != "api" {
		t.Fatalf("billing's bundle: %+v", b)
	}
	devices, err := srv.Store.SPADevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devices {
		if d.ID == reg.DeviceId && (len(d.Allowed) != 1 || int(d.Allowed[0]) != int(b.Services[0].ID)) {
			t.Fatalf("billing's scope: %v", d.Allowed)
		}
	}

	// Regular users only.
	users, err := bill.node.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, u := range users.Msg.Users {
		names = append(names, u.Name)
	}
	if !slices.Equal(names, []string{"alice", "carol"}) {
		t.Fatalf("billing lists %v", names)
	}
	for _, call := range []func() error{
		func() error {
			_, err := bill.node.GetUser(ctx, connect.NewRequest(&nodev1.GetUserRequest{Name: "ops"}))
			return err
		},
		func() error {
			_, err := bill.node.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "ops"}))
			return err
		},
		func() error {
			_, err := bill.node.DeleteUser(ctx, connect.NewRequest(&nodev1.DeleteUserRequest{Name: "integrations"}))
			return err
		},
		func() error {
			_, err := bill.node.SetUserExpiry(ctx, connect.NewRequest(&nodev1.SetUserExpiryRequest{Name: "ops", ExpiresAt: 1}))
			return err
		},
		func() error {
			_, err := bill.node.RenewUser(ctx, connect.NewRequest(&nodev1.RenewUserRequest{Name: "ops"}))
			return err
		},
		func() error {
			_, err := bill.node.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "ops", Name: "x"}))
			return err
		},
		func() error {
			_, err := bill.node.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: reg.DeviceId}))
			return err
		},
	} {
		if err := call(); connect.CodeOf(err) != connect.CodeNotFound {
			t.Errorf("a service user to billing: %v", err)
		}
	}
	if _, err := bill.node.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "ops"})); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Errorf("a service user's name: %v", err)
	}
	devs, err := bill.node.ListDevices(ctx, connect.NewRequest(&nodev1.ListDevicesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs.Msg.Devices {
		t.Errorf("billing sees the device %s/%s", d.User, d.Name)
	}

	// What billing does to regular users, and may not.
	if _, err := bill.node.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "dave", Services: []string{"n1"}})); err != nil {
		t.Fatal(err)
	}
	if _, err := bill.node.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "eve", Services: []string{"api"}})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("billing gives the api service: %v", err)
	}
	if _, err := bill.node.SetUserServices(ctx, connect.NewRequest(&nodev1.SetUserServicesRequest{Name: "alice", Services: []string{"r1", "api"}})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("billing gives the api service: %v", err)
	}
	if _, err := bill.node.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "carol"})); err != nil {
		t.Fatal(err)
	}
	// A failed call of an integration: in the audit once in a while.
	for range 3 {
		if _, err := bill.node.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "nobody", Enabled: true})); connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("an unknown user: %v", err)
		}
	}
	for _, role := range []string{"admin", "billing", "support"} {
		if _, err := bill.node.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: "x", Role: role})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("billing invites %s: %v", role, err)
		}
	}
	inv, err := bill.node.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: "phone"}))
	if err != nil || inv.Msg.InviteCode == "" {
		t.Fatalf("billing invites a user's device: %v", err)
	}
	before := time.Now().Unix()
	exp, err := bill.node.SetUserExpiry(ctx, connect.NewRequest(&nodev1.SetUserExpiryRequest{Name: "alice", ExpiresAt: 1}))
	if err != nil || exp.Msg.User.ExpiresAt < before || exp.Msg.User.ExpiresAt > time.Now().Unix() {
		t.Fatalf("expire now: %v %v", exp, err)
	}
	if exp, err := bill.node.SetUserExpiry(ctx, connect.NewRequest(&nodev1.SetUserExpiryRequest{Name: "alice"})); err != nil || exp.Msg.User.ExpiresAt != 0 {
		t.Fatalf("never: %v %v", exp, err)
	}
	if r, err := bill.node.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: inv.Msg.Invite.Id})); err != nil || !r.Msg.Invite {
		t.Fatalf("billing withdraws an invite: %v %v", r, err)
	}

	// The answers without what the role does not see.
	got, err := bill.node.GetUser(ctx, connect.NewRequest(&nodev1.GetUserRequest{Name: "alice"}))
	if err != nil || got.Msg.User.Note == "" {
		t.Fatalf("billing reads the note: %v %v", got, err)
	}
	got, err = sup.node.GetUser(ctx, connect.NewRequest(&nodev1.GetUserRequest{Name: "alice"}))
	if err != nil || got.Msg.User.Note != "" || got.Msg.User.Name != "alice" {
		t.Fatalf("support reads the note: %v %v", got, err)
	}
	svcs, err := sup.node.ListServices(ctx, connect.NewRequest(&nodev1.ListServicesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range svcs.Msg.Services {
		if s.SettingsJson != "" || s.CreatedAt != 0 || s.Uid != 0 || s.Sni != "" || s.Name == "" || s.Kind == "" {
			t.Errorf("support sees of a service %v", s)
		}
	}
	srv.Health = &health.Board{}
	srv.Health.Done("acme secret-site.example.org", nil)
	st, err := sup.node.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
	if err != nil || st.Msg.Host != "" || len(st.Msg.SpaPorts) != 0 || st.Msg.Version == "" {
		t.Fatalf("support's status: %v %v", st, err)
	}
	if len(st.Msg.Loops) != 1 || st.Msg.Loops[0].Name != "acme" {
		t.Errorf("support sees the loops %v", st.Msg.Loops)
	}
	all, err := c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
	if err != nil || all.Msg.Users != st.Msg.Users || all.Msg.ActiveDevices != st.Msg.ActiveDevices {
		t.Errorf("the counts differ: %v and %v (%v)", all.Msg, st.Msg, err)
	}
	m, err := sup.node.GetMetrics(ctx, connect.NewRequest(&nodev1.GetMetricsRequest{}))
	if err != nil || strings.Contains(m.Msg.Text, "secret-site") || !strings.Contains(m.Msg.Text, `loop="acme"`) {
		t.Errorf("support reads the metrics: %v\n%s", err, m.Msg.GetText())
	}
	if self, err := sup.dev.GetSelf(ctx, connect.NewRequest(&devicev1.GetSelfRequest{})); err != nil || self.Msg.Role != "support" {
		t.Errorf("support's self: %v %v", self, err)
	}

	// The rest of the API is not theirs; a refusal is in the audit once.
	for _, d := range []remoteDevice{bill, sup} {
		if _, err := d.node.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "naive", Name: "n2"})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("an integration creates a service: %v", err)
		}
		if _, err := d.node.ExportUser(ctx, connect.NewRequest(&nodev1.ExportUserRequest{Name: "alice"})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("an integration exports a user: %v", err)
		}
		if _, err := d.node.Backup(ctx, connect.NewRequest(&nodev1.BackupRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("an integration's backup: %v", err)
		}
	}
	if _, err := sup.node.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "alice"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("support changes a user: %v", err)
	}
	if _, err := bill.node.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "naive", Name: "n2"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("billing creates a service: %v", err)
	}
	audit, err := srv.Store.ListAudit(ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	denied, changes, failed := 0, 0, 0
	for _, e := range audit {
		switch {
		case e.Action == "api.denied" && e.Actor == "integrations/billing (billing)" && e.Target == "CreateService":
			denied++
		case e.Actor == "integrations/billing (billing)" && e.Action == "user.enable=false" && e.Target == "carol":
			changes++
		}
		if e.Action == "user.expires=now" && e.Actor != "integrations/billing (billing)" {
			t.Errorf("the expiry by %q", e.Actor)
		}
		if e.Action == "user.enable=true" && e.Target == "nobody" {
			failed++
		}
	}
	if denied != 1 || changes != 1 || failed != 1 {
		t.Errorf("audit: %d refusals of CreateService, %d changes by billing, %d failures", denied, changes, failed)
	}
}
