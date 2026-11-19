package api

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// Every NodeService method an integration may call counts against one
// class of its rate limits.
func TestCallClasses(t *testing.T) {
	for procedure, labels := range methodRoles {
		if !strings.HasPrefix(procedure, "/"+nodev1connect.NodeServiceName+"/") {
			continue
		}
		if !slices.Contains(labels, labelBilling) && !slices.Contains(labels, labelSupport) {
			continue
		}
		if _, ok := callClasses[methodName(procedure)]; !ok {
			t.Errorf("%s: no class", procedure)
		}
	}
}

// A token bucket: the burst at once, then the rate.
func TestBucket(t *testing.T) {
	r := limitRate{Burst: 3, PerHour: 3600} // one a second
	var b bucket
	now := time.Unix(1_700_000_000, 0)
	for i := range 3 {
		if !b.take(r, now) {
			t.Fatalf("take %d of the burst", i)
		}
	}
	if b.take(r, now) {
		t.Fatal("past the burst")
	}
	if b.take(r, now.Add(500*time.Millisecond)) || !b.take(r, now.Add(1100*time.Millisecond)) {
		t.Fatal("refill")
	}
	if b.take(limitRate{}, now) {
		t.Fatal("no rate: no call")
	}
}

// Stage 1b (integrations-v1 §2.4, §2.6, §2.2): root's limits and mass
// limit, refused to others; the rate limits refuse with resource_exhausted
// and an audit line once; billing's disables and deletions past the hour's
// limit need confirm_mass; billing turns the traffic counting neither on
// nor off unless an administrator keeps it on; support sees notes when an
// administrator lets it.
func TestIntegrationLimits(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	as := func(uid uint32) context.Context {
		return context.WithValue(context.WithValue(ctx, peerKey{}, &unix.Ucred{Uid: uid}), actorKey{}, "test")
	}
	for _, svc := range [][2]string{{"api", "api"}, {"reality", "n1"}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: svc[0], Name: svc[1]})); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"integrations", "u1", "u2", "u3", "u4"} {
		var services []string
		if name != "integrations" {
			services = []string{"n1"}
		}
		if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: name, Services: services, Note: "note of " + name})); err != nil {
			t.Fatal(err)
		}
	}
	addr, pin := startRemote(t, srv)
	minute := time.Now().Unix() / 60
	enroll := func(name, role string) remoteDevice {
		t.Helper()
		resp, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "integrations", Name: name, Role: role}))
		if err != nil {
			t.Fatal(err)
		}
		d := newRemoteDevice(t, addr, pin)
		if _, err := d.register(ctx, resp.Msg.InviteCode, minute); err != nil {
			t.Fatal(err)
		}
		return d
	}
	bill, sup := enroll("billing", "billing"), enroll("support", "support")
	set := func(uid uint32, req *nodev1.SetIntegrationSettingsRequest) error {
		_, err := srv.SetIntegrationSettings(as(uid), connect.NewRequest(req))
		return err
	}

	// Root's settings are root's.
	two := uint32(2)
	if err := set(1000, &nodev1.SetIntegrationSettingsRequest{MassLimit: &two}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("the mass limit by the group: %v", err)
	}
	support := &nodev1.IntegrationLimitsFor{Role: "support", Limits: &nodev1.IntegrationLimits{Read: &nodev1.Rate{Burst: 3, PerHour: 1}}}
	if err := set(1000, &nodev1.SetIntegrationSettingsRequest{Limits: support}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("limits by the group: %v", err)
	}
	if err := set(0, &nodev1.SetIntegrationSettingsRequest{MassLimit: &two, Limits: support}); err != nil {
		t.Fatal(err)
	}
	bad := &nodev1.IntegrationLimitsFor{Role: "admin", Limits: &nodev1.IntegrationLimits{Inflight: 2}}
	if err := set(0, &nodev1.SetIntegrationSettingsRequest{Limits: bad}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("limits for admins: %v", err)
	}

	// The rate limits: support's three reads, then none.
	for i := range 3 {
		if _, err := sup.node.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{})); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	for range 2 {
		if _, err := sup.node.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{})); connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("over the limit: %v", err)
		}
	}

	// Support's sight of notes: off by default, the administrator's.
	notes := func() string {
		t.Helper()
		if err := set(0, &nodev1.SetIntegrationSettingsRequest{Limits: &nodev1.IntegrationLimitsFor{Role: "support"}, ToDefault: true}); err != nil {
			t.Fatal(err)
		}
		u, err := sup.node.GetUser(ctx, connect.NewRequest(&nodev1.GetUserRequest{Name: "u1"}))
		if err != nil {
			t.Fatal(err)
		}
		return u.Msg.User.Note
	}
	if n := notes(); n != "" {
		t.Fatalf("support sees a note: %q", n)
	}
	on := true
	if err := set(1000, &nodev1.SetIntegrationSettingsRequest{SupportNotes: &on}); err != nil {
		t.Fatal(err)
	}
	if n := notes(); n != "note of u1" {
		t.Fatalf("support with notes on: %q", n)
	}

	// billing's mass actions: two an hour, then with confirm only.
	disable := func(name string, confirm bool) error {
		_, err := bill.node.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: name, ConfirmMass: confirm}))
		return err
	}
	if err := disable("nobody", false); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("an unknown user: %v", err) // not counted: it did nothing
	}
	if err := disable("u1", false); err != nil {
		t.Fatal(err)
	}
	if _, err := bill.node.DeleteUser(ctx, connect.NewRequest(&nodev1.DeleteUserRequest{Name: "u2"})); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := disable("u3", false); connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "confirm") {
			t.Fatalf("over the mass limit: %v", err)
		}
	}
	if _, err := bill.node.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "u3", Enabled: true})); err != nil {
		t.Fatalf("an enable is no mass action: %v", err)
	}
	if err := disable("u3", true); err != nil {
		t.Fatalf("confirmed: %v", err)
	}
	if _, err := c.DeleteUser(ctx, connect.NewRequest(&nodev1.DeleteUserRequest{Name: "u4"})); err != nil {
		t.Fatalf("root's deletion is not billing's: %v", err)
	}

	// The traffic counting: billing's first limit would turn it on.
	limit := int64(1 << 30)
	if _, err := bill.node.SetUserTraffic(ctx, connect.NewRequest(&nodev1.SetUserTrafficRequest{Name: "u1", LimitBytes: &limit})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("billing turns the counting on: %v", err)
	}
	if _, err := bill.node.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "u5", TrafficLimitBytes: limit})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("billing turns the counting on with a new user: %v", err)
	}
	counting := "on"
	if err := set(1000, &nodev1.SetIntegrationSettingsRequest{TrafficCounting: &counting}); err != nil {
		t.Fatal(err)
	}
	if _, err := bill.node.SetUserTraffic(ctx, connect.NewRequest(&nodev1.SetUserTrafficRequest{Name: "u1", LimitBytes: &limit})); err != nil {
		t.Fatalf("billing's limit with the counting kept on: %v", err)
	}
	none := int64(0)
	if _, err := bill.node.SetUserTraffic(ctx, connect.NewRequest(&nodev1.SetUserTrafficRequest{Name: "u1", LimitBytes: &none})); err != nil {
		t.Fatalf("billing's last limit off with the counting kept on: %v", err)
	}

	// What the node says of it all.
	st, err := srv.GetIntegrationSettings(as(1000), connect.NewRequest(&nodev1.GetIntegrationSettingsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Msg.SupportNotes || st.Msg.MassLimit != 2 || st.Msg.MassActions != 3 || st.Msg.MassRefused != 2 || st.Msg.TrafficCounting != "on" {
		t.Errorf("settings: %+v", st.Msg)
	}
	limited := map[string]uint64{}
	for _, d := range st.Msg.Devices {
		limited[d.Role] = d.Limited
		if d.Calls == 0 || d.LastCall == 0 {
			t.Errorf("device %s: %+v", d.Name, d)
		}
	}
	if limited["support"] != 2 || limited["billing"] != 0 {
		t.Errorf("limited: %v", limited)
	}
	audit, err := srv.Store.ListAudit(ctx, 300)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, e := range audit {
		count[e.Action]++
	}
	if count["api.limited"] != 1 || count["api.mass"] != 1 || count["user.enable=false confirm"] != 1 ||
		count["integration.set mass-limit=2"] != 1 || count["traffic.counting=on"] != 1 || count["integration.set support-notes=on"] != 1 {
		t.Errorf("audit: %v", count)
	}
	m, err := c.GetMetrics(ctx, connect.NewRequest(&nodev1.GetMetricsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`raycontrol_api_limited_total{role="support"} 2`,
		`raycontrol_integration_mass_actions_total{result="refused"} 2`,
		`raycontrol_integration_mass_actions_total{result="confirmed"} 1`,
		`raycontrol_api_calls_total{role="support",code="resource_exhausted"} 2`,
	} {
		if !strings.Contains(m.Msg.Text, want) {
			t.Errorf("metrics: no %s", want)
		}
	}
}
