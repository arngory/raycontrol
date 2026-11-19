package api

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"

	devicev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1"
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
	// DeviceService's calls count too.
	if _, err := sup.dev.GetSelf(ctx, connect.NewRequest(&devicev1.GetSelfRequest{})); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("GetSelf over the limit: %v", err)
	}
	// Refusals by role, each counted, one audit line.
	for range 3 {
		if _, err := bill.node.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "naive", Name: "x"})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("billing creates a service: %v", err)
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
	// An expiry now is a disable by another name.
	if _, err := bill.node.SetUserExpiry(ctx, connect.NewRequest(&nodev1.SetUserExpiryRequest{Name: "u1", ExpiresAt: 1})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("an expiry now over the mass limit: %v", err)
	}
	if _, err := bill.node.SetUserExpiry(ctx, connect.NewRequest(&nodev1.SetUserExpiryRequest{Name: "u1", ExpiresAt: 1, ConfirmMass: true})); err != nil {
		t.Fatalf("an expiry now, confirmed: %v", err)
	}
	if _, err := bill.node.SetUserExpiry(ctx, connect.NewRequest(&nodev1.SetUserExpiryRequest{Name: "u1"})); err != nil {
		t.Fatalf("never is no mass action: %v", err)
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
	if !st.Msg.SupportNotes || st.Msg.MassLimit != 2 || st.Msg.MassActions != 4 || st.Msg.MassRefused != 3 || st.Msg.TrafficCounting != "on" {
		t.Errorf("settings: %+v", st.Msg)
	}
	limited, denied := map[string]uint64{}, map[string]uint64{}
	billID := ""
	for _, d := range st.Msg.Devices {
		limited[d.Role], denied[d.Role] = d.Limited, d.Denied
		if d.Role == "billing" {
			billID = d.Id
		}
		if d.Calls == 0 || d.LastCall == 0 {
			t.Errorf("device %s: %+v", d.Name, d)
		}
	}
	if limited["support"] != 3 || limited["billing"] != 0 || denied["billing"] != 3 {
		t.Errorf("limited %v, denied %v", limited, denied)
	}
	audit, err := srv.Store.ListAudit(ctx, 300)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, e := range audit {
		count[e.Action]++
	}
	if count["api.limited"] != 2 || count["api.mass"] != 2 || count["user.enable=false confirm"] != 1 || count["user.expires=now confirm"] != 1 || count["api.denied"] != 1 ||
		count["integration.set mass-limit=2"] != 1 || count["traffic.counting=on"] != 1 || count["integration.set support-notes=on"] != 1 {
		t.Errorf("audit: %v", count)
	}
	m, err := c.GetMetrics(ctx, connect.NewRequest(&nodev1.GetMetricsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`raycontrol_api_limited_total{role="support"} 3`,
		`raycontrol_integration_mass_actions_total{result="refused"} 3`,
		`raycontrol_integration_mass_actions_total{result="confirmed"} 2`,
		`raycontrol_api_calls_total{role="support",code="resource_exhausted"} 3`,
	} {
		if !strings.Contains(m.Msg.Text, want) {
			t.Errorf("metrics: no %s", want)
		}
	}

	// A device's limits reset: its own go, its role's stay.
	seven := &nodev1.IntegrationLimits{Read: &nodev1.Rate{Burst: 7, PerHour: 7}}
	for _, req := range []*nodev1.SetIntegrationSettingsRequest{
		{Limits: &nodev1.IntegrationLimitsFor{Role: "billing", Limits: seven}},
		{Limits: &nodev1.IntegrationLimitsFor{DeviceId: billID, Limits: &nodev1.IntegrationLimits{Inflight: 3}}},
		{Limits: &nodev1.IntegrationLimitsFor{DeviceId: billID}, ToDefault: true},
	} {
		if err := set(0, req); err != nil {
			t.Fatal(err)
		}
	}
	st, err = srv.GetIntegrationSettings(as(1000), connect.NewRequest(&nodev1.GetIntegrationSettingsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range st.Msg.Limits {
		if l.DeviceId != "" || l.Role == "billing" && (!l.Set || l.Limits.Read.GetBurst() != 7) {
			t.Errorf("after the device's reset: %v", l)
		}
	}
	// A request applies whole or not at all.
	off := false
	if err := set(0, &nodev1.SetIntegrationSettingsRequest{SupportNotes: &off, Limits: &nodev1.IntegrationLimitsFor{Role: "admin"}}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad limits: %v", err)
	}
	if st, err := srv.GetIntegrationSettings(as(1000), connect.NewRequest(&nodev1.GetIntegrationSettingsRequest{})); err != nil || !st.Msg.SupportNotes {
		t.Fatalf("half a request applied: %v", err)
	}
}

// What an integration's metrics sum when its labels make series alike:
// counters summed, levels by their highest, a last success by its lowest.
func TestRelabel(t *testing.T) {
	var m Metrics
	for _, l := range []struct {
		loop                string
		runs, last, failing float64
	}{{"acme a.example", 1, 100, 0}, {"acme b.example", 2, 50, 1}} {
		m.Add("raycontrol_loop_runs_total", "", l.runs, "loop", l.loop)
		m.Add("raycontrol_loop_last_success_seconds", "", l.last, "loop", l.loop)
		m.Add("raycontrol_loop_failing", "", l.failing, "loop", l.loop)
	}
	text := m.relabel(integrationLabels(nil)).String()
	for _, want := range []string{
		`raycontrol_loop_runs_total{loop="acme"} 3`,
		`raycontrol_loop_last_success_seconds{loop="acme"} 50`,
		`raycontrol_loop_failing{loop="acme"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %s in\n%s", want, text)
		}
	}
	if strings.Contains(text, "example") {
		t.Errorf("a site in\n%s", text)
	}
}
