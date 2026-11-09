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

// SetUserTraffic (traffic-limit-v1 §3.6): a limit with its period, the
// count in User, a user over the limit out of the export and counted as
// over_limit in the metrics, every call audited.
func TestSetUserTraffic(t *testing.T) {
	srv, sock, changes := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "hy2-masq", Name: "hy2"})); err != nil {
		t.Fatal(err)
	}
	r, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"hy2"},
		TrafficLimitBytes: 1000, TrafficPeriod: "monthly", TrafficResetDay: 15}))
	if err != nil {
		t.Fatal(err)
	}
	u := r.Msg.User
	if u.TrafficLimitBytes != 1000 || u.TrafficPeriod != "monthly" || u.TrafficResetDay != 15 || u.TrafficUsedBytes != 0 ||
		u.TrafficPeriodStart == 0 || u.TrafficNextReset != store.NextReset(time.Now(), 15).Unix() || u.TrafficExhausted {
		t.Fatalf("created %+v", u)
	}
	for name, req := range map[string]*nodev1.CreateUserRequest{
		"day 29":         {Name: "b1", TrafficLimitBytes: 1, TrafficResetDay: 29},
		"weekly":         {Name: "b2", TrafficLimitBytes: 1, TrafficPeriod: "weekly; DROP TABLE"},
		"a negative one": {Name: "b3", TrafficLimitBytes: -1},
	} {
		if _, err := c.CreateUser(ctx, connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Nothing asked, a period that is not one, a day out of range: refused.
	bad := "weekly; DROP"
	day := int32(31)
	for name, req := range map[string]*nodev1.SetUserTrafficRequest{
		"nothing": {Name: "alice"}, "period": {Name: "alice", Period: &bad}, "day": {Name: "alice", ResetDay: &day},
	} {
		if _, err := c.SetUserTraffic(ctx, connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := c.SetUserTraffic(ctx, connect.NewRequest(&nodev1.SetUserTrafficRequest{Name: "nobody", ResetUsage: true})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("nobody: %v", err)
	}

	// Over the limit: no export, over_limit in the metrics.
	su, _ := srv.Store.UserByName(ctx, "alice")
	if err := srv.Store.WriteTraffic(ctx, store.TrafficWrite{Adds: []store.TrafficAdd{{UserID: su.ID, Start: su.TrafficStart, Up: 600, Down: 400}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExportUser(ctx, connect.NewRequest(&nodev1.ExportUserRequest{Name: "alice"})); connect.CodeOf(err) != connect.CodeFailedPrecondition ||
		!strings.Contains(err.Error(), "traffic limit") {
		t.Fatalf("export over the limit: %v", err)
	}
	m, err := c.GetMetrics(ctx, connect.NewRequest(&nodev1.GetMetricsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{`raycontrol_users{state="over_limit"} 1`, `raycontrol_users{state="active"} 0`, "raycontrol_users_limited 1"} {
		if !strings.Contains(m.Msg.Text, line+"\n") {
			t.Errorf("metrics without %q", line)
		}
	}
	if strings.Contains(m.Msg.Text, "alice") {
		t.Error("a user's name in the metrics")
	}
	list, err := c.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{}))
	if err != nil || len(list.Msg.Users) != 1 || list.Msg.Users[0].TrafficUsedBytes != 1000 || !list.Msg.Users[0].TrafficExhausted {
		t.Fatalf("list %+v %v", list.Msg.GetUsers(), err)
	}
	// Disabled, the user is off for that, not for the limit: not
	// exhausted, as the subscription and the metrics have it.
	if _, err := c.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "alice"})); err != nil {
		t.Fatal(err)
	}
	list, err = c.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{}))
	if err != nil || list.Msg.Users[0].TrafficExhausted || list.Msg.Users[0].TrafficUsedBytes != 1000 {
		t.Fatalf("disabled: %+v %v", list.Msg.GetUsers(), err)
	}
	if _, err := c.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "alice", Enabled: true})); err != nil {
		t.Fatal(err)
	}

	// Raised, then off: back, and no count.
	before := changes.Load()
	limit := int64(5000)
	s, err := c.SetUserTraffic(ctx, connect.NewRequest(&nodev1.SetUserTrafficRequest{Name: "alice", LimitBytes: &limit}))
	if err != nil || s.Msg.User.TrafficExhausted || s.Msg.User.TrafficUsedBytes != 1000 || changes.Load() == before {
		t.Fatalf("raised %+v %v", s.Msg.GetUser(), err)
	}
	if _, err := c.ExportUser(ctx, connect.NewRequest(&nodev1.ExportUserRequest{Name: "alice"})); err != nil {
		t.Fatalf("export: %v", err)
	}
	none := "none"
	if s, err = c.SetUserTraffic(ctx, connect.NewRequest(&nodev1.SetUserTrafficRequest{Name: "alice", Period: &none, ResetUsage: true})); err != nil ||
		s.Msg.User.TrafficPeriod != "none" || s.Msg.User.TrafficUsedBytes != 0 || s.Msg.User.TrafficNextReset != 0 {
		t.Fatalf("none %+v %v", s.Msg.GetUser(), err)
	}
	off := int64(0)
	if s, err = c.SetUserTraffic(ctx, connect.NewRequest(&nodev1.SetUserTrafficRequest{Name: "alice", LimitBytes: &off})); err != nil ||
		s.Msg.User.TrafficLimitBytes != 0 || s.Msg.User.TrafficPeriod != "" || s.Msg.User.TrafficPeriodStart != 0 {
		t.Fatalf("off %+v %v", s.Msg.GetUser(), err)
	}
	audit, err := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{Limit: 4}))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range audit.Msg.Entries {
		got = append(got, e.Action+" "+e.Target+" "+e.Result)
	}
	want := []string{"user.traffic limit=0 alice ok", "user.traffic period=none reset-usage alice ok", "user.export alice ok", "user.traffic limit=5000 alice ok"}
	if strings.Join(got, "; ") != strings.Join(want, "; ") {
		t.Fatalf("audit %q", got)
	}
	// The bad period was not written into the audit.
	all, _ := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{Limit: 100}))
	for _, e := range all.Msg.Entries {
		if strings.Contains(e.Action, "DROP") || strings.Contains(e.Result, "DROP") {
			t.Fatalf("audit %+v", e)
		}
	}
}
