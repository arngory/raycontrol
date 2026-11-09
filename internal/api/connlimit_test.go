package api

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"

	"github.com/arngory/raycontrol/internal/connlimit"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/store"
)

// rayctl conn-limit's API (spec/conn-limit-v1.md §8): on without a setting;
// root on the node only changes it, audited; the group sees it on the
// node, nobody through the remote API; the perimeter snapshots of the node
// and its relays carry it; the guard's report reaches GetConnLimit and the
// metrics.
func TestConnLimitAPI(t *testing.T) {
	srv, _, changes := startServer(t)
	ctx := context.Background()
	as := func(uid uint32) context.Context {
		return context.WithValue(context.WithValue(ctx, peerKey{}, &unix.Ucred{Uid: uid}), actorKey{}, "test")
	}
	remote := context.WithValue(ctx, actorKey{}, "admin/laptop (remote)")
	set := func(ctx context.Context, off bool) (bool, error) {
		r, err := srv.SetConnLimit(ctx, connect.NewRequest(&nodev1.SetConnLimitRequest{Off: off}))
		if err != nil {
			return false, err
		}
		return r.Msg.Off, nil
	}
	get := func(ctx context.Context) (*nodev1.GetConnLimitResponse, error) {
		r, err := srv.GetConnLimit(ctx, connect.NewRequest(&nodev1.GetConnLimitRequest{}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	if r, err := get(as(1000)); err != nil || r.Off || r.Guard != nil {
		t.Fatalf("a new node: %+v %v", r, err)
	}
	refused := map[string]context.Context{"the group": as(1000), "remote": remote}
	if os.Getuid() != 0 {
		refused["rayd's own user"] = as(uint32(os.Getuid()))
	}
	for name, ctx := range refused {
		if _, err := set(ctx, true); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("%s changes it: %v", name, err)
		}
	}
	if _, err := get(remote); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("remote sees it: %v", err)
	}
	if off, _ := srv.Store.ConnLimitOff(ctx); off {
		t.Fatal("changed by a refused call")
	}
	before := changes.Load()
	if off, err := set(as(0), true); err != nil || !off {
		t.Fatalf("off: %v %v", off, err)
	}
	if changes.Load() == before {
		t.Fatal("rayspa and apply not told")
	}
	if r, err := get(as(1000)); err != nil || !r.Off {
		t.Fatalf("the group sees: %+v %v", r, err)
	}
	p := &PerimeterServer{Server: srv, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour, RayspaUID: 9191}
	snap, err := p.snapshot(ctx)
	if err != nil || !snap.ConnLimitOff {
		t.Fatalf("snapshot: %v %v", snap.GetConnLimitOff(), err)
	}
	// A relay's snapshot: the same switch.
	if _, err := srv.Store.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if rs, err := p.RelaySnapshot(ctx, "r1"); err != nil || !rs.ConnLimitOff {
		t.Fatalf("relay snapshot: %v %v", rs.GetConnLimitOff(), err)
	}
	if off, err := set(as(0), false); err != nil || off {
		t.Fatalf("on: %v %v", off, err)
	}
	if snap, err = p.snapshot(ctx); err != nil || snap.ConnLimitOff {
		t.Fatalf("on again: %v %v", snap.GetConnLimitOff(), err)
	}
	entries, _ := srv.Store.ListAudit(ctx, 10)
	for _, want := range []string{"off", "on"} {
		if !slices.ContainsFunc(entries, func(e store.AuditEntry) bool {
			return e.Action == "conn_limit.set" && e.Target == want && e.Result == "ok" && e.Actor == "test"
		}) {
			t.Errorf("%q not audited: %+v", want, entries)
		}
	}
	if !nodeOnly[nodev1connect.NodeServiceGetConnLimitProcedure] || !nodeOnly[nodev1connect.NodeServiceSetConnLimitProcedure] {
		t.Error("the remote API offers the connection limits")
	}

	// The guard's report: rayspa's user and root only.
	srv.ConnLimit = &connlimit.Monitor{Health: &health.Board{}}
	report := &perimeterv1.ReportGuardRequest{Guard: &perimeterv1.Guard{On: true, Since: 1_700_000_000, LastOn: 1_700_000_000,
		Switches: 3, Refused: 42, SweptUdp: 5, SweptTcpOut: 6, SweptTcpIn: 7}}
	if _, err := p.ReportGuard(as(1000), connect.NewRequest(report)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("another user reports: %v", err)
	}
	if _, err := p.ReportGuard(as(9191), connect.NewRequest(report)); err != nil {
		t.Fatal(err)
	}
	r, err := get(as(0))
	if err != nil || r.Guard == nil || !r.Guard.On || r.Guard.Refused != 42 || r.Guard.SweptTcpIn != 7 || r.Guard.Since != 1_700_000_000 || r.Guard.Reported == 0 {
		t.Fatalf("the guard: %+v %v", r.GetGuard(), err)
	}
	text, err := srv.metrics(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"raycontrol_conn_guard_on 1", "raycontrol_conn_guard_refused_total 42", `raycontrol_conn_guard_swept_total{kind="tcp-in"} 7`,
		"raycontrol_conn_guard_switches_total 3"} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	if strings.Contains(text, `user="`) || strings.Contains(text, "u5") {
		t.Error("a user in the metrics")
	}
}

// The refusals of Hysteria2 and Xray reach GetConnLimit, the status line
// and the metrics as naive's: users by number and service, the metrics by
// service and kind only, with zeros for a service that refused nothing.
func TestConnLimitHysteriaXray(t *testing.T) {
	srv, _, _ := startServer(t)
	ctx := context.WithValue(context.WithValue(context.Background(), peerKey{}, &unix.Ucred{Uid: 0}), actorKey{}, "test")
	now := time.Now()
	limits := map[string]map[string]map[string]int64{"nv": {}, "ho": {"u5": {"tcp": 10}}, "r": {"u9": {"dest": 1}}}
	read := func(svc string) func(context.Context) (connlimit.Reading, error) {
		return func(context.Context) (connlimit.Reading, error) {
			// A new answer each time, as a process's.
			out := map[string]map[string]int64{}
			for name, kinds := range limits[svc] {
				out[name] = maps.Clone(kinds)
			}
			return connlimit.Reading{Boot: "b-" + svc, Age: time.Hour, AgeKnown: true, Limits: out}, nil
		}
	}
	hb := &health.Board{}
	srv.ConnLimit = &connlimit.Monitor{Health: hb, Now: func() time.Time { return now }, Proc: t.TempDir(),
		Sources: func(context.Context) ([]connlimit.Source, error) {
			return []connlimit.Source{{Service: "nv", Read: read("nv")}, {Service: "ho", Read: read("ho")}, {Service: "r", Read: read("r")}}, nil
		}}
	srv.ConnLimit.Round(ctx) // a baseline: the processes ran for an hour
	limits["ho"]["u5"]["tcp"], limits["r"]["u9"]["dest"] = 13, 5
	limits["r"]["u5"] = map[string]int64{"tcp": 2}
	now = now.Add(connlimit.Every)
	srv.ConnLimit.Round(ctx)
	r, err := srv.GetConnLimit(ctx, connect.NewRequest(&nodev1.GetConnLimitRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	var users []string
	for _, u := range r.Msg.Users {
		users = append(users, fmt.Sprintf("u%d %s %d", u.Id, u.Service, u.Refused))
	}
	if !slices.Equal(users, []string{"u5 ho 3", "u5 r 2", "u9 r 4"}) {
		t.Fatalf("users %v", users)
	}
	var line string
	for _, l := range hb.Loops() {
		if l.Name == "conn-limit" {
			line = l.Detail
		}
	}
	if line != "at a limit in 15 min: u5 (ho: 3), u5 (r: 2), u9 (r: 4)" {
		t.Fatalf("status %q", line)
	}
	text, err := srv.metrics(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`raycontrol_conn_limit_refused_total{service="ho",kind="tcp"} 3`,
		`raycontrol_conn_limit_refused_total{service="r",kind="dest"} 4`, `raycontrol_conn_limit_refused_total{service="r",kind="tcp"} 2`,
		`raycontrol_conn_limit_refused_total{service="nv",kind="tcp"} 0`, `raycontrol_conn_limit_users{service="r"} 2`,
		`raycontrol_conn_limit_users{service="nv"} 0`} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	if strings.Contains(text, "u5") || strings.Contains(text, "u9") {
		t.Error("a user in the metrics")
	}
}
