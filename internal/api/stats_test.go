package api

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/stats"
	"github.com/arngory/raycontrol/internal/sub"
)

// GetStats (spec/stats-v1.md): the metrics over the window, services as
// kind#n, zones by number, loops by kind; no name of a service, user,
// device or zone, no error text; the subscription's answers by outcome.
func TestGetStats(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)

	if _, err := c.GetStats(ctx, connect.NewRequest(&nodev1.GetStatsRequest{})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("without a sampler: %v", err)
	}

	srv.Health = &health.Board{}
	srv.Health.Done("apply", nil)
	srv.Health.Done("acme secret-site", errors.New("secret-site.example.org does not resolve"))
	for _, svc := range [][2]string{{"reality", "secret-reality"}, {"naive", "secret-naive"}, {"naive", "other-naive"}, {"dnstt", "secret-dns"}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: svc[0], Name: svc[1]})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice"})); err != nil {
		t.Fatal(err)
	}
	dev, err := c.CreateDevice(ctx, connect.NewRequest(&nodev1.CreateDeviceRequest{User: "alice", Name: "phone"}))
	if err != nil {
		t.Fatal(err)
	}
	// A device names its client itself: free text in the pre-release.
	if err := srv.Store.SetDeviceClient(ctx, dev.Msg.Device.Id, "niko/1.59.0-secret.1", time.Hour); err != nil {
		t.Fatal(err)
	}
	srv.Paths.Run = t.TempDir()
	zone := zoneOf(t, c, "secret-dns")
	serveStats(t, srv.Paths.FrontStats(), `{"started":1700000000,"queries":{"`+zone+`":11,"stray.example.net":2},"refused":3}`+"\n")
	serveStats(t, srv.Paths.StatsSocket("secret-dns"), `{"queries":5,"sessions":1,"zones":{"`+zone+`":3}}`+"\n")

	now := time.Now()
	srv.SubRequests, srv.Started = &sub.Requests{}, now.Add(-90*time.Minute)
	srv.Stats = &stats.Sampler{Collect: srv.StatsPoints, Now: func() time.Time { return now }}
	srv.Stats.Start()
	for i := range 70 {
		srv.SubRequests.OK.Add(2)
		if i%10 == 0 {
			srv.SubRequests.ClientRefused.Add(1)
		}
		if err := srv.Stats.Take(ctx); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}

	resp, err := c.GetStats(ctx, connect.NewRequest(&nodev1.GetStatsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	text := string(resp.Msg.Json)
	for _, secret := range []string{"secret", "alice", "phone", "example", zone, "does not resolve", "test-node"} {
		if strings.Contains(text, secret) {
			t.Errorf("%q in the report:\n%s", secret, text)
		}
	}
	var r stats.Report
	if err := json.Unmarshal(resp.Msg.Json, &r); err != nil {
		t.Fatal(err)
	}
	if r.Node.Raycontrol != "test" || r.Node.RaydUptimeS < 90*60 || r.Partial {
		t.Fatalf("node: %+v partial %v %q", r.Node, r.Partial, r.Why)
	}
	got := map[string]float64{}
	for _, ct := range r.Counters {
		key := ct.Name
		for _, l := range []string{"outcome", "service", "zone", "loop"} {
			if v, ok := ct.Labels[l]; ok {
				key += " " + l + "=" + v
			}
		}
		got[key] = ct.Delta
	}
	// An hour: from the sample at minute 10 (22 answers) to the last
	// (140), and the refused one of every ten from 2 to 7.
	for key, want := range map[string]float64{
		"raycontrol_sub_requests_total outcome=ok":             118,
		"raycontrol_sub_requests_total outcome=client_refused": 5,
		"raycontrol_sub_requests_total outcome=denied":         0,
		"raycontrol_loop_errors_total loop=acme":               0,
		"raycontrol_dnstt_queries_total service=dnstt#1":       0,
	} {
		if v, ok := got[key]; !ok || v != want {
			t.Errorf("%s: %v (%v), want %v", key, v, ok, want)
		}
	}
	gauges := map[string]float64{}
	for _, g := range r.Gauges {
		key := g.Name
		for _, l := range []string{"service", "zone", "state"} {
			if v, ok := g.Labels[l]; ok {
				key += " " + l + "=" + v
			}
		}
		gauges[key] = g.End
	}
	if gauges["raycontrol_dnstt_sessions service=dnstt#1"] != 1 || gauges["raycontrol_users state=active"] != 1 {
		t.Errorf("gauges: %v", gauges)
	}
	front := false
	for _, ct := range r.Counters {
		if ct.Name == "raycontrol_dns_front_queries_total" {
			front = true
			if z := ct.Labels["zone"]; z != "dnstt#1/zone1" && z != "other" {
				t.Errorf("a zone as %q", z)
			}
		}
		if strings.HasSuffix(ct.Name, "_seconds") || ct.Name == "raycontrol_info" {
			t.Errorf("%s in the report", ct.Name)
		}
	}
	if !front {
		t.Error("no front counters")
	}
	if len(r.Clients) != 1 || r.Clients[0] != (stats.ClientSeen{Product: "niko", Version: "1.59.0-other", Devices: 1}) {
		t.Errorf("clients: %+v", r.Clients)
	}
	var ids []string
	for _, s := range r.Services {
		ids = append(ids, s.ID)
	}
	for _, want := range []string{"dnstt#1", "naive#1", "naive#2", "reality#1"} {
		if !slices.Contains(ids, want) {
			t.Errorf("services: %v, no %s", ids, want)
		}
	}

	for _, bad := range []int64{60, 3 * 3600} {
		if _, err := c.GetStats(ctx, connect.NewRequest(&nodev1.GetStatsRequest{LastSeconds: bad})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("window %ds: %v", bad, err)
		}
	}
}

func TestClientVersion(t *testing.T) {
	for in, want := range map[string]string{
		"1.59.0": "1.59.0", "1.59.0-pre.20261120.1": "1.59.0-pre", "1.60.0-rc.1": "1.60.0-rc", "1.0.0-alice": "1.0.0-other",
		"79161234567.0.0": "other", "1.1000.0": "other", "1.0.10000": "other", "1.0": "other", "": "other", "99.999.9999": "99.999.9999",
	} {
		if got := clientVersion(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"niko": "niko", "rayctl": "rayctl", "-": "-", "alice": "other"} {
		if got := clientProduct(in); got != want {
			t.Errorf("product %q: %q, want %q", in, got, want)
		}
	}
}
