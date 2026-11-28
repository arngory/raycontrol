package api

import (
	"context"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/traffic"
)

// rayctl metrics shows each naive service's datagram requests
// (naive-udp-v1 §7) as its stats socket gives them, read the way rayd
// wires it: by service, direction and reason only, every reason with its
// zero; what the reasons do not cover is "other". A service without
// udp=on (its socket not even read), one whose socket does not answer and
// a disabled one show none.
func TestMetricsNaiveUDP(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "reality"})); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nv", "plain", "away", "off", "stale"} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "naive", Name: name})); err != nil {
			t.Fatal(name, err)
		}
	}
	// udp=on but on plain and stale (a process still running with -udp
	// before rayctl apply).
	for _, name := range []string{"nv", "away", "off"} {
		if _, err := c.SetServiceOption(ctx, connect.NewRequest(&nodev1.SetServiceOptionRequest{Name: name, Key: "udp", Value: "on"})); err != nil {
			t.Fatal(name, err)
		}
	}
	if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "off"})); err != nil {
		t.Fatal(err)
	}
	srv.Paths.Run = t.TempDir()
	serve := func(name string, udp func() naive.UDPStats) {
		if err := os.Mkdir(filepath.Join(srv.Paths.Run, name), 0o700); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		users := filepath.Join(dir, "users.json")
		if err := os.WriteFile(users, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		u := &naive.Users{Path: users}
		u.SetUDP(udp)
		if err := u.ServeStats(t.Context(), srv.Paths.StatsSocket(name), slog.New(slog.DiscardHandler)); err != nil {
			t.Fatal(err)
		}
	}
	serve("nv", func() naive.UDPStats {
		return naive.UDPStats{Requests: 7, Refused: 2, In: 40, Out: 38, CapsulesIn: 3, CapsulesOut: 1, Dropped: 9,
			DroppedBy: map[string]int64{"denied": 4, "write": 1, "future": 2}}
	})
	serve("plain", nil)
	serve("off", func() naive.UDPStats { return naive.UDPStats{Requests: 99} })
	serve("stale", func() naive.UDPStats { return naive.UDPStats{Requests: 98} })
	var mu sync.Mutex
	var asked []string
	srv.NaiveStats = func(ctx context.Context, service string) (*naive.UDPStats, *naive.MemoryStats, error) {
		mu.Lock()
		asked = append(asked, service)
		mu.Unlock()
		r, err := traffic.ReadLine(ctx, srv.Paths.StatsSocket(service))
		return r.UDP, r.Memory, err
	}
	m, err := c.GetMetrics(ctx, connect.NewRequest(&nodev1.GetMetricsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	text := m.Msg.Text
	for _, want := range []string{
		"# TYPE raycontrol_naive_udp_requests_total counter",
		`raycontrol_naive_udp_requests_total{service="nv"} 7`,
		`raycontrol_naive_udp_refused_total{service="nv"} 2`,
		`raycontrol_naive_udp_datagrams_total{service="nv",direction="in"} 40`,
		`raycontrol_naive_udp_datagrams_total{service="nv",direction="out"} 38`,
		`raycontrol_naive_udp_capsules_total{service="nv",direction="in"} 3`,
		`raycontrol_naive_udp_capsules_total{service="nv",direction="out"} 1`,
		`raycontrol_naive_udp_dropped_total{service="nv",reason="bad"} 0`,
		`raycontrol_naive_udp_dropped_total{service="nv",reason="denied"} 4`,
		`raycontrol_naive_udp_dropped_total{service="nv",reason="write"} 1`,
		`raycontrol_naive_udp_dropped_total{service="nv",reason="future"} 2`,
		`raycontrol_naive_udp_dropped_total{service="nv",reason="other"} 2`,
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("metrics lack %s", want)
		}
	}
	for _, reason := range naive.DropReasons() {
		if !strings.Contains(text, `raycontrol_naive_udp_dropped_total{service="nv",reason="`+reason+`"}`) {
			t.Errorf("no line for the reason %s", reason)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "raycontrol_naive_udp_") && !strings.Contains(line, `{service="nv"`) {
			t.Errorf("UDP metrics of another service: %s", line)
		}
	}
	// Each enabled service is read once (its tunnels' memory), a disabled
	// one not; the datagrams shown are those of the ones with udp=on only,
	// whatever a process without it gives.
	slices.Sort(asked)
	if !slices.Equal(asked, []string{"away", "nv", "plain", "stale"}) {
		t.Errorf("sockets read: %v", asked)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "raycontrol_naive_udp_") {
			labels := line[strings.Index(line, "{")+1 : strings.Index(line, "}")]
			for _, kv := range strings.Split(labels, ",") {
				if k, _, _ := strings.Cut(kv, "="); k != "service" && k != "direction" && k != "reason" {
					t.Errorf("a label %s: %s", k, line)
				}
			}
		}
	}
	// Without the reader (a rayd that has none wired): no UDP metrics.
	srv.NaiveStats = nil
	if m, err = c.GetMetrics(ctx, connect.NewRequest(&nodev1.GetMetricsRequest{})); err != nil || strings.Contains(m.Msg.Text, "raycontrol_naive_udp_") {
		t.Fatalf("without the reader: %v", err)
	}
}

// A hostile line's dropped datagrams: sums past int64 saturate, nothing
// comes out below zero, "other" is what the reasons do not cover, added to
// an "other" the line gave itself.
func TestAddNaiveUDPHostile(t *testing.T) {
	lines := func(u naive.UDPStats) map[string]string {
		var m Metrics
		addNaiveUDP(&m, "nv", u)
		out := map[string]string{}
		for _, l := range strings.Split(m.String(), "\n") {
			if r, ok := strings.CutPrefix(l, `raycontrol_naive_udp_dropped_total{service="nv",reason="`); ok {
				reason, v, _ := strings.Cut(r, `"} `)
				out[reason] = v
			}
		}
		return out
	}
	const top = math.MaxInt64
	// Two reasons at the top: their sum saturates, no "other" comes from
	// a sum that wrapped below dropped.
	got := lines(naive.UDPStats{Dropped: top, DroppedBy: map[string]int64{"denied": top, "write": top}})
	if _, ok := got["other"]; ok || got["denied"] != strconv.FormatFloat(top, 'f', -1, 64) {
		t.Errorf("saturated: %v", got)
	}
	// Below zero (not what traffic.ReadLine gives, but whatever the hook
	// does): zero, and no wrap either.
	got = lines(naive.UDPStats{Dropped: 5, DroppedBy: map[string]int64{"denied": -top, "write": 2}})
	if got["denied"] != "0" || got["write"] != "2" || got["other"] != "3" {
		t.Errorf("below zero: %v", got)
	}
	// The line's own "other", and the rest on top of it, at the top.
	got = lines(naive.UDPStats{Dropped: top, DroppedBy: map[string]int64{"other": top - 1}})
	if got["other"] != strconv.FormatFloat(top, 'f', -1, 64) {
		t.Errorf("other: %v", got)
	}
	got = lines(naive.UDPStats{Dropped: 10, DroppedBy: map[string]int64{"other": 4, "late": 1}})
	if got["other"] != "9" || got["late"] != "1" || got["bad"] != "0" {
		t.Errorf("other and the rest: %v", got)
	}
	for _, v := range []int64{0, 1, top} {
		for _, w := range []int64{-1, 0, 1, top} {
			if s := addSaturating(v, w); s < 0 || s < v || w > 0 && v < top && s == v {
				t.Errorf("%d + %d = %d", v, w, s)
			}
		}
	}
}

// rayctl metrics shows each enabled naive service's TCP tunnels' memory
// (memory-v1 §5) as its stats socket gives it, udp=on or not: counts by
// service only. One that does not give it, or does not answer, shows none.
func TestMetricsNaiveMemory(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "reality"})); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nv", "old", "away"} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "naive", Name: name})); err != nil {
			t.Fatal(name, err)
		}
	}
	srv.Paths.Run = t.TempDir()
	for name, mem := range map[string]func() naive.MemoryStats{
		"nv": func() naive.MemoryStats {
			return naive.MemoryStats{Budget: 64 << 20, Charge: 3 << 20, Pressure: true, Refused: 5, Evicted: 2}
		},
		"old": nil,
	} {
		if err := os.Mkdir(filepath.Join(srv.Paths.Run, name), 0o700); err != nil {
			t.Fatal(err)
		}
		users := filepath.Join(t.TempDir(), "users.json")
		if err := os.WriteFile(users, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		u := &naive.Users{Path: users}
		u.SetMemory(mem)
		if err := u.ServeStats(t.Context(), srv.Paths.StatsSocket(name), slog.New(slog.DiscardHandler)); err != nil {
			t.Fatal(err)
		}
	}
	srv.NaiveStats = func(ctx context.Context, service string) (*naive.UDPStats, *naive.MemoryStats, error) {
		r, err := traffic.ReadLine(ctx, srv.Paths.StatsSocket(service))
		return r.UDP, r.Memory, err
	}
	m, err := c.GetMetrics(ctx, connect.NewRequest(&nodev1.GetMetricsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	text := m.Msg.Text
	for _, want := range []string{
		`raycontrol_naive_tunnels_budget_bytes{service="nv"} 67108864`,
		`raycontrol_naive_tunnels_charge_bytes{service="nv"} 3145728`,
		`raycontrol_naive_tunnels_pressure{service="nv"} 1`,
		`raycontrol_naive_tunnels_refused_total{service="nv"} 5`,
		`raycontrol_naive_tunnels_evicted_total{service="nv"} 2`,
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("metrics lack %s", want)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "raycontrol_naive_tunnels_") && !strings.Contains(line, `{service="nv"}`) {
			t.Errorf("memory metrics of another service: %s", line)
		}
	}
}
