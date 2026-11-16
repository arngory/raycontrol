package api

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
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
// udp=on, one whose socket does not answer and a disabled one show none.
func TestMetricsNaiveUDP(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "reality", Name: "reality"})); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nv", "plain", "away", "off"} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "naive", Name: name})); err != nil {
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
	var mu sync.Mutex
	var asked []string
	srv.NaiveUDP = func(ctx context.Context, service string) (*naive.UDPStats, error) {
		mu.Lock()
		asked = append(asked, service)
		mu.Unlock()
		r, err := traffic.ReadLine(ctx, srv.Paths.StatsSocket(service))
		return r.UDP, err
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
	for _, name := range []string{"plain", "away", "off"} {
		if strings.Contains(text, `raycontrol_naive_udp_requests_total{service="`+name+`"}`) {
			t.Errorf("%s has UDP metrics", name)
		}
	}
	if strings.Contains(strings.Join(asked, " "), "off") {
		t.Errorf("a disabled service's socket read: %v", asked)
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
	srv.NaiveUDP = nil
	if m, err = c.GetMetrics(ctx, connect.NewRequest(&nodev1.GetMetricsRequest{})); err != nil || strings.Contains(m.Msg.Text, "raycontrol_naive_udp_") {
		t.Fatalf("without the reader: %v", err)
	}
}
