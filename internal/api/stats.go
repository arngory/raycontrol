package api

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/stats"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// statsLabels are the labels a stats sample keeps (spec/stats-v1.md §3):
// service and zone as numbers, a loop by its kind, the rest as the
// metrics have them. A label not listed is dropped, its series summed: a
// new metric's label stays out of the reports until it is looked at.
var statsLabels = map[string]bool{
	"service": true, "zone": true, "loop": true, "kind": true, "state": true, "role": true, "enabled": true,
	"product": true, "version": true, "reason": true, "result": true, "direction": true, "outcome": true,
}

// StatsPoints is the metrics as the stats sampler keeps them: no Unix times
// and no version (the report has its own), services as kind#n (their
// order of creation among the services of that kind), a zone as its
// service's and its number there, a loop by the word that names its kind.
func (s *Server) StatsPoints(ctx context.Context, now time.Time) ([]stats.Point, error) {
	m, err := s.collect(ctx, now)
	if err != nil {
		return nil, err
	}
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	ids := serviceIDs(services)
	zones := map[string]string{}
	for _, svc := range services {
		for i, z := range provision.Zones(svc) {
			zones[z] = fmt.Sprintf("%s/zone%d", ids[svc.Name], i+1)
		}
	}
	out := make([]stats.Point, 0, len(m.points))
	for _, p := range m.points {
		if p.Name == "raycontrol_info" || strings.HasSuffix(p.Name, "_seconds") {
			continue
		}
		labels := make([]string, 0, len(p.Labels))
		for i := 0; i+1 < len(p.Labels); i += 2 {
			name, value := p.Labels[i], p.Labels[i+1]
			if !statsLabels[name] {
				continue
			}
			switch name {
			case "service":
				value = cmp.Or(ids[value], "other")
			case "zone":
				value = cmp.Or(zones[value], "other")
			case "loop":
				value, _, _ = strings.Cut(value, " ")
			}
			labels = append(labels, name, value)
		}
		out = append(out, stats.Point{Name: p.Name, Labels: labels, Value: p.Value})
	}
	return out, nil
}

// serviceIDs is stats.ServiceIDs of the store's services.
func serviceIDs(services []store.Service) map[string]string {
	refs := make([]stats.ServiceRef, len(services))
	for i, svc := range services {
		refs[i] = stats.ServiceRef{ID: svc.ID, Name: svc.Name, Kind: svc.Kind}
	}
	return stats.ServiceIDs(refs)
}

// GetStats returns the node's statistics over a window (spec/stats-v1.md).
func (s *Server) GetStats(ctx context.Context, req *connect.Request[nodev1.GetStatsRequest]) (*connect.Response[nodev1.GetStatsResponse], error) {
	if s.Stats == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("this rayd keeps no statistics"))
	}
	last := time.Hour
	if req.Msg.LastSeconds != 0 {
		last = time.Duration(req.Msg.LastSeconds) * time.Second
	}
	if last < stats.MinWindow || last > stats.MaxWindow {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the window is %v to %v", stats.MinWindow, stats.MaxWindow))
	}
	r, err := s.Stats.Report(ctx, last)
	if errors.Is(err, stats.ErrNoSamples) {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("rayd has no sample yet: ask again in a minute"))
	}
	if err != nil {
		return nil, toConnect(err)
	}
	now := r.To
	r.Node.Raycontrol = s.Version
	r.Node.OS, r.Node.Arch = runtime.GOOS, runtime.GOARCH
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		r.Node.Kernel = strings.TrimSpace(string(b))
	}
	if !s.Started.IsZero() {
		r.Node.RaydUptimeS = int64(now.Sub(s.Started).Seconds())
	}

	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	ids := serviceIDs(services)
	for _, svc := range services {
		out := stats.Service{ID: ids[svc.Name], Kind: svc.Kind, Enabled: svc.Enabled}
		if svc.Enabled {
			secrets, err := s.Store.ServiceSecrets(ctx, svc.ID)
			if err != nil {
				return nil, toConnect(err)
			}
			if notAfter, ok := certNotAfter(secrets); ok {
				days := int(math.Floor(notAfter.Sub(now).Hours() / 24))
				out.CertDays = &days
			}
		}
		r.Services = append(r.Services, out)
	}
	slices.SortFunc(r.Services, func(a, b stats.Service) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(len(a.ID), len(b.ID)), cmp.Compare(a.ID, b.ID))
	})

	// The clients the devices named in the window (client-min-v1 §5).
	r.ClientsSince = now.Add(-2 * sub.ClientSeenEvery)
	if r.From.Before(r.ClientsSince) {
		r.ClientsSince = r.From
	}
	clients, err := s.Store.ClientCounts(ctx, r.ClientsSince)
	if err != nil {
		return nil, toConnect(err)
	}
	for _, c := range clients {
		product, version, _ := strings.Cut(c.Client, "/")
		if product == "" {
			continue // never named one
		}
		r.Clients = append(r.Clients, stats.ClientSeen{Product: product, Version: version, Devices: c.Devices})
	}
	stats.SortClients(r.Clients)

	b, err := json.Marshal(r)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.GetStatsResponse{Json: b}), nil
}
