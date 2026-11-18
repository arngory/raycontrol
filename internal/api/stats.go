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
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/stats"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// statsLabels are the labels a report keeps (spec/stats-v1.md §2.4):
// service and zone as numbers, a loop by its kind, a client's product and
// version as clientLabel has them, the rest as the metrics have them. A
// label not listed is dropped, its series summed with their likes: a new
// metric's label stays out of the reports until it is looked at.
var statsLabels = map[string]bool{
	"service": true, "zone": true, "loop": true, "kind": true, "state": true, "role": true, "enabled": true,
	"product": true, "version": true, "reason": true, "result": true, "direction": true, "outcome": true,
}

// StatsPoints is the metrics as the stats sampler keeps them, in rayd's
// memory only: no Unix times and no version (the report has its own), the
// labels as they are. statsClean makes them fit to show when a report is
// built, so that a series is followed by its own name across the window.
func (s *Server) StatsPoints(ctx context.Context, now time.Time) ([]stats.Point, error) {
	m, err := s.collect(ctx, now)
	if err != nil {
		return nil, err
	}
	out := make([]stats.Point, 0, len(m.points))
	for _, p := range m.points {
		if p.Name == "raycontrol_info" || strings.HasSuffix(p.Name, "_seconds") {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// statsClean maps a sampled series to what a report shows, by the services
// there are now: a service as kind#n (its order of creation among those of
// its kind), a zone as its service's and its number there, a loop by the
// word that names its kind; a service or zone gone since as "other".
func statsClean(services []store.Service) stats.Clean {
	ids := serviceIDs(services)
	zones := map[string]string{}
	for _, svc := range services {
		for i, z := range provision.Zones(svc) {
			zones[z] = fmt.Sprintf("%s/zone%d", ids[svc.Name], i+1)
		}
	}
	return func(_ string, raw []string) ([]string, bool) {
		labels := make([]string, 0, len(raw))
		for i := 0; i+1 < len(raw); i += 2 {
			name, value := raw[i], raw[i+1]
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
			case "product":
				value = clientProduct(value)
			case "version":
				value = clientVersion(value)
			}
			labels = append(labels, name, value)
		}
		return labels, true
	}
}

// clientProduct is a client's product as a report names it: one raycontrol
// knows, or "other". A device names its own; a report passed on carries
// none of a device's free text.
func clientProduct(p string) string {
	switch p {
	case "niko", "rayctl", "-":
		return p
	}
	return "other"
}

// clientVersion is a client's version without what a device could carry
// in it: "1.59.0-pre.20261120.1" is "1.59.0-pre", a pre-release not alpha,
// beta, rc or pre "-other", and a version past 99.999.9999 (digits to
// spare for anything) "other".
func clientVersion(v string) string {
	core, pre, found := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return "other"
	}
	for i, limit := range []uint64{99, 999, 9999} {
		n, err := strconv.ParseUint(parts[i], 10, 64)
		if err != nil || n > limit {
			return "other"
		}
	}
	if !found {
		return core
	}
	word, _, _ := strings.Cut(pre, ".")
	switch word {
	case "alpha", "beta", "rc", "pre":
		return core + "-" + word
	}
	return core + "-other"
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
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	r, err := s.Stats.Report(ctx, last, statsClean(services))
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
	seen := map[[2]string]int{}
	for _, c := range clients {
		product, version, _ := strings.Cut(c.Client, "/")
		if product == "" {
			continue // never named one
		}
		seen[[2]string{clientProduct(product), clientVersion(version)}] += c.Devices
	}
	for k, n := range seen {
		r.Clients = append(r.Clients, stats.ClientSeen{Product: k[0], Version: k[1], Devices: n})
	}
	stats.SortClients(r.Clients)

	b, err := json.Marshal(r)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.GetStatsResponse{Json: b}), nil
}
