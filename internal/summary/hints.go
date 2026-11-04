package summary

import (
	"context"
	"net/netip"
	"slices"
	"sort"
	"strconv"

	"github.com/arngory/raycontrol/internal/store"
)

// Hints is the subscription's hint for the network a client asks from
// (subscription-v1 §3, probe-v1 §6.2): a starting order of its profiles
// where it has no results of its own.
type Hints struct {
	Order       []uint16 `json:"order,omitempty"`         // services, the better first
	Avoid       []uint16 `json:"avoid,omitempty"`         // services that mostly fail here
	UDPBlocked  bool     `json:"udp_blocked,omitempty"`   // UDP mostly does not pass
	TCPStallKiB int      `json:"tcp_stall_kib,omitempty"` // TCP mostly stalls near this many KiB
	Devices     int64    `json:"devices"`                 // reports counted (not distinct devices)
	Days        int      `json:"days"`
}

// tally is the counters of one AS over the window.
type tally struct {
	reports int64
	nets    map[string]int64
	svc     map[int64]map[string]map[string]int64 // svc -> field -> bucket -> n
}

func sum(rows []store.SummaryCount) map[uint32]*tally {
	out := map[uint32]*tally{}
	for _, r := range rows {
		t := out[r.ASN]
		if t == nil {
			t = &tally{nets: map[string]int64{}, svc: map[int64]map[string]map[string]int64{}}
			out[r.ASN] = t
		}
		if r.Svc == 0 {
			switch r.Field {
			case "reports":
				t.reports += r.N
			case "net":
				t.nets[r.Bucket] += r.N
			}
			continue
		}
		if t.svc[r.Svc] == nil {
			t.svc[r.Svc] = map[string]map[string]int64{}
		}
		if t.svc[r.Svc][r.Field] == nil {
			t.svc[r.Svc][r.Field] = map[string]int64{}
		}
		t.svc[r.Svc][r.Field][r.Bucket] += r.N
	}
	return out
}

func total(m map[string]int64) int64 {
	var n int64
	for _, v := range m {
		n += v
	}
	return n
}

// hints of one AS for the services the client has.
func (t *tally) hints(svcs []uint16) *Hints {
	if t == nil || t.reports < K {
		return nil
	}
	h := &Hints{Devices: t.reports, Days: Window}
	type scored struct {
		svc   uint16
		score float64
	}
	var order []scored
	var udpNone, udpAll int64
	stalls := map[string]int64{}
	var tcpAll int64
	for _, s := range svcs {
		f := t.svc[int64(s)]
		res := f["result"]
		n := total(res)
		tcpAll += n
		for b, v := range f["stall"] {
			stalls[b] += v
		}
		udpAll += total(f["udp"])
		udpNone += f["udp"]["none"]
		if n < K {
			continue // too few here to tell this service apart
		}
		order = append(order, scored{s, (float64(res["works"]) + 0.5*float64(res["degraded"])) / float64(n)})
		if float64(res["fails"]) >= Majority*float64(n) {
			h.Avoid = append(h.Avoid, s)
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].score != order[j].score {
			return order[i].score > order[j].score
		}
		return order[i].svc < order[j].svc
	})
	for _, o := range order {
		h.Order = append(h.Order, o.svc)
	}
	if udpAll >= K && float64(udpNone) >= Majority*float64(udpAll) {
		h.UDPBlocked = true
	}
	if tcpAll >= K {
		var best string
		for b, v := range stalls {
			if best == "" || v > stalls[best] || v == stalls[best] && b < best {
				best = b
			}
		}
		if best != "" && float64(stalls[best]) >= Majority*float64(tcpAll) {
			h.TCPStallKiB, _ = strconv.Atoi(best)
		}
	}
	slices.Sort(h.Avoid)
	if len(h.Order) == 0 && len(h.Avoid) == 0 && !h.UDPBlocked && h.TCPStallKiB == 0 {
		return nil
	}
	return h
}

// Hints returns the hint for a client at addr with these services, or nil:
// reports off, an address without an AS, too few reports from it.
func (c *Collector) Hints(ctx context.Context, addr netip.Addr, svcs []uint16) *Hints {
	if c == nil || !Enabled(ctx, c.Store) || c.ASN == nil || !addr.IsValid() || addr.IsLoopback() {
		return nil
	}
	info, ok := c.ASN.Lookup(ctx, addr)
	if !ok || info.ASN == 0 {
		return nil
	}
	rows, err := c.Store.SummaryCounts(ctx, c.clock().Unix()/dayS-Window+1, info.ASN, false)
	if err != nil {
		return nil
	}
	return sum(rows)[info.ASN].hints(svcs)
}

// Network is the administrator's view of one AS over some days.
type Network struct {
	ASN      uint32
	Name     string
	Country  string
	Reports  int64
	Nets     map[string]int64
	Services map[int64]map[string]map[string]int64 // svc -> field -> bucket -> n
}

// View returns the networks with at least K reports over the last days,
// and how many reports the rest add up to: the node shows smaller groups
// to nobody, the administrator included (R4-21).
func (c *Collector) View(ctx context.Context, days int) (nets []Network, others int64, err error) {
	if days < 1 || days > Keep {
		days = Window
	}
	rows, err := c.Store.SummaryCounts(ctx, c.clock().Unix()/dayS-int64(days)+1, 0, true)
	if err != nil {
		return nil, 0, err
	}
	names, err := c.Store.SummaryAS(ctx)
	if err != nil {
		return nil, 0, err
	}
	for as, t := range sum(rows) {
		if t.reports < K {
			others += t.reports
			continue
		}
		nets = append(nets, Network{ASN: as, Name: names[as][0], Country: names[as][1], Reports: t.reports, Nets: t.nets, Services: t.svc})
	}
	sort.Slice(nets, func(i, j int) bool {
		if nets[i].Reports != nets[j].Reports {
			return nets[i].Reports > nets[j].Reports
		}
		return nets[i].ASN < nets[j].ASN
	})
	return nets, others, nil
}
