package api

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/asn"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/summary"
)

// SummaryDBs are the AS databases GetSummary reports on; tests point them
// elsewhere.
var SummaryDBs = [][2]string{{"operator", summary.OperatorDB}, {"release", summary.ReleaseDB}}

// GetSummary reports the client summaries (R4-21): only networks with at
// least k reports, the rest as a total.
func (s *Server) GetSummary(ctx context.Context, req *connect.Request[nodev1.GetSummaryRequest]) (*connect.Response[nodev1.GetSummaryResponse], error) {
	days := int(req.Msg.Days)
	if days < 1 || days > summary.Keep {
		days = summary.Window
	}
	api, _ := summary.API(ctx, s.Store)
	resp := &nodev1.GetSummaryResponse{Enabled: summary.Enabled(ctx, s.Store), Api: api, Days: uint32(days), K: summary.K}
	for _, d := range SummaryDBs {
		db := &asn.DB{Path: d[1]}
		built, kind, ok := db.Built()
		pb := &nodev1.SummaryDB{Role: d[0], Path: d[1], Present: ok, Type: kind}
		if ok {
			pb.Built = built.Unix()
		}
		resp.Dbs = append(resp.Dbs, pb)
	}
	nets, others, err := (&summary.Collector{Store: s.Store}).View(ctx, days)
	if err != nil {
		return nil, toConnect(err)
	}
	resp.OtherReports = others
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	names := map[int64]string{}
	for _, svc := range services {
		names[svc.ID] = svc.Name
	}
	for _, n := range nets {
		pb := &nodev1.SummaryNetwork{Asn: n.ASN, Name: n.Name, Country: n.Country, Reports: n.Reports, Nets: n.Nets, UdpMtu: n.MTU}
		for _, id := range slices.Sorted(maps.Keys(n.Services)) {
			f := n.Services[id]
			pb.Services = append(pb.Services, &nodev1.SummaryService{Id: uint32(id), Name: names[id],
				Results: f["result"], Udp: f["udp"], Mbps: f["mbps"], StallKib: f["stall"]})
		}
		resp.Networks = append(resp.Networks, pb)
	}
	return connect.NewResponse(resp), nil
}

// SetSummary turns the reports and the online lookup on or off. The token
// never goes into the audit log.
func (s *Server) SetSummary(ctx context.Context, req *connect.Request[nodev1.SetSummaryRequest]) (*connect.Response[nodev1.SetSummaryResponse], error) {
	m := req.Msg
	var err error
	switch m.Enabled {
	case "":
	case "on", "off":
		err = summary.SetEnabled(ctx, s.Store, m.Enabled == "on")
	default:
		err = fmt.Errorf("%w: enabled: on or off", store.ErrInvalid)
	}
	target := m.Enabled
	if err == nil && m.Api != "" {
		err = summary.SetAPI(ctx, s.Store, m.Api, m.Token)
		target += " api=" + m.Api
	}
	if err := s.done(ctx, "summary.set", target, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetSummaryResponse{}), nil
}
