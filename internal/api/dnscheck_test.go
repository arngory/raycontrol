package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/arngory/raycontrol/internal/dnscheck"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/health"
)

func TestCheckDNSZones(t *testing.T) {
	ctx := context.Background()
	_, sock, _ := startServer(t)
	if _, err := NewUnixClient(sock).CheckDNSZones(ctx, connect.NewRequest(&nodev1.CheckDNSZonesRequest{})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("without a monitor: %v", err)
	}

	var runs atomic.Int32
	hb := &health.Board{}
	_, sock, _ = startServerWith(t, func(s *Server) []func() (string, http.Handler) {
		s.Health = hb
		s.DNSCheck = &dnscheck.Monitor{Checker: &dnscheck.Checker{System: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}},
			Gap: time.Hour, Targets: func(context.Context) ([]dnscheck.Zone, error) { runs.Add(1); return nil, nil }}
		return nil
	})
	c := NewUnixClient(sock)
	check := func(req *nodev1.CheckDNSZonesRequest) (*nodev1.CheckDNSZonesResponse, error) {
		r, err := c.CheckDNSZones(ctx, connect.NewRequest(req))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	if r, err := check(&nodev1.CheckDNSZonesRequest{}); err != nil || r.CheckedAt != 0 || runs.Load() != 0 {
		t.Fatalf("before any check: %v %v", r, err)
	}
	first, err := check(&nodev1.CheckDNSZonesRequest{Now: true})
	if err != nil || first.CheckedAt == 0 || first.Limited || runs.Load() != 1 {
		t.Fatalf("now: %v %v", first, err)
	}
	if r, err := check(&nodev1.CheckDNSZonesRequest{Now: true}); err != nil || !r.Limited || r.CheckedAt != first.CheckedAt || runs.Load() != 1 {
		t.Fatalf("now again: %v %v", r, err)
	}
	if r, err := check(&nodev1.CheckDNSZonesRequest{}); err != nil || r.CheckedAt != first.CheckedAt || r.Limited {
		t.Fatalf("the last: %v %v", r, err)
	}
	if _, err := check(&nodev1.CheckDNSZonesRequest{Resolvers: []string{"nsdi"}}); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("other resolvers too soon: %v", err)
	}
	if _, err := check(&nodev1.CheckDNSZonesRequest{Resolvers: []string{"example.com"}}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a bad resolver: %v", err)
	}

	// A zone's summary reaches status as the loop's detail.
	hb.Report("dns-zone dns", "delegated; 3/3 resolvers", nil)
	st, err := c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
	if err != nil || len(st.Msg.Loops) != 1 || st.Msg.Loops[0].Detail != "delegated; 3/3 resolvers" {
		t.Fatalf("status %v %v", st, err)
	}
}

// The report as the API gives it: what was found, never a key.
func TestDNSReportPB(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	rs, err := dnscheck.ParseResolvers([]string{"google"})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1_800_000_000, 0)
	rep := dnscheck.Report{Start: start, End: start.Add(1500 * time.Millisecond), Resolvers: rs, Zones: []dnscheck.ZoneResult{{
		Zone:   dnscheck.Zone{Service: "dns", Kind: "dnstt", Name: "t3x.example.com", NS: "n7q.example.com", ProbeKey: key, SealKey: key, Seal: "required"},
		Parent: dnscheck.Step{State: dnscheck.Fail, Detail: "example.com (3 servers) has no NS for t3x.example.com"},
		Front:  dnscheck.Step{State: dnscheck.OK, Detail: "SOA and probe on 203.0.113.7:53", RTT: 3 * time.Millisecond},
		Resolvers: []dnscheck.ResolverResult{{Resolver: rs[0], Small: dnscheck.Step{State: dnscheck.OK, RTT: 38 * time.Millisecond},
			EDNS: 1400, Mixed: true, Egress: netip.MustParseAddr("172.253.0.1")}},
	}}}
	pb := DNSReportPB(rep)
	z := pb.Zones[0]
	if pb.CheckedAt != start.Unix()+1 || pb.DurationMs != 1500 || pb.Resolvers[0] != "google 8.8.8.8" || z.State != "fail" ||
		z.Error != "example.com (3 servers) has no NS for t3x.example.com" || z.Front.RttMs != 3 || z.Parent.State != "fail" {
		t.Fatalf("report %v", pb)
	}
	if r := z.Resolvers[0]; r.Small.State != "ok" || r.Small.RttMs != 38 || r.Edns != 1400 || !r.CaseRandomized || r.Egress != "172.253.0.1" || r.Network != "udp" {
		t.Fatalf("resolver %v", r)
	}
	b, err := protojson.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	for _, enc := range []string{string(key), hex.EncodeToString(key), base64.StdEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key)} {
		if strings.Contains(string(b), enc) {
			t.Fatalf("a key in the answer: %s", b)
		}
	}
}
