package main

import (
	"bytes"
	"strings"
	"testing"
	"text/tabwriter"
	"time"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

func TestLoopState(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ok := &nodev1.LoopHealth{Name: "dns-zone dns", LastOk: now.Unix() - 240, Detail: "delegated; 3/3 resolvers; large 3/3; EDNS 1232–1400"}
	if got := loopState(ok, now); got != "ok 4m0s ago: delegated; 3/3 resolvers; large 3/3; EDNS 1232–1400" {
		t.Fatalf("ok %q", got)
	}
	failed := &nodev1.LoopHealth{Name: "dns-zone mdns", LastOk: now.Unix() - 3*86400, LastError: now.Unix() - 240, Failing: true,
		Error: "the parent delegates k2p.example.com to n7q.example.com at 198.51.100.9, the node is 203.0.113.7", Detail: "not delegated"}
	if got := loopState(failed, now); got != "FAILED 4m0s ago: the parent delegates k2p.example.com to n7q.example.com at 198.51.100.9, the node is 203.0.113.7 (last ok 72h0m0s ago)" {
		t.Fatalf("failed %q", got)
	}
	if got := loopState(&nodev1.LoopHealth{Name: "apply", LastOk: now.Unix() - 12}, now); got != "ok 12s ago" {
		t.Fatalf("plain %q", got)
	}
}

func TestPrintDNSCheck(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	printDNSCheck(w, &nodev1.CheckDNSZonesResponse{NextAt: now.Unix() + 600}, now)
	w.Flush()
	if got := b.String(); got != "no check yet, next in 10m0s: rayctl dns check -now\n" {
		t.Fatalf("no check %q", got)
	}
	ok := func(rtt uint32) *nodev1.DNSCheckStep { return &nodev1.DNSCheckStep{State: "ok", RttMs: rtt} }
	m := &nodev1.CheckDNSZonesResponse{CheckedAt: now.Unix() - 240, NextAt: now.Unix() + 3360, DurationMs: 3200,
		Resolvers: []string{"google 8.8.8.8", "quad9 9.9.9.9"},
		Zones: []*nodev1.DNSZoneCheck{{
			Service: "dns", Kind: "dnstt", Zone: "t3x.example.com", Ns: "n7q.example.com", State: "warn", Delegated: true,
			Parent:  &nodev1.DNSCheckStep{State: "ok", Detail: "example.com (3 servers) delegates to n7q.example.com, glue 203.0.113.7 = node, TTL 300"},
			Front:   &nodev1.DNSCheckStep{State: "ok", Detail: "SOA and probe on 203.0.113.7:53"},
			Backend: &nodev1.DNSCheckStep{State: "ok", Detail: "sealed poll answered in 1.0 s"},
			Resolvers: []*nodev1.DNSResolverCheck{
				{Resolver: "google 8.8.8.8", Soa: ok(30), Small: ok(38), Large: ok(41), Edns: 1400, CaseRandomized: true, Egress: "172.253.0.1"},
				{Resolver: "quad9 9.9.9.9", Soa: ok(90), Small: ok(95), Large: &nodev1.DNSCheckStep{State: "warn", Detail: "large answers lost (no answer in 5s): dnstt will hardly work there"},
					Edns: 1232, Egress: "74.63.16.1"},
			}}, {
			Service: "mdns", Kind: "masterdns", Zone: "k2p.example.com", Ns: "n7q.example.com", State: "fail",
			Error:     "the parent delegates k2p.example.com to n7q.example.com at 198.51.100.9, the node is 203.0.113.7",
			Parent:    &nodev1.DNSCheckStep{State: "fail", Detail: "the parent delegates k2p.example.com to n7q.example.com at 198.51.100.9, the node is 203.0.113.7", Fix: "rayctl dns sync"},
			Front:     &nodev1.DNSCheckStep{State: "ok", Detail: "answers on 203.0.113.7:53 (NOERROR)"},
			Resolvers: []*nodev1.DNSResolverCheck{{Resolver: "google 8.8.8.8", Small: &nodev1.DNSCheckStep{State: "skip"}}},
		}}}
	b.Reset()
	printDNSCheck(w, m, now)
	w.Flush()
	want := `checked 4m0s ago in 3.2 s, next in 56m0s
resolvers: google 8.8.8.8, quad9 9.9.9.9

t3x.example.com (dnstt dns), NS n7q.example.com: warn
  ok    parent   example.com (3 servers) delegates to n7q.example.com, glue 203.0.113.7 = node, TTL 300
  ok    front    SOA and probe on 203.0.113.7:53
  ok    backend  sealed poll answered in 1.0 s
  RESOLVER        SOA  SMALL  LARGE  EDNS  0x20  EGRESS
  google 8.8.8.8  ok   38ms   ok     1400  yes   172.253.0.1
  quad9 9.9.9.9   ok   95ms   warn   1232  no    74.63.16.1
  → quad9 9.9.9.9 large probe: large answers lost (no answer in 5s): dnstt will hardly work there

k2p.example.com (masterdns mdns), NS n7q.example.com: FAILED: the parent delegates k2p.example.com to n7q.example.com at 198.51.100.9, the node is 203.0.113.7
  fail  parent   the parent delegates k2p.example.com to n7q.example.com at 198.51.100.9, the node is 203.0.113.7
                 → rayctl dns sync
  ok    front    answers on 203.0.113.7:53 (NOERROR)
  resolvers not asked: the parent does not delegate the zone to the node
`
	if got := b.String(); got != want {
		t.Fatalf("got\n%s\nwant\n%s\ndiff at %d", got, want, strings.Index(got, strings.TrimPrefix(want, got)))
	}
}
