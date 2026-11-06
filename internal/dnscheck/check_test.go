package dnscheck

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func (w *world) check(t *testing.T, zones []Zone, resolvers ...string) Report {
	t.Helper()
	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}
	return w.checker.Check(context.Background(), zones, mustResolvers(t, resolvers...), false)
}

// row is a resolver's row of a zone, by address.
func row(t *testing.T, z ZoneResult, addr string) ResolverResult {
	t.Helper()
	for _, r := range z.Resolvers {
		if r.Resolver.Addr.Addr().String() == addr {
			return r
		}
	}
	t.Fatalf("no row for %s in %+v", addr, z.Resolvers)
	return ResolverResult{}
}

// paced checks the rules the node keeps toward resolvers and parents: at
// most four queries a zone to one resolver, one query at a time to a
// server, no DO bit, RD only toward resolvers.
func (w *world) paced(t *testing.T) {
	t.Helper()
	for _, o := range w.net.overlaps {
		if _, isResolver := w.resolvers[o.to.Addr().String()]; isResolver {
			t.Errorf("two queries at once to the resolver %s: %s", o.to, o.what)
		}
	}
	perZone := map[string]int{}
	for _, q := range w.net.queries {
		if q.info.do {
			t.Errorf("DO bit in %s to %s", q.info.name, q.to)
		}
		if q.info.edns != ednsSize {
			t.Errorf("EDNS %d in %s to %s", q.info.edns, q.info.name, q.to)
		}
		if _, isResolver := w.resolvers[q.to.Addr().String()]; isResolver {
			if !q.info.h.RecursionDesired {
				t.Errorf("no RD toward the resolver %s: %s", q.to, q.info.name)
			}
			zone := mdnsZone
			if strings.HasSuffix(q.info.name, dnsttZone) {
				zone = dnsttZone
			}
			perZone[q.to.String()+" "+zone]++
		}
	}
	for k, n := range perZone {
		if n > queriesPerZone {
			t.Errorf("%d queries to %s", n, k)
		}
	}
	for i, p := range w.parents {
		if len(p.rd) > 0 {
			t.Errorf("parent server %d got RD set: %v", i, p.rd)
		}
	}
}

func TestCheckHealthy(t *testing.T) {
	w := newWorld(t)
	// seal=required: sealed polls, padded probe answers.
	w.front.zones[dnsttZone].seal, w.front.zones[dnsttZone].sealPad = "required", true
	zones := w.zones()
	zones[0].Seal = "required"
	rep := w.check(t, zones)
	w.paced(t)
	if len(rep.Zones) != 2 {
		t.Fatalf("zones %+v", rep.Zones)
	}
	d, m := rep.Zones[0], rep.Zones[1]
	for _, z := range []ZoneResult{d, m} {
		if err := z.Err(); err != nil || z.State() != OK {
			t.Errorf("%s: %v (state %v)\n%+v", z.Zone.Name, err, z.State(), z)
		}
		if !z.Delegated || z.Parent.State != OK ||
			z.Parent.Detail != "example.com (3 servers) delegates to n7q.example.com, glue 203.0.113.7 = node, TTL 300" {
			t.Errorf("%s parent %+v", z.Zone.Name, z.Parent)
		}
	}
	if d.Front.State != OK || d.Front.Detail != "SOA and probe on 203.0.113.7:53" {
		t.Errorf("front %+v", d.Front)
	}
	if d.Backend.State != OK || !strings.HasPrefix(d.Backend.Detail, "sealed poll answered in") {
		t.Errorf("backend %+v", d.Backend)
	}
	if m.Front.State != OK || m.Backend.State != Skip {
		t.Errorf("masterdns locally %+v %+v", m.Front, m.Backend)
	}
	for _, c := range []struct {
		addr, egress string
		edns         int
		mixed        bool
	}{{"8.8.8.8", "172.253.0.1", 1400, true}, {"1.1.1.1", "162.158.0.1", 1232, false}, {"9.9.9.9", "74.63.16.1", 1232, false}} {
		r := row(t, d, c.addr)
		if r.SOA.State != OK || r.Small.State != OK || r.Large.State != OK || r.EDNS != c.edns || r.Mixed != c.mixed || r.Egress.String() != c.egress {
			t.Errorf("%s: %+v", c.addr, r)
		}
		if mr := row(t, m, c.addr); mr.Small.State != OK {
			t.Errorf("masterdns via %s: %+v", c.addr, mr.Small)
		}
	}
	if got := d.Summary(); got != "delegated; 3/3 resolvers; large 3/3; EDNS 1232–1400" {
		t.Errorf("summary %q", got)
	}
	if got := m.Summary(); got != "delegated; 3/3 resolvers" {
		t.Errorf("masterdns summary %q", got)
	}
}

// The parent in its variants: right without glue, no NS (the wildcard
// answers), another NS name at the node, the glue elsewhere, servers that
// disagree. No resolver hears of a zone before the parent delegates it to
// the node.
func TestCheckParent(t *testing.T) {
	for _, c := range []struct {
		mode      string
		partial   bool
		state     State
		delegated bool
		detail    string
	}{
		{"noglue", false, OK, true, "example.com (3 servers) delegates to n7q.example.com, address 203.0.113.7 = node, TTL 300"},
		{"nons", false, Fail, false, "example.com (3 servers) has no NS for t3x.example.com: the wildcard *.example.com answers it instead"},
		{"nxdomain", false, Fail, false, "example.com (3 servers) says t3x.example.com does not exist (NXDOMAIN): no delegation"},
		{"wrongns", false, Warn, true, "example.com (3 servers) delegates to other.example.com, glue 203.0.113.7 = node, TTL 300; the front names n7q.example.com at the apex"},
		{"wrongglue", false, Fail, false, "the parent delegates t3x.example.com to n7q.example.com at 198.51.100.9, the node is 203.0.113.7"},
		{"nons", true, Fail, false, "only 2 of 3 servers of example.com delegate t3x.example.com"},
	} {
		t.Run(fmt.Sprintf("%s partial=%v", c.mode, c.partial), func(t *testing.T) {
			w := newWorld(t)
			for i, p := range w.parents {
				if !c.partial || i == 2 {
					p.set(dnsttZone, c.mode)
				}
			}
			rep := w.check(t, w.zones()[:1])
			w.paced(t)
			z := rep.Zones[0]
			if z.Parent.State != c.state || z.Delegated != c.delegated || z.Parent.Detail != c.detail {
				t.Fatalf("parent %v %v %q", z.Parent.State, z.Delegated, z.Parent.Detail)
			}
			asked := 0
			for ip := range w.resolvers {
				asked += len(w.net.sent(netip.MustParseAddr(ip)))
			}
			if !c.delegated && asked != 0 {
				t.Fatalf("%d queries to resolvers before the delegation", asked)
			}
			if err := z.Err(); (c.state == Fail) != (err != nil) || (err != nil && !strings.Contains(err.Error(), c.detail)) {
				t.Fatalf("err %v", err)
			}
			if !c.delegated && !strings.Contains(z.Summary(), "not delegated; resolvers not asked") {
				t.Fatalf("summary %q", z.Summary())
			}
			// The front is asked on the node all the same.
			if z.Front.State != OK {
				t.Fatalf("front %+v", z.Front)
			}
		})
	}
	// Parents that do not answer the node: nothing is said of the zone,
	// and resolvers are not asked.
	w := newWorld(t)
	for _, ip := range parentIPs {
		w.net.handle(netip.AddrPortFrom(ip, 53), nil)
	}
	z := w.check(t, w.zones()[:1]).Zones[0]
	if z.Parent.State != Warn || z.Delegated || z.Err() != nil || !strings.Contains(z.Parent.Detail, "did not answer the node") {
		t.Fatalf("silent parent %+v %v", z.Parent, z.Err())
	}
	if n := len(w.net.sent(netip.MustParseAddr("8.8.8.8"))); n != 0 {
		t.Fatalf("%d queries to a resolver", n)
	}
}

// Resolvers and their habits (dnsprobe-v1 §6).
func TestCheckResolvers(t *testing.T) {
	w := newWorld(t)
	sims := map[string]*resolverSim{
		"192.0.2.101": {edns: 512},                   // small answers only
		"192.0.2.102": {edns: 1220},                  // still the large one
		"192.0.2.103": {edns: 0},                     // no OPT toward the node
		"192.0.2.104": {edns: 1232, dropOver: 600},   // large answers lost
		"192.0.2.105": {edns: 1232, tcOver: 512},     // large answers truncated over UDP
		"192.0.2.106": {edns: 1232, dropFirst: true}, // the first copy lost
		"192.0.2.107": {servfail: true},              // no way to the node
		"192.0.2.108": {silent: true},                // no answer
		"192.0.2.109": {forge: true},                 // answers for the zone itself
		"192.0.2.110": {nxdomain: true},              // too
		"192.0.2.111": {edns: 1232, case20: true},    // 0x20
		"192.0.2.112": {edns: 1232, minimise: true},  // QNAME minimisation
	}
	var addrs []string
	for ip, r := range sims {
		r.egress = netip.MustParseAddr(ip).Next()
		w.resolver(ip, r)
		addrs = append(addrs, ip)
	}
	rep := w.check(t, w.zones()[:1], addrs...)
	w.paced(t)
	z := rep.Zones[0]
	for _, c := range []struct {
		addr         string
		small, large State
		detail       string // of the step that is not ok
	}{
		{"192.0.2.101", OK, Warn, "a small answer: it advertises EDNS 512 to the node; dnstt runs slower there"},
		{"192.0.2.102", OK, OK, ""},
		{"192.0.2.103", OK, Warn, "a small answer: it sends the node no EDNS; dnstt runs slower there"},
		{"192.0.2.104", OK, Warn, "large answers lost (no answer in 150ms): dnstt will hardly work there"},
		{"192.0.2.105", OK, Warn, "large answers come truncated over UDP, whole over TCP"},
		{"192.0.2.106", OK, Skip, "its queries of this round are spent"},
		{"192.0.2.107", Fail, Skip, "SERVFAIL: it does not reach the node"},
		{"192.0.2.108", Fail, Skip, "no answer in 150ms"},
		{"192.0.2.109", Fail, Skip, "a TXT the node did not make (the token does not match): the answer is not the node's (the resolver answers for the zone itself?)"},
		{"192.0.2.110", Fail, Skip, "NXDOMAIN: the answer is not the node's (the resolver answers for the zone itself?)"},
		{"192.0.2.111", OK, OK, ""},
		{"192.0.2.112", OK, OK, ""},
	} {
		r := row(t, z, c.addr)
		detail := r.Small.Detail
		if c.small == OK {
			detail = r.Large.Detail
		}
		if r.Small.State != c.small || r.Large.State != c.large || detail != c.detail {
			t.Errorf("%s: small %v, large %v %q; want %v, %v %q", c.addr, r.Small.State, r.Large.State, detail, c.small, c.large, c.detail)
		}
	}
	if r := row(t, z, "192.0.2.111"); !r.Mixed {
		t.Errorf("0x20 not seen: %+v", r)
	}
	// The resolver that lost the first copies got each query twice: the
	// apex and the small probe took its four.
	if n := len(w.net.sent(netip.MustParseAddr("192.0.2.106"))); n != 4 {
		t.Errorf("%d queries to the lossy resolver", n)
	}
	// TCP after TC: the large probe again.
	if qs := w.net.sent(netip.MustParseAddr("192.0.2.105")); len(qs) != 4 || qs[3].network != "tcp" {
		t.Errorf("queries to the truncating resolver %+v", qs)
	}
	// Some resolvers got through: the zone is fine, with its warnings in
	// the table.
	if err := z.Err(); err != nil {
		t.Errorf("err %v", err)
	}
	if got := z.Summary(); got != "delegated; 8/12 resolvers; large 3/7; EDNS 512–1232" {
		t.Errorf("summary %q", got)
	}
}

// No resolver that counts gets through: the zone fails, saying why. The
// Russian ones only warn.
func TestCheckUnreached(t *testing.T) {
	w := newWorld(t)
	for _, ip := range []string{"8.8.8.8", "1.1.1.1"} {
		w.resolvers[ip].silent = true
	}
	w.resolvers["9.9.9.9"].servfail = true
	w.resolver("195.208.5.1", &resolverSim{egress: netip.MustParseAddr("195.208.5.2"), servfail: true})
	w.resolver("195.208.4.1", &resolverSim{egress: netip.MustParseAddr("195.208.4.2"), edns: 1232})
	z := w.check(t, w.zones()[:1], "google", "cloudflare", "quad9", "nsdi").Zones[0]
	err := z.Err()
	want := "no resolver got the zone's answer from the node (google 8.8.8.8: no answer in 150ms; cloudflare 1.1.1.1: no answer in 150ms; " +
		"quad9 9.9.9.9: SERVFAIL: it does not reach the node): is UDP 53 open in the provider's firewall?"
	if err == nil || err.Error() != want {
		t.Fatalf("err %v", err)
	}
	if r := row(t, z, "195.208.5.1"); r.Small.State != Warn {
		t.Fatalf("nsdi failing %+v", r.Small)
	}
	if r := row(t, z, "195.208.4.1"); r.Small.State != OK {
		t.Fatalf("nsdi passing %+v", r.Small)
	}
	// nsdi alone: its failure is never the zone's.
	w = newWorld(t)
	w.resolver("195.208.5.1", &resolverSim{servfail: true})
	w.resolver("195.208.4.1", &resolverSim{silent: true})
	if z := w.check(t, w.zones()[:1], "nsdi").Zones[0]; z.Err() != nil || z.State() != Warn {
		t.Fatalf("nsdi only: %v %v", z.Err(), z.State())
	}
	// Resolvers the node has no route to (IPv4 from an IPv6-only node):
	// skipped, not failed.
	w = newWorld(t)
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"} {
		w.net.unreach[netip.MustParseAddr(ip)] = true
	}
	z = w.check(t, w.zones()[:1]).Zones[0]
	if z.Err() != nil || row(t, z, "8.8.8.8").Small.State != Skip || !strings.Contains(z.Summary(), "resolvers: no route from the node") {
		t.Fatalf("unreachable: %v %q", z.Err(), z.Summary())
	}
}

// The node itself: the front down, a zone it does not have, a key it does
// not know; the backend down, behind auth=required, with another seal key.
func TestCheckNode(t *testing.T) {
	t.Run("front down", func(t *testing.T) {
		w := newWorld(t)
		w.net.handle(nodeFront, nil)
		for _, r := range w.resolvers {
			r.node = func(string, netip.Addr, []byte) []byte { return nil }
		}
		z := w.check(t, w.zones()).Zones
		for _, zr := range z {
			if zr.Front.State != Fail || zr.Err() == nil || !strings.Contains(zr.Err().Error(), "the front: ") {
				t.Errorf("%s: %+v %v", zr.Zone.Name, zr.Front, zr.Err())
			}
		}
	})
	t.Run("zone not in the front", func(t *testing.T) {
		w := newWorld(t)
		delete(w.front.zones, dnsttZone)
		zr := w.check(t, w.zones()[:1]).Zones[0]
		if zr.Front.State != Fail || zr.Front.Detail != "REFUSED on 203.0.113.7:53: t3x.example.com is not among the front's zones" {
			t.Fatalf("front %+v", zr.Front)
		}
	})
	t.Run("another probe key", func(t *testing.T) {
		w := newWorld(t)
		w.front.key = seq(9, 32)
		zr := w.check(t, w.zones()[:1]).Zones[0]
		if zr.Front.State != Warn || !strings.Contains(zr.Front.Detail, "does niko-front have the node's key?") {
			t.Fatalf("front %+v", zr.Front)
		}
		if err := zr.Err(); err == nil || !strings.Contains(err.Error(), "no resolver got the zone's answer from the node") || strings.Contains(err.Error(), "firewall") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("the front on loopback", func(t *testing.T) {
		w := newWorld(t)
		w.checker.Local = func(netip.Addr) bool { return false } // behind 1:1 NAT
		loop := netip.MustParseAddrPort("127.0.0.1:53")
		w.net.handle(loop, w.front.handle)
		zr := w.check(t, w.zones()[:1]).Zones[0]
		if zr.Front.Detail != "SOA and probe on 127.0.0.1:53" || len(w.net.sent(loop.Addr())) == 0 {
			t.Fatalf("front %+v", zr.Front)
		}
	})
	t.Run("backend down", func(t *testing.T) {
		w := newWorld(t)
		w.front.zones[dnsttZone].down = true
		zr := w.check(t, w.zones()[:1]).Zones[0]
		if zr.Backend.State != Warn || zr.Err() != nil || zr.Front.State != OK {
			t.Fatalf("backend %+v front %+v err %v", zr.Backend, zr.Front, zr.Err())
		}
		if !strings.Contains(zr.Summary(), "backend: sealed poll: no answer in 150ms: is the dnstt backend up?") {
			t.Fatalf("summary %q", zr.Summary())
		}
	})
	t.Run("auth required", func(t *testing.T) {
		w := newWorld(t)
		w.front.zones[dnsttZone].auth, w.front.zones[dnsttZone].authKey = "required", seq(0x60, 32)
		zones := w.zones()[:1]
		zones[0].Auth = "required"
		zr := w.check(t, zones).Zones[0]
		if zr.Backend.State != OK || !strings.HasPrefix(zr.Backend.Detail, "alive: NODATA to a sealed poll without a device's tag") {
			t.Fatalf("backend %+v", zr.Backend)
		}
		// With a key the poll goes through: the node's own (provision.
		// DNSCheckDevice), a device's (rayctl probe -dns).
		zones[0].AuthKey = seq(0x60, 32)
		if zr := w.check(t, zones).Zones[0]; zr.Backend.State != OK || !strings.HasPrefix(zr.Backend.Detail, "sealed poll answered") {
			t.Fatalf("tagged %+v", zr.Backend)
		}
		// Tagged, a backend with another seal key is not alive but wrong
		// (review 8: untagged, NODATA read as alive hid a stale key).
		w.front.zones[dnsttZone].sealKey, w.front.zones[dnsttZone].seal = seq(0x50, 32), "required"
		if zr := w.check(t, zones).Zones[0]; zr.Backend.State != Warn || zr.Backend.Detail != "NODATA to a sealed poll: the backend does not take the service's seal key" {
			t.Fatalf("tagged, another seal key %+v", zr.Backend)
		}
	})
	t.Run("another seal key", func(t *testing.T) {
		w := newWorld(t)
		w.front.zones[dnsttZone].sealKey = seq(0x50, 32)
		// optional: the backend reads the poll as an open one and answers
		// open, which does not carry the tag.
		zr := w.check(t, w.zones()[:1]).Zones[0]
		if zr.Backend.State != Warn || zr.Backend.Fix != "the backend has another seal key: rayctl apply" {
			t.Fatalf("optional %+v", zr.Backend)
		}
		w.front.zones[dnsttZone].seal = "required"
		zr = w.check(t, w.zones()[:1]).Zones[0]
		if zr.Backend.State != Warn || zr.Backend.Detail != "NODATA to a sealed poll: the backend does not take the service's seal key" {
			t.Fatalf("required %+v", zr.Backend)
		}
		// The seal off: an open poll, answered open.
		w.front.zones[dnsttZone].seal = "off"
		zones := w.zones()[:1]
		zones[0].Seal = "off"
		if zr := w.check(t, zones).Zones[0]; zr.Backend.State != OK || !strings.HasPrefix(zr.Backend.Detail, "poll answered") {
			t.Fatalf("off %+v", zr.Backend)
		}
	})
}

// The round's time runs out: what was not done is skipped, and a zone
// does not fail for it.
func TestCheckRoundOver(t *testing.T) {
	w := newWorld(t)
	for _, r := range w.resolvers {
		r.silent = true
	}
	// A round that waited for the resolvers would take GiveUp at least:
	// far past the Round, whatever the load (-race in parallel took 1.5 s
	// for a round of 300 ms once).
	w.checker.GiveUp, w.checker.Retry = 6*time.Second, 3*time.Second
	w.checker.Round = 300 * time.Millisecond
	start := time.Now()
	z := w.check(t, w.zones()[:1]).Zones[0]
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the round took %v", d)
	}
	if z.Err() != nil || row(t, z, "8.8.8.8").Small.State != Skip {
		t.Fatalf("err %v, rows %+v", z.Err(), z.Resolvers)
	}
}

// Parents only: no front, no resolver.
func TestCheckParentOnly(t *testing.T) {
	w := newWorld(t)
	rep := w.checker.Check(context.Background(), w.zones(), mustResolvers(t, DefaultResolvers...), true)
	if !rep.ParentOnly || !rep.Zones[0].Delegated || rep.Zones[0].Front.State != Skip || rep.Zones[0].Resolvers != nil {
		t.Fatalf("report %+v", rep.Zones[0])
	}
	for _, q := range w.net.queries {
		if q.to == nodeFront || q.to.Addr().String() == "8.8.8.8" {
			t.Fatalf("query to %s", q.to)
		}
	}
	// The parent is found once for both zones.
	soa := 0
	for _, q := range w.net.sent(systemAddr.Addr()) {
		if q.info.q.Type == dnsmessage.TypeSOA {
			soa++
		}
	}
	if soa != 1 {
		t.Fatalf("%d SOA lookups for one parent", soa)
	}
}
