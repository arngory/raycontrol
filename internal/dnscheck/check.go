// Package dnscheck checks a node's DNS tunnel zones as a client's resolver
// reaches them (docs/09-observability.md): the delegation at the parent,
// the front and the backend on the node itself, and the zone through
// public resolvers with dnsprobe-v1 (docs/spec/dnsprobe-v1.md). It keeps
// no state of the node: rayd gives it the zones (provision.DNSCheckTargets).
//
// It is gentle with the resolvers, which the node's clients share: one
// resolver gets one query at a time and at most four a zone in a round (a
// second copy after 2 s without an answer, none after 5 s), at most six
// resolvers at once, a round in 30 s; no DO bit. The probes take at most
// 18 of the 40 tokens the front keeps for a resolver's network. Resolvers
// are asked only once the parent delegates the zone to the node: an early
// NXDOMAIN would stay in their caches for the parent's negative TTL, and
// everything below it with it (RFC 2308, RFC 8020).
package dnscheck

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Zone is a zone to check and what the check needs of its service.
type Zone struct {
	Service string // the service's name
	Kind    string // dnstt | masterdns | slipstream
	Name    string // the zone
	Spare   bool   // a spare zone of the service (spec/dnszones-v1.md), not its main one
	// NS is the name the parent should delegate the zone to; "" when the
	// delegation is the operator's own.
	NS string
	// Host is the node's public address (or a name of it): the delegation
	// must lead there.
	Host string
	// Front is where the front is asked on the node; zero: 127.0.0.1:53
	// (frontAddr).
	Front    netip.AddrPort
	ProbeKey Key    // dnsprobe-v1 (dnstt, slipstream: the front answers it)
	Seal     string // dnsseal-v1 mode (dnstt): off, optional or required
	SealKey  Key    // seals the poll unless the seal is off
	Auth     string // dnsauth-v1 mode (dnstt)
	AuthKey  Key    // a dnsauth key on the service for a tagged poll: the node's own (provision.DNSCheckDevice)
	AuthV2   bool   // the service takes dnsauth-v2 tags (auth_hint not off): the poll signs with v2
	SvcID    uint16
}

// Key is a key the check uses. It never prints.
type Key []byte

func (Key) String() string { return "<key>" }

// Format prints the placeholder whatever the verb.
func (Key) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("<key>")) }

// LogValue keeps the key out of logs.
func (Key) LogValue() slog.Value { return slog.StringValue("<key>") }

// State is how a step went.
type State int

const (
	Skip State = iota // not done
	OK
	Warn
	Fail
)

func (s State) String() string {
	switch s {
	case OK:
		return "ok"
	case Warn:
		return "warn"
	case Fail:
		return "fail"
	}
	return "skip"
}

// Step is one check's outcome.
type Step struct {
	State  State
	Detail string
	Fix    string // what to do, when it did not go well
	RTT    time.Duration
}

// ResolverResult is a zone through one resolver.
type ResolverResult struct {
	Resolver Resolver
	SOA      Step // the zone's apex (dnstt and slipstream with NS); it may come from the resolver's cache
	Small    Step // dnstt, slipstream: the small probe; masterdns: the answer to a random name
	Large    Step // dnstt, slipstream: the large probe
	// What the node saw of the resolver (dnstt, from the probe).
	EDNS   int  // the UDP size it advertised to the node, 0 without OPT
	Mixed  bool // it applies 0x20
	Egress netip.Addr
}

// ZoneResult is one zone's check.
type ZoneResult struct {
	Zone      Zone
	Parent    Step
	Delegated bool // the parent delegates the zone to the node: resolvers were asked
	Front     Step
	Backend   Step
	Resolvers []ResolverResult
}

// Report is one round of checks.
type Report struct {
	Start, End time.Time
	Resolvers  []Resolver
	ParentOnly bool // only the parents were asked (a new zone or address)
	Zones      []ZoneResult
	// Limited: an operator's check came too soon after the last one; this
	// is the last one.
	Limited bool
}

// Checker checks zones. The zero value checks on the host's network.
type Checker struct {
	Net    Exchanger        // nil: Net{}
	System []netip.AddrPort // recursive resolvers that find the parents; nil: the host's (SystemResolvers)
	// Private lets the walk ask a parent's server at an address no public
	// server has (PublicAddr): tests, and labs (rayd -dns-check-private).
	// Off, such servers are not asked, wherever a zone's DNS points.
	Private bool
	Now     func() time.Time // the probes' minute; nil: time.Now
	// The pace: a second copy after Retry without an answer, none after
	// GiveUp, a round within Round, Parallel resolvers at once.
	Retry, GiveUp, Round time.Duration
	Parallel             int
}

// Pacing defaults.
const (
	DefaultRetry    = 2 * time.Second
	DefaultGiveUp   = 5 * time.Second
	DefaultRound    = 30 * time.Second
	DefaultParallel = 6
	// queriesPerZone: what one resolver gets of a zone in a round.
	queriesPerZone = 4
)

func (c *Checker) net() Exchanger {
	if c.Net == nil {
		return Net{}
	}
	return c.Net
}

func (c *Checker) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func (c *Checker) retry() time.Duration  { return orDefault(c.Retry, DefaultRetry) }
func (c *Checker) giveUp() time.Duration { return orDefault(c.GiveUp, DefaultGiveUp) }
func (c *Checker) round() time.Duration  { return orDefault(c.Round, DefaultRound) }

func (c *Checker) parallel() int {
	if c.Parallel <= 0 {
		return DefaultParallel
	}
	return c.Parallel
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

func (c *Checker) asker(network string, addr netip.AddrPort, budget int) *asker {
	return &asker{c: c, net: network, addr: addr, budget: budget}
}

// Check checks the zones in one round: the parents first; then, only for
// zones the parent delegates to the node, the resolvers, while the front
// and the backend are asked on the node. parentOnly stops after the
// parents.
func (c *Checker) Check(ctx context.Context, zones []Zone, resolvers []Resolver, parentOnly bool) Report {
	ctx, cancel := context.WithTimeout(ctx, c.round())
	defer cancel()
	rep := Report{Start: time.Now(), Resolvers: resolvers, ParentOnly: parentOnly, Zones: make([]ZoneResult, len(zones))}
	rd := &round{c: c, system: c.System, parents: map[string]*lookup[parentZone]{}, hosts: map[string]*lookup[[]netip.Addr]{}}
	if rd.system == nil {
		rd.system, rd.sysErr = SystemResolvers("")
	}
	nodes := make([][]netip.Addr, len(zones))
	var wg sync.WaitGroup
	for i, z := range zones {
		// As the front matches it and the parent writes it (review 7: a
		// zone in capitals or with a final dot was "not delegated").
		z.Name, z.NS = canonical(z.Name), canonical(z.NS)
		rep.Zones[i] = ZoneResult{Zone: z}
		wg.Go(func() {
			nodes[i] = rd.node(ctx, z.Host)
			rep.Zones[i].Parent, rep.Zones[i].Delegated = rd.delegation(ctx, z, nodes[i])
		})
	}
	wg.Wait()
	if parentOnly {
		rep.End = time.Now()
		return rep
	}
	for i := range zones {
		rep.Zones[i].Resolvers = make([]ResolverResult, len(resolvers))
	}
	// On the node: the front, and the backend behind it.
	for i, z := range zones {
		wg.Go(func() {
			front := frontAddr(z)
			rep.Zones[i].Front = c.front(ctx, z, front)
			if z.Kind == "dnstt" {
				rep.Zones[i].Backend = c.backend(ctx, z, front)
			}
		})
	}
	// Through the resolvers: one resolver's queries in turn, zone by zone.
	sem := make(chan struct{}, c.parallel())
	for j, r := range resolvers {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			for i, z := range zones {
				if !rep.Zones[i].Delegated {
					rep.Zones[i].Resolvers[j] = ResolverResult{Resolver: r}
					continue
				}
				rep.Zones[i].Resolvers[j] = c.viaResolver(ctx, z, r)
			}
		})
	}
	wg.Wait()
	rep.End = time.Now()
	return rep
}

// frontAddr is where the front is asked: over loopback, which it
// listens on too (0.0.0.0:53). Not the node's public address: the front's
// answer to it would go over lo to a local address, which the perimeter
// refuses to the data plane (S-2): every node with its address on an
// interface saw "no answer" there, its clients' tunnels working. A DNS
// server holding the public address beside the front is rayd's port53
// check.
func frontAddr(z Zone) netip.AddrPort {
	if z.Front.IsValid() {
		return z.Front
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53)
}

// failed turns an error of a query into a step of the given state; a
// round that ran out, a server the node has no route to and a spent budget
// are skips: they say nothing of the zone.
func failed(err error, state State, what string) Step {
	switch {
	case errors.Is(err, errRoundOver) || errors.Is(err, errBudget):
		return Step{State: Skip, Detail: err.Error()}
	case unreachable(err):
		return Step{State: Skip, Detail: "no route from the node: " + err.Error()}
	}
	return Step{State: state, Detail: what + err.Error()}
}

// probed reports whether the zone is checked with dnsprobe-v1 probes,
// which the front answers itself: dnstt's always (without the key, a skip),
// slipstream's when the check has the key. Otherwise an answer to a random
// name: masterdns's, and slipstream's for a client without dns_probe (the
// front answers an untagged query in its zone with NOERROR), never a
// silent skip.
func probed(z Zone) bool {
	return z.Kind == "dnstt" || z.Kind == "slipstream" && len(z.ProbeKey) == 32
}

// front checks the zone at the front on the node: the apex and a small
// probe where probed, an answer to a random name otherwise. REFUSED is
// the front's own: the zone is not in its configuration.
func (c *Checker) front(ctx context.Context, z Zone, addr netip.AddrPort) Step {
	a := c.asker("udp", addr, queriesPerZone)
	where := addr.String()
	refused := Step{State: Fail, Detail: "REFUSED on " + where + ": " + z.Name + " is not among the front's zones",
		Fix: "rayctl apply; journalctl -u niko-front"}
	down := func(err error, who string) Step {
		s := failed(err, Fail, who+" on "+where+": ")
		if s.State == Fail {
			s.Fix = "systemctl status niko-front; rayctl status: port53"
		}
		return s
	}
	if !probed(z) {
		x, err := c.randomName(ctx, a, z, false)
		switch {
		case err != nil:
			return down(err, "the front or the backend")
		case x.r.RCode == dnsmessage.RCodeRefused:
			return refused
		case x.r.RCode == dnsmessage.RCodeSuccess || x.r.RCode == dnsmessage.RCodeNameError:
			return Step{State: OK, Detail: "answers on " + where + " (" + rcodeText(x.r.RCode) + ")", RTT: x.rtt}
		}
		return Step{State: Fail, Detail: rcodeText(x.r.RCode) + " on " + where, Fix: "journalctl -u niko-" + z.Service}
	}
	var did []string
	var warns []string
	if z.NS != "" {
		q, err := newQuery(z.Name, dnsmessage.TypeSOA, false)
		if err != nil {
			return Step{State: Fail, Detail: err.Error()}
		}
		x, err := a.ask(ctx, q)
		switch {
		case err != nil:
			return down(err, "SOA")
		case x.r.RCode == dnsmessage.RCodeRefused:
			return refused
		}
		owner, mname, ok := soaIn(x.r.answers)
		switch {
		case x.r.RCode != dnsmessage.RCodeSuccess:
			warns = append(warns, "SOA: "+rcodeText(x.r.RCode))
		case !ok || owner != canonical(z.Name):
			warns = append(warns, "no SOA at the apex: niko-server before v0.9.0?")
		case mname != canonical(z.NS):
			warns = append(warns, fmt.Sprintf("the apex names %s, rayd asks for %s: rayctl apply", mname, z.NS))
		default:
			did = append(did, "SOA")
		}
	}
	if len(z.ProbeKey) == 32 {
		_, x, err := c.probe(ctx, a, z, false, false)
		switch {
		case err == nil:
			did = append(did, "probe")
		case errors.Is(err, errRoundOver) || errors.Is(err, errBudget):
		case x.r == nil:
			return down(err, "probe")
		case x.r.RCode == dnsmessage.RCodeRefused:
			return refused
		default:
			warns = append(warns, "the probe: "+err.Error()+": does niko-front have the node's key? systemctl restart niko-front")
		}
	}
	if len(warns) > 0 {
		return Step{State: Warn, Detail: strings.Join(warns, "; ")}
	}
	if len(did) == 0 {
		return Step{State: Skip}
	}
	return Step{State: OK, Detail: strings.Join(did, " and ") + " on " + where}
}

// backend polls the dnstt backend through the front on the node: sealed
// when the seal is on, with a tag when a device's key is at hand.
func (c *Checker) backend(ctx context.Context, z Zone, addr netip.AddrPort) Step {
	var seal, auth []byte
	if z.Seal != "" && z.Seal != "off" && len(z.SealKey) == 32 {
		seal = z.SealKey
	}
	if z.Auth != "" && z.Auth != "off" && len(z.AuthKey) == 32 {
		auth = z.AuthKey
	}
	p, err := NewPoll(z.Name, seal, auth, z.AuthV2, c.now())
	if err != nil {
		return Step{State: Warn, Detail: err.Error()}
	}
	q, err := newQuery(p.Name, dnsmessage.TypeTXT, false)
	if err != nil {
		return Step{State: Warn, Detail: err.Error()}
	}
	what := "poll"
	if p.Sealed {
		what = "sealed poll"
	}
	x, err := c.asker("udp", addr, 2).ask(ctx, q)
	if err != nil {
		s := failed(err, Warn, what+": ")
		if s.State == Warn {
			s.Detail += ": is the dnstt backend up?"
			s.Fix = "systemctl status niko-" + z.Service
		}
		return s
	}
	if x.r.RCode != dnsmessage.RCodeSuccess {
		return Step{State: Warn, Detail: what + ": " + rcodeText(x.r.RCode)}
	}
	data, ok := x.r.txt(p.Name)
	switch {
	case ok:
		if _, err := p.Open(data); err != nil {
			s := Step{State: Warn, Detail: what + ": the answer does not open: " + err.Error()}
			if p.Sealed {
				s.Fix = "the backend has another seal key: rayctl apply"
			}
			return s
		}
		return Step{State: OK, Detail: fmt.Sprintf("%s answered in %.1f s", what, x.rtt.Seconds()), RTT: x.rtt}
	case z.Auth == "required" && auth == nil:
		return Step{State: OK, Detail: "alive: NODATA to a " + what + " without a device's tag (auth=required)", RTT: x.rtt}
	case p.Sealed:
		return Step{State: Warn, Detail: "NODATA to a sealed poll: the backend does not take the service's seal key", Fix: "rayctl apply"}
	case z.Seal == "required":
		return Step{State: Warn, Detail: "NODATA: seal=required and the service has no seal key yet", Fix: "rayctl apply"}
	}
	return Step{State: Warn, Detail: "NODATA to a poll: the backend does not take it"}
}

// viaResolver checks a zone through one resolver.
func (c *Checker) viaResolver(ctx context.Context, z Zone, r Resolver) ResolverResult {
	res := ResolverResult{Resolver: r}
	a := c.asker(r.Net, r.Addr, queriesPerZone)
	switch {
	case probed(z):
		if z.NS != "" {
			res.SOA = c.apexVia(ctx, a, z)
		}
		if len(z.ProbeKey) != 32 {
			res.Small = Step{State: Skip, Detail: "no probe key"}
			break
		}
		res.Small = c.probeVia(ctx, a, z, false, &res)
		if res.Small.State == OK {
			res.Large = c.probeVia(ctx, a, z, true, &res)
		}
	default:
		x, err := c.randomName(ctx, a, z, true)
		switch {
		case err != nil:
			if res.Small = failed(err, Fail, ""); res.Small.State == Fail {
				res.Small.Fix = reachFix
			}
		case x.r.RCode == dnsmessage.RCodeSuccess || x.r.RCode == dnsmessage.RCodeNameError:
			res.Small = Step{State: OK, Detail: rcodeText(x.r.RCode), RTT: x.rtt}
		default:
			res.Small = Step{State: Fail, Detail: rcodeText(x.r.RCode), Fix: reachFix}
		}
	}
	if r.WarnOnly {
		for _, s := range []*Step{&res.SOA, &res.Small, &res.Large} {
			if s.State == Fail {
				s.State = Warn
			}
		}
	}
	return res
}

// reachFix is what a resolver that does not reach the node calls for.
const reachFix = "UDP 53 of the node must be open to everyone: the provider's firewall"

// apexVia asks a resolver for the zone's SOA. It may come from a cache, so
// it proves nothing of the node now and never fails the zone.
func (c *Checker) apexVia(ctx context.Context, a *asker, z Zone) Step {
	q, err := newQuery(z.Name, dnsmessage.TypeSOA, true)
	if err != nil {
		return Step{State: Warn, Detail: err.Error()}
	}
	x, err := a.ask(ctx, q)
	if err != nil {
		return failed(err, Warn, "")
	}
	if x.r.RCode != dnsmessage.RCodeSuccess {
		return Step{State: Warn, Detail: rcodeText(x.r.RCode)}
	}
	owner, mname, ok := soaIn(x.r.answers)
	switch {
	case !ok || owner != canonical(z.Name):
		return Step{State: Warn, Detail: "no SOA at the apex (an old answer in its cache?)"}
	case mname != canonical(z.NS):
		return Step{State: Warn, Detail: "the SOA names " + mname + " (an old answer in its cache?)"}
	}
	return Step{State: OK, RTT: x.rtt}
}

// probeVia sends a probe through a resolver and reads what the node saw.
func (c *Checker) probeVia(ctx context.Context, a *asker, z Zone, large bool, res *ResolverResult) Step {
	ans, x, err := c.probe(ctx, a, z, large, true)
	if err == nil {
		res.EDNS, res.Mixed, res.Egress = ans.EDNS, ans.Mixed, ans.Egress
	}
	if !large {
		switch {
		case err == nil:
			return Step{State: OK, RTT: x.rtt}
		case x.r == nil:
			s := failed(err, Fail, "")
			if s.State == Fail {
				s.Fix = reachFix
			}
			return s
		case x.r.RCode == dnsmessage.RCodeServerFailure:
			return Step{State: Fail, Detail: "SERVFAIL: it does not reach the node", Fix: reachFix}
		case x.r.RCode == dnsmessage.RCodeRefused:
			return Step{State: Fail, Detail: "REFUSED: it does not serve the node"}
		case x.r.Truncated:
			return Step{State: Fail, Detail: "truncated (TC), and no answer over TCP"}
		}
		return Step{State: Fail, Detail: err.Error() + ": the answer is not the node's (the resolver answers for the zone itself?)"}
	}
	switch {
	case err == nil && ans.Large && x.tcp:
		return Step{State: Warn, Detail: "large answers come truncated over UDP, whole over TCP", RTT: x.rtt}
	case err == nil && ans.Large:
		return Step{State: OK, RTT: x.rtt}
	case err == nil && ans.EDNS == 0:
		return Step{State: Warn, Detail: "a small answer: it sends the node no EDNS; " + z.Kind + " runs slower there", RTT: x.rtt}
	case err == nil:
		return Step{State: Warn, Detail: fmt.Sprintf("a small answer: it advertises EDNS %d to the node; %s runs slower there", ans.EDNS, z.Kind), RTT: x.rtt}
	case x.r != nil && x.r.Truncated:
		return Step{State: Warn, Detail: "truncated (TC) over UDP: large answers need TCP there"}
	case x.r == nil:
		s := failed(err, Warn, "")
		if s.State == Warn {
			s.Detail = "large answers lost (" + err.Error() + "): " + z.Kind + " will hardly work there"
		}
		return s
	}
	return Step{State: Warn, Detail: "large probe: " + err.Error()}
}

// probe sends a probe of the zone and opens its answer; x.r is nil when
// none came. rd is set when the query goes through a resolver.
func (c *Checker) probe(ctx context.Context, a *asker, z Zone, large, rd bool) (ProbeAnswer, exchange, error) {
	p, err := NewProbe(z.ProbeKey, z.Name, large, c.now())
	if err != nil {
		return ProbeAnswer{}, exchange{}, err
	}
	name := p.Label() + "." + canonical(z.Name)
	q, err := newQuery(name, dnsmessage.TypeTXT, rd)
	if err != nil {
		return ProbeAnswer{}, exchange{}, err
	}
	x, err := a.ask(ctx, q)
	if err != nil {
		return ProbeAnswer{}, x, err
	}
	if x.r.RCode != dnsmessage.RCodeSuccess {
		return ProbeAnswer{}, x, errors.New(rcodeText(x.r.RCode))
	}
	if x.r.Truncated {
		return ProbeAnswer{}, x, errors.New("truncated (TC)")
	}
	data, ok := x.r.txt(name)
	if !ok {
		return ProbeAnswer{}, x, errors.New("NOERROR without TXT")
	}
	ans, err := p.Open(z.ProbeKey, data)
	if err != nil {
		return ans, x, fmt.Errorf("a TXT the node did not make (%w)", err)
	}
	return ans, x, nil
}

// randomName asks for TXT of a random name in the zone: masterdns has no
// probe, and any answer from the node is a sign of life.
func (c *Checker) randomName(ctx context.Context, a *asker, z Zone, rd bool) (exchange, error) {
	q, err := newQuery(randomLabel(20)+"."+canonical(z.Name), dnsmessage.TypeTXT, rd)
	if err != nil {
		return exchange{}, err
	}
	return a.ask(ctx, q)
}

// randomLabel is n random letters and digits.
func randomLabel(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// Err says why the zone fails, nil when it does not: only clear breakage.
// The delegation is missing or leads elsewhere, the front does not answer
// on the node, or no resolver that counts (not WarnOnly) got the small
// probe through. Everything else is a warning in Summary.
func (r ZoneResult) Err() error {
	var msgs []string
	if r.Parent.State == Fail {
		msgs = append(msgs, r.Parent.Detail)
	}
	if r.Front.State == Fail {
		msgs = append(msgs, "the front: "+r.Front.Detail)
	}
	if m := r.unreached(); m != "" {
		msgs = append(msgs, m)
	}
	if len(msgs) == 0 {
		return nil
	}
	return errors.New(strings.Join(msgs, "; "))
}

// unreached says why no resolver that counts reached the node; "" when one
// did, or none was asked.
func (r ZoneResult) unreached() string {
	var why []string
	closed := true
	for _, rr := range r.Resolvers {
		if rr.Resolver.WarnOnly || rr.Small.State == Skip {
			continue
		}
		if rr.Small.State == OK {
			return ""
		}
		why = append(why, rr.Resolver.String()+": "+rr.Small.Detail)
		closed = closed && rr.Small.Fix == reachFix
	}
	if len(why) == 0 {
		return ""
	}
	msg := "no resolver got the zone's answer from the node (" + strings.Join(why, "; ") + ")"
	if closed {
		msg += ": is UDP 53 open in the provider's firewall?"
	}
	return msg
}

// Summary is the zone in a line: the delegation, how many resolvers got
// through, large answers and EDNS sizes (dnstt), and the warnings.
func (r ZoneResult) Summary() string {
	var parts []string
	switch {
	case r.Delegated:
		parts = append(parts, "delegated")
	case r.Parent.State == Fail:
		parts = append(parts, "not delegated")
	case r.Parent.State == Warn:
		parts = append(parts, "delegation unknown")
	}
	asked, passed, large, largeAsked, minEDNS, maxEDNS := 0, 0, 0, 0, 0, 0
	for _, rr := range r.Resolvers {
		if rr.Small.State == Skip {
			continue
		}
		asked++
		if rr.Small.State != OK {
			continue
		}
		passed++
		if rr.Large.State != Skip {
			largeAsked++
		}
		if rr.Large.State == OK {
			large++
		}
		if e := rr.EDNS; e > 0 {
			if minEDNS == 0 || e < minEDNS {
				minEDNS = e
			}
			maxEDNS = max(maxEDNS, e)
		}
	}
	switch {
	case !r.Delegated:
		parts = append(parts, "resolvers not asked")
	case asked > 0:
		parts = append(parts, fmt.Sprintf("%d/%d resolvers", passed, asked))
		if largeAsked > 0 {
			parts = append(parts, fmt.Sprintf("large %d/%d", large, largeAsked))
		}
		if minEDNS == maxEDNS && minEDNS > 0 {
			parts = append(parts, fmt.Sprintf("EDNS %d", minEDNS))
		} else if minEDNS > 0 {
			parts = append(parts, fmt.Sprintf("EDNS %d–%d", minEDNS, maxEDNS))
		}
	case len(r.Resolvers) > 0:
		parts = append(parts, "resolvers: "+r.Resolvers[0].Small.Detail)
	}
	if r.Parent.State == Warn {
		parts = append(parts, "parent: "+r.Parent.Detail)
	}
	if r.Front.State == Warn {
		parts = append(parts, "front: "+r.Front.Detail)
	}
	if r.Backend.State == Warn {
		parts = append(parts, "backend: "+r.Backend.Detail)
	}
	return strings.Join(parts, "; ")
}

// State is the zone's: fail with Err, warn when a step warns, else ok.
func (r ZoneResult) State() State {
	if r.Err() != nil {
		return Fail
	}
	worst := OK
	for _, s := range []Step{r.Parent, r.Front, r.Backend} {
		worst = max(worst, s.State)
	}
	for _, rr := range r.Resolvers {
		for _, s := range []Step{rr.SOA, rr.Small, rr.Large} {
			worst = max(worst, min(s.State, Warn))
		}
	}
	return worst
}
