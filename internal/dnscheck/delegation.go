package dnscheck

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// The delegation of a zone, as its parent's own servers give it: the zone
// cut above the zone and the parent's servers come through the host's
// resolver, then each of those servers (at most four) is asked for the
// zone's NS with RD=0, past every cache. Resolvers are told what they say.
const maxParentServers = 4

// round is one check's shared lookups: the host's resolvers, the parents
// and the node's addresses, each looked up once.
type round struct {
	c       *Checker
	system  []netip.AddrPort
	sysErr  error
	mu      sync.Mutex
	parents map[string]*lookup[parentZone]
	hosts   map[string]*lookup[[]netip.Addr]
}

// lookup is a value found once, whoever asks first.
type lookup[T any] struct {
	once sync.Once
	v    T
	err  error
}

func cached[T any](rd *round, m map[string]*lookup[T], key string, f func() (T, error)) (T, error) {
	rd.mu.Lock()
	l := m[key]
	if l == nil {
		l = &lookup[T]{}
		m[key] = l
	}
	rd.mu.Unlock()
	l.once.Do(func() { l.v, l.err = f() })
	return l.v, l.err
}

// parentZone is the zone cut above a zone and the servers asked for it.
type parentZone struct {
	name    string
	servers []parentServer
}

type parentServer struct {
	name string
	addr netip.AddrPort
}

// recursive asks the host's resolvers in turn, until one answers with
// NOERROR or NXDOMAIN.
func (rd *round) recursive(ctx context.Context, name string, t dnsmessage.Type) (*reply, error) {
	if rd.sysErr != nil {
		return nil, rd.sysErr
	}
	q, err := newQuery(name, t, true)
	if err != nil {
		return nil, err
	}
	last := fmt.Errorf("no resolver of the host")
	for _, s := range rd.system[:min(len(rd.system), 3)] {
		a := rd.c.asker("udp", s, 2)
		x, err := a.ask(ctx, q)
		switch {
		case err != nil:
			last = fmt.Errorf("%s: %w", s.Addr(), err)
		case x.r.RCode == dnsmessage.RCodeSuccess || x.r.RCode == dnsmessage.RCodeNameError:
			return x.r, nil
		default:
			last = fmt.Errorf("%s: %s", s.Addr(), rcodeText(x.r.RCode))
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// node is the addresses the delegation must lead to: the host's, looked up
// when it is a name.
func (rd *round) node(ctx context.Context, host string) []netip.Addr {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}
	}
	if host == "" {
		return nil
	}
	addrs, _ := cached(rd, rd.hosts, host, func() ([]netip.Addr, error) {
		var out []netip.Addr
		for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			if r, err := rd.recursive(ctx, host, t); err == nil {
				out = append(out, addrsIn(r.answers, canonical(host))...)
			}
		}
		return out, nil
	})
	return addrs
}

// parent finds the zone cut above zone (the owner of the SOA that answers
// for the name above it) and up to four of its servers, with an address of
// the node's family.
func (rd *round) parent(ctx context.Context, zone string, v6 bool) (parentZone, error) {
	above := parentName(zone)
	return cached(rd, rd.parents, above, func() (parentZone, error) {
		r, err := rd.recursive(ctx, above, dnsmessage.TypeSOA)
		if err != nil {
			return parentZone{}, fmt.Errorf("SOA %s through the host's resolver: %w", above, err)
		}
		owner, _, ok := soaIn(r.answers)
		if !ok {
			owner, _, ok = soaIn(r.authorities)
		}
		if !ok || owner == "" || (owner != above && !strings.HasSuffix(above, "."+owner)) {
			return parentZone{}, fmt.Errorf("no SOA above %s through the host's resolver", zone)
		}
		p := parentZone{name: owner}
		if r, err = rd.recursive(ctx, owner, dnsmessage.TypeNS); err != nil {
			return p, fmt.Errorf("NS %s through the host's resolver: %w", owner, err)
		}
		names, _ := nsIn(r.answers, owner)
		slices.Sort(names)
		for _, n := range names {
			if len(p.servers) == maxParentServers {
				break
			}
			addrs := family(addrsIn(r.additionals, n), v6)
			if len(addrs) == 0 {
				t := dnsmessage.TypeA
				if v6 {
					t = dnsmessage.TypeAAAA
				}
				if ar, err := rd.recursive(ctx, n, t); err == nil {
					addrs = family(addrsIn(ar.answers, n), v6)
				}
			}
			if len(addrs) > 0 {
				p.servers = append(p.servers, parentServer{name: n, addr: netip.AddrPortFrom(addrs[0], 53)})
			}
		}
		if len(p.servers) == 0 {
			return p, fmt.Errorf("no server of %s with an address", owner)
		}
		return p, nil
	})
}

// parentAnswer is what one server of the parent says of the zone.
type parentAnswer struct {
	server parentServer
	err    error            // no answer
	rcode  dnsmessage.RCode // NOERROR or NXDOMAIN when it answered
	ns     []string         // the names it delegates the zone to
	ttl    uint32
	glue   map[string][]netip.Addr
}

// delegation asks the parent's servers for the zone and says what they
// give: the step, and whether the zone leads to the node, so that
// resolvers may be asked.
func (rd *round) delegation(ctx context.Context, z Zone, node []netip.Addr) (Step, bool) {
	v6 := len(node) > 0 && !node[0].Is4()
	p, err := rd.parent(ctx, z.Name, v6)
	if err != nil {
		if ctx.Err() != nil {
			return Step{State: Skip, Detail: errRoundOver.Error()}, false
		}
		return Step{State: Warn, Detail: "not found: " + err.Error(),
			Fix: "rayctl status: resolver; the node asks the parent through its own resolver"}, false
	}
	answers := make([]parentAnswer, len(p.servers))
	var wg sync.WaitGroup
	for i, s := range p.servers {
		wg.Go(func() { answers[i] = rd.askParent(ctx, s, z.Name) })
	}
	wg.Wait()

	var answered, delegating []parentAnswer
	absent := ""
	for _, a := range answers {
		if a.err != nil {
			continue
		}
		answered = append(answered, a)
		switch {
		case len(a.ns) > 0:
			delegating = append(delegating, a)
		case a.rcode == dnsmessage.RCodeNameError:
			absent = "NXDOMAIN"
		default:
			absent = "no NS"
		}
	}
	servers := fmt.Sprintf("%s (%d %s)", p.name, len(p.servers), plural(len(p.servers), "server", "servers"))
	fix := "rayctl dns sync, or the NS and A records of rayctl dns at the zone's DNS provider"
	switch {
	case len(answered) == 0:
		if ctx.Err() != nil {
			return Step{State: Skip, Detail: errRoundOver.Error()}, false
		}
		return Step{State: Warn, Detail: fmt.Sprintf("%s did not answer the node: %v", servers, answers[0].err),
			Fix: "outbound UDP 53 of the node blocked? Then resolvers are not asked either"}, false
	case len(delegating) == 0 && absent == "NXDOMAIN":
		return Step{State: Fail, Detail: fmt.Sprintf("%s says %s does not exist (NXDOMAIN): no delegation", servers, z.Name), Fix: fix}, false
	case len(delegating) == 0:
		return Step{State: Fail, Detail: fmt.Sprintf("%s has no NS for %s: the wildcard *.%s answers it instead", servers, z.Name, p.name), Fix: fix}, false
	case len(delegating) < len(answered):
		return Step{State: Fail, Detail: fmt.Sprintf("only %d of %d servers of %s delegate %s", len(delegating), len(answered), p.name, z.Name),
			Fix: "a new delegation reaches every server of the parent within minutes; if not, " + fix}, false
	}

	// The names, from every server; their addresses: glue, else the
	// parent's own record (a name in its zone) or the host's resolver.
	var names []string
	glue := map[string][]netip.Addr{}
	ttl := uint32(0)
	for _, a := range delegating {
		for _, n := range a.ns {
			if !contains(names, n) {
				names = append(names, n)
			}
			for _, g := range a.glue[n] {
				if !contains(glue[n], g) {
					glue[n] = append(glue[n], g)
				}
			}
		}
		if ttl == 0 || a.ttl < ttl {
			ttl = a.ttl
		}
	}
	slices.Sort(names)
	addrs := map[string][]netip.Addr{}
	glued := true
	for _, n := range names {
		if len(glue[n]) > 0 {
			addrs[n] = glue[n]
			continue
		}
		glued = false
		addrs[n] = rd.nsAddrs(ctx, delegating[0].server, p.name, n)
	}

	to := strings.Join(names, ", ")
	if len(node) == 0 {
		return Step{State: Warn, Detail: fmt.Sprintf("%s delegates %s to %s (%s); the node's own address is not known", servers, z.Name, to, addrList(names, addrs))}, true
	}
	var stray []string
	for _, n := range names {
		if !slices.ContainsFunc(addrs[n], func(a netip.Addr) bool { return slices.Contains(node, a.Unmap()) }) {
			stray = append(stray, n)
		}
	}
	if len(stray) > 0 {
		at := addrList(stray, addrs)
		if len(at) == 0 {
			at = "no address"
		}
		return Step{State: Fail, Detail: fmt.Sprintf("the parent delegates %s to %s at %s, the node is %s", z.Name, strings.Join(stray, ", "), at, node[0]),
			Fix: fix + " (after rayctl restore -host, the records still lead to the old host)"}, false
	}
	kind := "glue"
	if !glued {
		kind = "address"
	}
	detail := fmt.Sprintf("%s delegates to %s, %s %s = node, TTL %d", servers, to, kind, node[0], ttl)
	if missing := len(p.servers) - len(answered); missing > 0 {
		detail += fmt.Sprintf("; %d of %d servers did not answer", missing, len(p.servers))
	}
	if z.NS != "" && !contains(names, canonical(z.NS)) {
		return Step{State: Warn, Detail: detail + "; the front names " + z.NS + " at the apex",
			Fix: "the parent and the front should name the same server: " + fix}, true
	}
	if len(answered) < len(p.servers) {
		return Step{State: Warn, Detail: detail}, true
	}
	return Step{State: OK, Detail: detail}, true
}

// askParent asks one server of the parent for the zone's NS, without
// recursion.
func (rd *round) askParent(ctx context.Context, s parentServer, zone string) parentAnswer {
	out := parentAnswer{server: s}
	q, err := newQuery(zone, dnsmessage.TypeNS, false)
	if err != nil {
		out.err = err
		return out
	}
	a := rd.c.asker("udp", s.addr, 2)
	x, err := a.ask(ctx, q)
	if err != nil {
		out.err = err
		return out
	}
	switch x.r.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	default:
		out.err = fmt.Errorf("%s", rcodeText(x.r.RCode))
		return out
	}
	out.rcode = x.r.RCode
	// A referral: NS in the authority section; a parent that serves the
	// zone itself: in the answer.
	if out.ns, out.ttl = nsIn(x.r.authorities, zone); len(out.ns) == 0 {
		out.ns, out.ttl = nsIn(x.r.answers, zone)
	}
	out.glue = map[string][]netip.Addr{}
	for _, n := range out.ns {
		out.glue[n] = addrsIn(x.r.additionals, n)
	}
	return out
}

// nsAddrs finds the address of a name the zone is delegated to without
// glue: from the parent's server for a name in its zone, else through the
// host's resolver.
func (rd *round) nsAddrs(ctx context.Context, s parentServer, parent, name string) []netip.Addr {
	var out []netip.Addr
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		if name == parent || strings.HasSuffix(name, "."+parent) {
			q, err := newQuery(name, t, false)
			if err != nil {
				continue
			}
			a := rd.c.asker("udp", s.addr, 1)
			if x, err := a.ask(ctx, q); err == nil {
				out = append(out, addrsIn(x.r.answers, name)...)
			}
		} else if r, err := rd.recursive(ctx, name, t); err == nil {
			out = append(out, addrsIn(r.answers, name)...)
		}
	}
	return out
}

// parentName is the name above zone.
func parentName(zone string) string {
	_, rest, _ := strings.Cut(canonical(zone), ".")
	return rest
}

// family keeps the addresses of one family.
func family(addrs []netip.Addr, v6 bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if a.Unmap().Is4() != v6 {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// addrList shows the addresses of names: "198.51.100.9" or, for several
// names, "n1 198.51.100.9, n2 …".
func addrList(names []string, addrs map[string][]netip.Addr) string {
	var parts []string
	for _, n := range names {
		var as []string
		for _, a := range addrs[n] {
			as = append(as, a.String())
		}
		if len(as) == 0 {
			continue
		}
		if len(names) == 1 {
			return strings.Join(as, " ")
		}
		parts = append(parts, n+" "+strings.Join(as, " "))
	}
	return strings.Join(parts, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// rcodeText is an RCODE as DNS tools show it.
func rcodeText(rc dnsmessage.RCode) string {
	switch rc {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE %d", rc)
}
