package naive

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// The process's cache of names (spec/conn-limit-v1.md §2), before the public
// resolvers, for TCP's destinations and UoT's alike: an answer for
// nameHit, and for nameMiss only a name that does not exist or has no
// address (NXDOMAIN, NODATA: DNSError.IsNotFound). A timeout, SERVFAIL or
// the guard's refusal is not kept: in a cache all users share, one failed
// try would close the name to every one of them. Without it every CONNECT
// by name is two queries (A and AAAA) from new sockets: two conntrack
// entries of 30 s.
//
// Its memory is bounded: only a domain name (253 bytes at most) is looked
// up or kept, an answer keeps nameAddrs addresses at most, and the cache
// nameCache names. Entries wait in two queues in the order they expire
// (each kind has one lifetime): what expired goes at the next answer kept,
// and when the cache is full what expires first goes, without walking the
// whole cache.
const (
	nameHit   = time.Minute
	nameMiss  = 30 * time.Second
	nameCache = 8192 // names kept at most
	nameAddrs = 16   // addresses an answer keeps
	nameMax   = 253  // a domain name's bytes, without the final dot
)

type names struct {
	mu sync.Mutex
	m  map[string]cachedName
	// The entries in the order they expire, answers and misses apart; one
	// replaced since is passed over when its turn comes.
	hits, misses expiries
}

type cachedName struct {
	addrs []netip.Addr // none: a name that does not exist, or has no address
	until time.Time
}

// errNoName is a name the cache knows does not resolve.
var errNoName = &net.DNSError{Err: "no such host (cached)", IsNotFound: true}

// errBadName is a host that is no domain name: refused before the cache,
// the user's token and the resolvers.
var errBadName = &net.DNSError{Err: "not a domain name", IsNotFound: true}

// domainName reports whether host is a name the resolvers may be asked:
// 253 bytes at most without the final dot, labels of 1 to 63 letters,
// digits, '-' and '_' (no '-' first or last), not all digits, as Go's
// resolver has them. Go answers anything else "no such host" without
// asking; the cache must not keep it.
func domainName(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > nameMax {
		return false
	}
	last := byte('.')
	nonNumeric := false
	label := 0
	for i := range len(host) {
		c := host[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', c == '_':
			nonNumeric = true
			label++
		case '0' <= c && c <= '9':
			label++
		case c == '-':
			if last == '.' {
				return false
			}
			nonNumeric = true
			label++
		case c == '.':
			if last == '.' || last == '-' || label > 63 {
				return false
			}
			label = 0
		default:
			return false
		}
		last = c
	}
	return last != '-' && label <= 63 && nonNumeric
}

// get is the cached answer for a name: its addresses, or errNoName, and
// when it expires; ok false when the cache does not know it.
func (c *names) get(name string, now time.Time) (addrs []netip.Addr, until time.Time, err error, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getLocked(name, now)
}

func (c *names) getLocked(name string, now time.Time) (addrs []netip.Addr, until time.Time, err error, ok bool) {
	e, ok := c.m[name]
	if !ok || !now.Before(e.until) {
		return nil, time.Time{}, nil, false
	}
	if len(e.addrs) == 0 {
		return nil, e.until, errNoName, true
	}
	return e.addrs, e.until, nil, true
}

// put keeps an answer, or a miss that says the name does not resolve, and
// says until when (zero: not kept).
func (c *names) put(name string, addrs []netip.Addr, err error, now time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.putLocked(name, addrs, err, now)
}

func (c *names) putLocked(name string, addrs []netip.Addr, err error, now time.Time) time.Time {
	var e cachedName
	var dnsErr *net.DNSError
	q := &c.hits
	switch {
	case err == nil && len(addrs) > 0:
		e = cachedName{addrs: slices.Clone(addrs[:min(len(addrs), nameAddrs)]), until: now.Add(nameHit)}
	case err == nil, errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		e = cachedName{until: now.Add(nameMiss)}
		q = &c.misses
	default:
		return time.Time{} // a timeout, SERVFAIL, a refusal: not kept
	}
	if c.m == nil {
		c.m = map[string]cachedName{}
	}
	// What expired goes; full, what expires first.
	expired := func(x expiry) bool { return !now.Before(x.until) }
	c.hits.drop(c.m, expired)
	c.misses.drop(c.m, expired)
	if _, ok := c.m[name]; !ok {
		for len(c.m) >= nameCache {
			h, hok := c.hits.front()
			m, mok := c.misses.front()
			switch {
			case hok && (!mok || h.until.Before(m.until)):
				c.hits.drop(c.m, nil)
			case mok:
				c.misses.drop(c.m, nil)
			default:
				clear(c.m) // never: every entry is in a queue
			}
		}
	}
	c.m[name] = e
	q.push(expiry{name, e.until})
	return e.until
}

// expiries is a queue of cache entries in the order they expire.
type expiries struct {
	q    []expiry
	head int
}

type expiry struct {
	name  string
	until time.Time
}

func (x *expiries) push(e expiry) { x.q = append(x.q, e) }

func (x *expiries) front() (expiry, bool) {
	if x.head == len(x.q) {
		return expiry{}, false
	}
	return x.q[x.head], true
}

// drop takes entries off the front while gone holds for the front one, and
// each out of the cache unless it was replaced since; with gone nil, until
// one has left the cache.
func (x *expiries) drop(m map[string]cachedName, gone func(expiry) bool) {
	for x.head < len(x.q) {
		e := x.q[x.head]
		if gone != nil && !gone(e) {
			return
		}
		x.q[x.head] = expiry{}
		x.head++
		removed := false
		if v, ok := m[e.name]; ok && v.until.Equal(e.until) {
			delete(m, e.name)
			removed = true
		}
		if x.head == len(x.q) {
			x.q, x.head = x.q[:0], 0
		} else if x.head >= 1024 && x.head > len(x.q)/2 {
			n := copy(x.q, x.q[x.head:])
			clear(x.q[n:])
			x.q, x.head = x.q[:n], 0
		}
		if gone == nil && removed {
			return
		}
	}
}

// lookupName gives a name's addresses through the cache. A miss of the
// cache pays a lookup token of the user's, unless paid already (TCP pays
// before the 200, to answer 429): none left, no lookup. A host that is no
// domain name is refused before either.
func (s *Server) lookupName(ctx context.Context, user, name string, paid bool) ([]netip.Addr, error) {
	if !domainName(name) {
		return nil, errBadName
	}
	now := s.lim.clock()
	if addrs, _, err, ok := s.names.get(name, now); ok {
		return addrs, err
	}
	if !paid && !s.lim.lookup(user) {
		return nil, errors.New("naive: too many lookups")
	}
	addrs, err := s.resolve(ctx, name)
	s.names.put(name, addrs, err, s.lim.clock())
	return addrs[:min(len(addrs), nameAddrs)], err
}

// cached reports whether the cache knows a name now (TCP's check before
// the 200).
func (s *Server) cached(name string) bool {
	_, _, _, ok := s.names.get(name, s.lim.clock())
	return ok
}
