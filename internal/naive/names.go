package naive

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
const (
	nameHit   = time.Minute
	nameMiss  = 30 * time.Second
	nameCache = 8192 // names kept at most
)

type names struct {
	mu sync.Mutex
	m  map[string]cachedName
}

type cachedName struct {
	addrs []netip.Addr // none: a name that does not exist, or has no address
	until time.Time
}

// errNoName is a name the cache knows does not resolve.
var errNoName = &net.DNSError{Err: "no such host (cached)", IsNotFound: true}

// get is the cached answer for a name: its addresses, or errNoName; ok
// false when the cache does not know it.
func (c *names) get(name string, now time.Time) ([]netip.Addr, error, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[name]
	if !ok || !now.Before(e.until) {
		return nil, nil, false
	}
	if len(e.addrs) == 0 {
		return nil, errNoName, true
	}
	return e.addrs, nil, true
}

// put keeps an answer, or a miss that says the name does not resolve.
func (c *names) put(name string, addrs []netip.Addr, err error, now time.Time) {
	var e cachedName
	var dnsErr *net.DNSError
	switch {
	case err == nil && len(addrs) > 0:
		e = cachedName{addrs: addrs, until: now.Add(nameHit)}
	case err == nil, errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		e = cachedName{until: now.Add(nameMiss)}
	default:
		return // a timeout, SERVFAIL, a refusal: not kept
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]cachedName{}
	}
	if _, ok := c.m[name]; !ok && len(c.m) >= nameCache {
		for k, v := range c.m {
			if !now.Before(v.until) {
				delete(c.m, k)
			}
		}
		for k := range c.m {
			if len(c.m) < nameCache {
				break
			}
			delete(c.m, k) // any: a random one by Go's map order
		}
	}
	c.m[name] = e
}

// lookupName gives a name's addresses through the cache. A miss of the
// cache pays a lookup token of the user's, unless paid already (TCP pays
// before the 200, to answer 429): none left, no lookup.
func (s *Server) lookupName(ctx context.Context, user, name string, paid bool) ([]netip.Addr, error) {
	now := s.lim.clock()
	if addrs, err, ok := s.names.get(name, now); ok {
		return addrs, err
	}
	if !paid && !s.lim.lookup(user) {
		return nil, errors.New("naive: too many lookups")
	}
	addrs, err := s.resolve(ctx, name)
	s.names.put(name, addrs, err, s.lim.clock())
	return addrs, err
}

// cached reports whether the cache knows a name now (TCP's check before
// the 200).
func (s *Server) cached(name string) bool {
	_, _, ok := s.names.get(name, s.lim.clock())
	return ok
}
