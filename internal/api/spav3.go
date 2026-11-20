package api

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/arngory/raycontrol/internal/node"
)

// nodeSPA is the node's SPA parameters as a bundle hands them out, with
// the versions it takes (spa-v3 §5).
func (s *Server) nodeSPA(ctx context.Context) node.SPAParams {
	sp := node.FromParams(s.Params)
	sp.Versions = s.SPAVersions(ctx)
	return sp
}

// SPAVersions are the SPA versions the node offers its clients (spa-v3
// §5): v3 only where a v3 packet to the node's public address can pass,
// that is with -host an address, or a name the node's resolver gives a
// public address for. Behind 1:1 NAT with split-horizon DNS (a cloud's own
// names resolve to the private address inside it) the node knows no public
// address, a v3 packet to it would be refused, and a client given only a
// name has no address to fall back to with v2: no v3 then, as before it.
// nil means [2].
func (s *Server) SPAVersions(ctx context.Context) []int {
	host, err := node.Host(ctx, s.Store)
	if err != nil {
		return nil
	}
	for _, a := range s.own.get(ctx, host, time.Now()) {
		if ip, err := netip.ParseAddr(a); err == nil && publicAddr(ip) {
			return slices.Clone(node.SPAVersions)
		}
	}
	return nil
}

// cgnat is the shared address space of carriers (RFC 6598): private too.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicAddr reports whether a is a public unicast address.
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

// usableOwn reports whether a may be an own address at all: none a client
// could be sent to that the node would take (loopback, as a hostname in
// /etc/hosts gives; link-local; multicast; unspecified).
func usableOwn(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsMulticast() &&
		!a.IsLinkLocalMulticast() && !a.IsInterfaceLocalMulticast()
}

// Own addresses of the node (spa-v3 §4): a v3 packet that names one of
// them opens, from wherever it came. With -host an address, that address;
// with -host a name, what the node's resolver gives for it, for a node
// behind 1:1 NAT whose packets come to a private address.
const (
	ownAddrsTTL   = 10 * time.Minute
	ownAddrsRetry = time.Minute
	ownAddrsWait  = 2 * time.Second
	ownAddrsMax   = 16 // the snapshot's bound (perimeter.maxOwnAddrs)
)

type ownAddrs struct {
	mu      sync.Mutex
	host    string
	addrs   []string
	next    time.Time // when to resolve again
	running bool
}

// ownLookup resolves -host; tests replace it.
var ownLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// get returns the node's own addresses for host. A name is resolved at
// its first use (for at most ownAddrsWait), then again in the background
// every ownAddrsTTL; a lookup that fails keeps what the last one gave.
func (o *ownAddrs) get(ctx context.Context, host string, now time.Time) []string {
	if a, err := netip.ParseAddr(host); err == nil {
		if a = a.Unmap().WithZone(""); !usableOwn(a) {
			return nil // rayd init -host 0.0.0.0: no address of the node at all
		}
		return []string{a.String()}
	}
	if host == "" {
		return nil
	}
	o.mu.Lock()
	if o.host != host {
		o.host, o.addrs, o.next = host, nil, time.Time{}
	}
	first := o.next.IsZero()
	stale := !o.running && !now.Before(o.next)
	if stale {
		o.running = true
	}
	o.mu.Unlock()
	if stale {
		if first {
			rctx, cancel := context.WithTimeout(ctx, ownAddrsWait)
			o.resolve(rctx, host, now)
			cancel()
		} else {
			// Past the snapshot that asked: the next one takes the result.
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			go func() {
				defer cancel()
				o.resolve(rctx, host, now)
			}()
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.addrs)
}

func (o *ownAddrs) resolve(ctx context.Context, host string, now time.Time) {
	got, err := ownLookup(ctx, host)
	var addrs []string
	for _, a := range got {
		if a = a.Unmap().WithZone(""); !usableOwn(a) {
			continue
		}
		if s := a.String(); !slices.Contains(addrs, s) && len(addrs) < ownAddrsMax {
			addrs = append(addrs, s)
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.running = false
	if o.host != host {
		return // -host changed meanwhile
	}
	if err != nil || len(addrs) == 0 {
		o.next = now.Add(ownAddrsRetry)
		return
	}
	slices.Sort(addrs)
	o.addrs, o.next = addrs, now.Add(ownAddrsTTL)
}

// relaySPA records the SPA versions a relay's rayspa said it takes when
// its feed opened (spa-v3 §5); the last word stays after it closed.
func (r *Remote) setRelaySPA(name string, versions []uint32) {
	var vs []int
	for _, v := range versions {
		if slices.Contains(node.SPAVersions, int(v)) && !slices.Contains(vs, int(v)) {
			vs = append(vs, int(v))
		}
	}
	slices.Sort(vs)
	r.relayMu.Lock()
	defer r.relayMu.Unlock()
	if r.relaySPA == nil {
		r.relaySPA = map[string][]int{}
	}
	r.relaySPA[name] = vs
}

// RelaySPA gives the SPA versions a relay's rayspa takes, nil until it
// said (since this node started) or when it took only v2 then: the
// subscription's relays[].spa.versions.
func (r *Remote) RelaySPA(name string) []int {
	r.relayMu.Lock()
	defer r.relayMu.Unlock()
	if vs := r.relaySPA[name]; slices.Contains(vs, 3) {
		return slices.Clone(vs)
	}
	return nil
}
