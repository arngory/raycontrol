package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/arngory/raycontrol/internal/certs"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// relayNamesEvery is how often the relays' names are checked without a
// change: a record made by hand, without a DNS provider, is found within
// it.
const relayNamesEvery = 5 * time.Minute

// relayNameLookup bounds one name's lookup.
const relayNameLookup = 10 * time.Second

// relayNameCheck keeps which relays' names clients may be given
// (spec/relay-names-v1.md §4, §5): those that resolve to the relay's
// address alone and the certificate of the service's site covers. Before
// its record answers, the wildcard gives a name the exit's address, and a
// client would knock at the exit with the relay's key, in vain. Without a
// DNS provider it also says which names the site's next certificate takes
// (ToOrder, §6), and why one is not in it yet.
type relayNameCheck struct {
	st *store.Store
	// lookup resolves a name ("ip4": relays are IPv4): the system's
	// resolver, a test's own.
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
	wake   chan struct{}
	// acmeForward reports a relay whose rayspa forwards TCP 80 for the
	// ACME windows (api.Server.RelayACMEForward); nil: none does.
	acmeForward func(relay string) bool
	// ordering: rayd orders the sites' certificates (-acme-directory).
	// resolved, if set, runs when a name the certificate does not cover
	// yet comes to resolve to its relay: the manager may order it now.
	ordering bool
	resolved func()

	mu     sync.Mutex
	state  map[string]relayNameState // by name, of the last check
	orders map[string]error          // the last order's outcome for a name (certs.Manager.RelayReport)
}

// relayNameState is a name as the last check found it: ready, or why not;
// resolves: to its relay alone.
type relayNameState struct {
	ready    bool
	resolves bool
	problem  string
}

func newRelayNameCheck(st *store.Store, lookup func(context.Context, string, string) ([]netip.Addr, error)) *relayNameCheck {
	return &relayNameCheck{st: st, lookup: lookup, wake: make(chan struct{}, 1)}
}

// Ready reports whether clients may be given a relay's name
// (sub.Server.RelayNameReady).
func (c *relayNameCheck) Ready(name string) bool {
	ready, _ := c.Status(name)
	return ready
}

// Status is whether a relay's name is ready and, if not, why
// (api.Server.RelayNameStatus).
func (c *relayNameCheck) Status(name string) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.state[provision.CanonicalZone(name)]
	if !ok {
		return false, "not checked yet"
	}
	return s.ready, s.problem
}

// Wake has the names checked again now: the DNS sync changed records.
func (c *relayNameCheck) Wake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Ordered takes an order's outcome for the relays' names it had
// (certs.Manager.RelayReport): its error says why they are not ready.
func (c *relayNameCheck) Ordered(_ string, names []string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.orders == nil {
		c.orders = map[string]error{}
	}
	for _, n := range names {
		c.orders[n] = err
	}
}

// ToOrder are the relays' names a site's next certificate takes
// (certs.Manager.RelayNames, §5, §6): without a DNS provider, those of
// relays whose rayspa forwards TCP 80 for the window and that resolved to
// their relay alone at the last check; by relay, then service.
func (c *relayNameCheck) ToOrder(ctx context.Context, site string) []string {
	if cf, _, err := provision.Cloudflare(ctx, c.st); err != nil || cf != nil {
		return nil
	}
	names, err := provision.RelayNames(ctx, c.st)
	if err != nil {
		return nil
	}
	all, err := c.st.ListServices(ctx)
	if err != nil {
		return nil
	}
	var out []string
	for _, rn := range names {
		i := slices.IndexFunc(all, func(s store.Service) bool { return s.ID == rn.Service })
		if i < 0 || provision.SiteOf(all[i]) != site || c.acmeForward == nil || !c.acmeForward(rn.Relay) {
			continue
		}
		c.mu.Lock()
		resolves := c.state[rn.Name].resolves
		c.mu.Unlock()
		if resolves {
			out = append(out, rn.Name)
		}
	}
	return out
}

// run checks the names at its start, after each change and every
// relayNamesEvery. No name nor address goes in the log: rayctl relay list
// shows them.
func (c *relayNameCheck) run(ctx context.Context, changes func() <-chan struct{}, log *slog.Logger) {
	for {
		wake := changes()
		if err := c.check(ctx); err != nil && ctx.Err() == nil {
			log.Warn("relay names not checked", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-c.wake:
		case <-time.After(relayNamesEvery):
		}
	}
}

// check looks at every relay's name once. A name that leaves the list
// (its relay or service gone) leaves the state with it.
func (c *relayNameCheck) check(ctx context.Context) error {
	names, err := provision.RelayNames(ctx, c.st)
	if err != nil {
		return err
	}
	all, err := c.st.ListServices(ctx)
	if err != nil {
		return err
	}
	cf, _, err := provision.Cloudflare(ctx, c.st)
	if err != nil {
		return err
	}
	state := make(map[string]relayNameState, len(names))
	for _, rn := range names {
		state[rn.Name] = c.one(ctx, rn, all, cf != nil)
	}
	c.mu.Lock()
	before := c.state
	c.state = state
	for n := range c.orders {
		if _, ok := state[n]; !ok {
			delete(c.orders, n)
		}
	}
	c.mu.Unlock()
	// A name that came to resolve and waits for the certificate: the
	// manager may order it now, not at its next hourly check.
	for n, s := range state {
		if s.resolves && !s.ready && !before[n].resolves && c.resolved != nil {
			c.resolved()
			break
		}
	}
	return nil
}

// one checks a name: what it resolves to, then the certificate; cf: the
// node has a DNS provider (and so a wildcard certificate, §5).
func (c *relayNameCheck) one(ctx context.Context, rn provision.RelayName, all []store.Service, cf bool) relayNameState {
	i := slices.IndexFunc(all, func(s store.Service) bool { return s.ID == rn.Service })
	if i < 0 {
		return relayNameState{problem: "its service is gone"}
	}
	if problem := c.resolves(ctx, rn); problem != "" {
		return relayNameState{problem: problem}
	}
	site := provision.SiteOf(all[i])
	if provision.SiteCovers(ctx, c.st, all, site, rn.Name) {
		return relayNameState{ready: true, resolves: true}
	}
	j := slices.IndexFunc(all, func(s store.Service) bool { return s.Kind == "site" && s.Name == site })
	c.mu.Lock()
	order, ordered := c.orders[rn.Name]
	c.mu.Unlock()
	var problem string
	switch {
	case cf:
		problem = "the certificate of " + site + " does not cover it: with a DNS provider it is a wildcard once every name of the site " +
			"is under the domain"
	case j >= 0 && provision.ParseSiteKeyState(all[j]).Imported:
		problem = "the certificate of " + site + " is the operator's own (rayctl service cert) and does not cover it; the next one the " +
			"node orders for the site takes it"
	case !c.ordering:
		problem = "the certificate of " + site + " does not cover it, and this node orders none (-acme-directory is empty): " +
			"import one that does (rayctl service cert)"
	case c.acmeForward == nil || !c.acmeForward(rn.Relay):
		problem = "the relay's rayspa does not forward TCP 80 for the certificate's order (a relay before v0.35.0, or its feed not " +
			"open since this node started): update the relay (rayctl update here takes the relays along)"
	case ordered && errors.Is(order, certs.ErrTooManyNames):
		problem = "left out of the certificate of " + site + ": " + order.Error()
	case ordered && order != nil:
		problem = "the order of the certificate of " + site + " with it failed: " + order.Error()
	default:
		problem = "waiting for the certificate of " + site + " with it"
	}
	return relayNameState{resolves: true, problem: problem}
}

// resolves says why a name does not resolve to its relay alone, "" when
// it does.
func (c *relayNameCheck) resolves(ctx context.Context, rn provision.RelayName) string {
	lctx, cancel := context.WithTimeout(ctx, relayNameLookup)
	defer cancel()
	addrs, err := c.lookup(lctx, "ip4", rn.Name)
	if err != nil {
		return "does not resolve: " + err.Error()
	}
	if len(addrs) == 0 {
		return "resolves to no IPv4 address"
	}
	var got []string
	alone := true
	for _, a := range addrs {
		got = append(got, a.Unmap().String())
		alone = alone && a.Unmap() == rn.Address
	}
	if !alone {
		return fmt.Sprintf("resolves to %s, not to the relay's %s alone (the record is not in yet, or not alone)",
			strings.Join(got, ", "), rn.Address)
	}
	return ""
}
