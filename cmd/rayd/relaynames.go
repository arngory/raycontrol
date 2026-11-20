package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

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
// (spec/relay-names-v1.md §4, §5): those the certificate of the service's
// site covers and that resolve to the relay's address alone. Before its
// record answers, the wildcard gives a name the exit's address, and a
// client would knock at the exit with the relay's key, in vain.
type relayNameCheck struct {
	st *store.Store
	// lookup resolves a name ("ip4": relays are IPv4): the system's
	// resolver, a test's own.
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
	wake   chan struct{}

	mu    sync.Mutex
	state map[string]relayNameState // by name, of the last check
}

// relayNameState is a name as the last check found it: ready, or why not.
type relayNameState struct {
	ready   bool
	problem string
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
	state := make(map[string]relayNameState, len(names))
	for _, rn := range names {
		state[rn.Name] = c.one(ctx, rn, all)
	}
	c.mu.Lock()
	c.state = state
	c.mu.Unlock()
	return nil
}

// one checks a name: the certificate first (stage 1: a wildcard, with a
// DNS provider; §5), then what the name resolves to.
func (c *relayNameCheck) one(ctx context.Context, rn provision.RelayName, all []store.Service) relayNameState {
	i := slices.IndexFunc(all, func(s store.Service) bool { return s.ID == rn.Service })
	if i < 0 {
		return relayNameState{problem: "its service is gone"}
	}
	site := provision.SiteOf(all[i])
	if !provision.SiteCovers(ctx, c.st, all, site, rn.Name) {
		return relayNameState{problem: "the certificate of " + site + " does not cover it (with a DNS provider, rayctl dns cloudflare, " +
			"the site's wildcard certificate does)"}
	}
	lctx, cancel := context.WithTimeout(ctx, relayNameLookup)
	defer cancel()
	addrs, err := c.lookup(lctx, "ip4", rn.Name)
	if err != nil {
		return relayNameState{problem: "does not resolve: " + err.Error()}
	}
	if len(addrs) == 0 {
		return relayNameState{problem: "resolves to no IPv4 address"}
	}
	var got []string
	ready := true
	for _, a := range addrs {
		got = append(got, a.Unmap().String())
		ready = ready && a.Unmap() == rn.Address
	}
	if !ready {
		return relayNameState{problem: fmt.Sprintf("resolves to %s, not to the relay's %s alone (the record is not in yet, or not alone)",
			strings.Join(got, ", "), rn.Address)}
	}
	return relayNameState{ready: true}
}
