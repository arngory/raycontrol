package provision

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"slices"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/store"
)

// settingRelayNames holds the relays' names (spec/relay-names-v1.md §3):
// JSON {"<relay>": {"<service ID>": "<name>"}}.
const settingRelayNames = node.RelayNamesSetting

// RelayName is a relay's name for one service of the node
// (spec/relay-names-v1.md §3): one label under the node's domain that
// resolves to the relay's address. A client that goes through the relay
// connects to it and sends it as SNI; the front routes it to the service.
type RelayName struct {
	Relay   string
	Address netip.Addr // the relay's, which the name resolves to
	Service int64
	Name    string
}

// RelayNamed reports whether a service has a name at each relay that
// forwards it (§2): its SNI is the node's, one its site's certificate
// proves. Not REALITY with a target of someone else's, nor hy2-obfs: their
// SNI is not the node's, and a relay's name would hide nothing.
func RelayNamed(svc store.Service) bool {
	switch svc.Kind {
	case "naive", "doh", "hy2-masq":
		return true
	case "reality":
		return siteOf(svc) != ""
	}
	return false
}

// RelayNames are the names of the pairs of a relay and a service that
// have one now (§3), by relay, then service: the node has a domain and its
// host is an address, the relay its bundle (cert_pin, as the subscription
// lists it), and the service is enabled, RelayNamed and forwarded by the
// relay (RelayPorts). Made on first use, under the lock service names are
// chosen under, with newZone as theirs, and kept while the relay and the
// service are: clients are given them. A name not one label under the
// domain (the domain changed since) gets a new one; the names of a relay
// or a service removed go. None while a zone holds the domain, as with
// the node's own name; and none for the pairs past the last free label.
// Callers do not hold settingsMu.
func RelayNames(ctx context.Context, st *store.Store) ([]RelayName, error) {
	domain, err := Domain(ctx, st)
	if err != nil || domain == "" {
		return nil, err
	}
	host, err := node.Host(ctx, st)
	if err != nil || len(node.Addrs(host)) == 0 {
		return nil, err
	}
	// As clients resolve them: a domain stored before Init canonicalized
	// it may have capitals or a final dot.
	domain = canonicalZone(domain)
	// Without the lock while nothing is to be made or dropped: on every
	// render and fetch.
	names, changed, err := relayNames(ctx, st, domain, false)
	if err != nil || !changed {
		return names, err
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	names, _, err = relayNames(ctx, st, domain, true)
	return names, err
}

// relayNames is RelayNames for the canonical domain. Without write it
// makes and stores nothing, and changed says that the stored names are
// not what they should be: a pair has none, or a name is to go. With
// write (under settingsMu) it makes the missing ones and stores the lot.
func relayNames(ctx context.Context, st *store.Store, domain string, write bool) ([]RelayName, bool, error) {
	relays, err := st.ListRelays(ctx)
	if err != nil {
		return nil, false, err
	}
	all, err := st.ListServices(ctx)
	if err != nil {
		return nil, false, err
	}
	// A zone stored at or above the domain, as v0.13 took: no name under
	// it resolves, as NodeDNSName says.
	if zoneHoldsDomain(all, domain) {
		return nil, false, nil
	}
	stored, err := storedRelayNames(ctx, st)
	if err != nil {
		return nil, false, err
	}
	// Kept: the names of relays and services still there, under the
	// domain, disabled services' too (they may be enabled again).
	kept := map[string]map[int64]string{}
	for r, svcs := range stored {
		if !slices.ContainsFunc(relays, func(x store.Relay) bool { return x.Name == r }) {
			continue
		}
		for id, name := range svcs {
			if slices.ContainsFunc(all, func(s store.Service) bool { return s.ID == id }) && oneLabelUnder(name, domain) {
				if kept[r] == nil {
					kept[r] = map[int64]string{}
				}
				kept[r][id] = name
			}
		}
	}
	ssh := SSHPorts(all)
	var out []RelayName
	var made []string // in this call: newZone reads the stored ones itself
	full, missing := false, false
	for _, r := range relays {
		if r.CertPin == "" {
			continue
		}
		for _, svc := range all {
			if !svc.Enabled || !RelayNamed(svc) {
				continue
			}
			if ports, err := RelayPorts(r, svc, ssh); err != nil || len(ports) == 0 {
				continue
			}
			name := kept[r.Name][svc.ID]
			if name == "" {
				missing = true
				if !write || full {
					continue
				}
				name, err = newZone(ctx, st, all, made...)
				if errors.Is(err, store.ErrInvalid) {
					// No label left: the pairs after this one wait, as
					// the node's own name does.
					full = true
					continue
				}
				if err != nil {
					return nil, false, err
				}
				if kept[r.Name] == nil {
					kept[r.Name] = map[int64]string{}
				}
				kept[r.Name][svc.ID] = name
				made = append(made, name)
			}
			out = append(out, RelayName{Relay: r.Name, Address: r.Address, Service: svc.ID, Name: name})
		}
	}
	slices.SortFunc(out, func(a, b RelayName) int {
		return cmp.Or(cmp.Compare(a.Relay, b.Relay), cmp.Compare(a.Service, b.Service))
	})
	same := maps.EqualFunc(kept, stored, maps.Equal)
	if !write || same {
		return out, missing || !same, nil
	}
	b, err := json.Marshal(kept)
	if err != nil {
		return nil, false, err
	}
	// settingsMu is this process's, and rayd is the one process that
	// renders and syncs DNS: the names stored are those it made.
	return out, true, st.SetSetting(ctx, settingRelayNames, b)
}

// ForgetRelayNames drops a relay's names at once, as its removal and a new
// relay by its name do: the new one gets names of its own, not those of
// the one before, which resolvers may still hold with its address. A
// render after the removal would drop them too, but a relay added again
// before it would keep them.
func ForgetRelayNames(ctx context.Context, st *store.Store, relay string) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	stored, err := storedRelayNames(ctx, st)
	if _, ok := stored[relay]; err != nil || !ok {
		return err
	}
	delete(stored, relay)
	b, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	return st.SetSetting(ctx, settingRelayNames, b)
}

// storedRelayNames is the setting as stored, any relay's and service's,
// canonical. One that does not read is none: its names are made again,
// as the node's own name is when it is not one label under the domain.
func storedRelayNames(ctx context.Context, st *store.Store) (map[string]map[int64]string, error) {
	b, err := st.GetSetting(ctx, settingRelayNames)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var stored map[string]map[int64]string
	if json.Unmarshal(b, &stored) != nil {
		return nil, nil
	}
	for _, svcs := range stored {
		for id, name := range svcs {
			svcs[id] = canonicalZone(name)
		}
	}
	return stored, nil
}

// relayNameList is every relay name stored, by relay and service, with
// its relay: what newZone keeps clear of, and what a zone may not take
// (nodeNameClash).
func relayNameList(ctx context.Context, st *store.Store) (relays, names []string, err error) {
	stored, err := storedRelayNames(ctx, st)
	for _, r := range slices.Sorted(maps.Keys(stored)) {
		for _, id := range slices.Sorted(maps.Keys(stored[r])) {
			relays, names = append(relays, r), append(names, stored[r][id])
		}
	}
	return relays, names, err
}
