package provision

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// RelayParams returns a relay's own SPA parameters (relay-v1 §3), made on
// first use and kept: its devices' knocks depend on them.
func RelayParams(ctx context.Context, st *store.Store, name string) (spa.Params, error) {
	for range 2 {
		r, err := st.RelayByName(ctx, name)
		if err != nil {
			return spa.Params{}, err
		}
		if len(r.SPA) > 0 {
			var j node.SPAParams
			if err := json.Unmarshal(r.SPA, &j); err != nil {
				return spa.Params{}, err
			}
			return j.Params()
		}
		p, err := spa.RandomParams(nil)
		if err != nil {
			return p, err
		}
		b, err := json.Marshal(node.FromParams(p))
		if err != nil {
			return p, err
		}
		if set, err := st.SetRelaySPA(ctx, name, b); err != nil || set {
			return p, err
		}
		// Made by someone else meanwhile: read theirs.
	}
	return spa.Params{}, store.ErrInvalid
}

// NewRelayParams draws SPA parameters for a relay whose range keeps clear of
// the given ports, which the relay forwards or serves itself: a knock on a
// slot port that is also a forwarded one would go to the exit instead.
func NewRelayParams(avoid []store.Port) (spa.Params, []byte, error) {
	for range 100 {
		p, err := spa.RandomParams(nil)
		if err != nil {
			return p, nil, err
		}
		if slices.ContainsFunc(avoid, func(port store.Port) bool {
			return int(port.Num) >= int(p.PortBase) && int(port.Num) < int(p.PortBase)+int(p.PortRange)
		}) {
			continue
		}
		b, err := json.Marshal(node.FromParams(p))
		return p, b, err
	}
	return spa.Params{}, nil, fmt.Errorf("%w: no SPA range for the relay clear of its ports", store.ErrInvalid)
}

// RelayProbeSvc is the scope ID of a relay's own probe-v1 endpoint (relay-v1
// §9.1): a local service of the relay, which a knock names in an explicit
// scope. The exit's services have IDs far below it.
const RelayProbeSvc uint16 = 65535

// RelayProbePort draws the port of a relay's probe endpoint, TCP and UDP on
// one number: clear of the ports the relay forwards or serves, of either
// protocol, and of its SPA range.
func RelayProbePort(avoid []store.Port, p spa.Params) (uint16, error) {
	const lo, hi = 10000, 60000
	// From a random port on, the first free one: found if there is one.
	start, err := rand.Int(rand.Reader, big.NewInt(hi-lo))
	if err != nil {
		return 0, err
	}
	for i := range int64(hi - lo) {
		port := uint16(lo + (start.Int64()+i)%(hi-lo))
		if int(port) >= int(p.PortBase) && int(port) < int(p.PortBase)+int(p.PortRange) ||
			slices.ContainsFunc(avoid, func(a store.Port) bool { return a.Num == port }) {
			continue
		}
		return port, nil
	}
	return 0, fmt.Errorf("%w: no port for the relay's probe endpoint", store.ErrInvalid)
}

// SSHPorts are the ports of the SSH services, enabled or not: sshd listens
// whatever the service's state.
func SSHPorts(services []store.Service) map[store.Port]bool {
	out := map[store.Port]bool{}
	for _, svc := range services {
		if svc.Kind == "ssh" {
			ports, _ := svc.Ports()
			for _, p := range ports {
				out[p] = true
			}
		}
	}
	return out
}

// ServicePorts are a service's ports in the perimeter: never SSH's for
// another service. Creating one is refused (provision.sshPortsApart); a
// database from before the check may have one, and a grant or a relay for
// that service must not reach sshd.
func ServicePorts(svc store.Service, ssh map[store.Port]bool) ([]store.Port, error) {
	ports, err := svc.Ports()
	if err != nil || svc.Kind == "ssh" {
		return ports, err
	}
	return slices.DeleteFunc(slices.Clone(ports), func(p store.Port) bool { return ssh[p] }), nil
}

// RelayPorts are the ports of svc a relay forwards: its own (ServicePorts),
// but the relay host's SSH and the relay's probe endpoint, which the relay
// serves itself (IssueRelayBundle keeps clear of them; a service given one
// later loses it there). The relay's snapshot and the subscription's via
// both go by it.
func RelayPorts(relay store.Relay, svc store.Service, ssh map[store.Port]bool) ([]store.Port, error) {
	ports, err := ServicePorts(svc, ssh)
	if err != nil {
		return nil, err
	}
	sshPort := store.Port{Proto: "tcp", Num: relay.SSHPort}
	return slices.DeleteFunc(slices.Clone(ports), func(p store.Port) bool {
		return p == sshPort || relay.ProbePort != 0 && p.Num == relay.ProbePort
	}), nil
}
