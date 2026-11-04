package summary

import (
	"context"
	"net/netip"
	"sync"

	"github.com/arngory/raycontrol/internal/asn"
	"github.com/arngory/raycontrol/internal/store"
)

// Paths of the AS databases on a node.
const (
	// OperatorDB is a database the operator imported (rayctl summary db),
	// in rayd's state directory: it comes first.
	OperatorDB = "/var/lib/raycontrol/asn.mmdb"
	// ReleaseDB is IPinfo Lite from the release (R4-21).
	ReleaseDB = "/usr/local/share/raycontrol/ipinfo_lite.mmdb"
)

// settingsAPI is the online lookup the administrator turned on, read from
// the settings at each lookup: turning it on or off needs no restart.
type settingsAPI struct {
	st *store.Store

	mu       sync.Mutex
	provider string
	token    string
	api      *asn.API
}

func (s *settingsAPI) Lookup(ctx context.Context, addr netip.Addr) (asn.Info, bool) {
	provider, token := API(ctx, s.st)
	s.mu.Lock()
	if provider != s.provider || token != s.token {
		s.provider, s.token, s.api = provider, token, nil
		if mk, ok := asn.Providers[provider]; ok && token != "" {
			s.api = &asn.API{Provider: mk(token, nil)}
		}
	}
	api := s.api
	s.mu.Unlock()
	if api == nil {
		return asn.Info{}, false
	}
	return api.Lookup(ctx, addr)
}

// Sources is the lookup chain of a node: the operator's database, the
// release's, then the API if turned on.
func Sources(st *store.Store, operator, release *asn.DB) asn.Chain {
	return asn.Chain{operator, release, &settingsAPI{st: st}}
}
