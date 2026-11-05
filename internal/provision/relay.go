package provision

import (
	"context"
	"encoding/json"

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
