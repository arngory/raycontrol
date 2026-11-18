package node

import (
	"context"
	"errors"
	"fmt"

	"github.com/arngory/raycontrol/internal/clientver"
	"github.com/arngory/raycontrol/internal/store"
)

const settingClient = "client_min"

// ClientPolicy is the node's minimum client version (client-min-v1 §2);
// the zero policy when none is set.
func ClientPolicy(ctx context.Context, st *store.Store) (clientver.Policy, error) {
	b, err := st.GetSetting(ctx, settingClient)
	if errors.Is(err, store.ErrNotFound) {
		return clientver.Policy{}, nil
	}
	if err != nil {
		return clientver.Policy{}, err
	}
	return clientver.Unmarshal(b)
}

// SetClientPolicy keeps a policy and returns it as kept; one without a
// minimum takes the policy away.
func SetClientPolicy(ctx context.Context, st *store.Store, p clientver.Policy) (clientver.Policy, error) {
	p, err := p.Check()
	if err != nil {
		return p, fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	b, err := p.Marshal()
	if err != nil {
		return p, err
	}
	return p, st.SetSetting(ctx, settingClient, b)
}
