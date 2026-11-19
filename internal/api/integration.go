package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// errForRole refuses a call's argument to the caller's role: what
// billing may not give (integrations-v1 §2.2, §2.4). PermissionDenied.
var errForRole = errors.New("not for this role")

// dataKinds are the services billing gives users (integrations-v1 §2.2):
// a data service each. ssh, api, subscription and site are not: a user's
// service is in the SPA scope of the user's devices, and ssh there would
// open the node's SSH. A kind the node learns later is out until it is
// put here (TestDataKinds).
var dataKinds = map[string]bool{
	"reality": true, "hy2-masq": true, "hy2-obfs": true, "naive": true, "doh": true, "yggdrasil": true,
	"dnstt": true, "masterdns": true, "slipstream": true, "olcrtc": true, "openflux": true, "inner": true,
}

// billingInviteRole refuses billing an invite of any role but user:
// before anything is written (integrations-v1 §2.4).
func billingInviteRole(ctx context.Context, role string) error {
	if callerRole(ctx) == "billing" && role != "user" {
		return fmt.Errorf("%w: billing invites devices of role user only", errForRole)
	}
	return nil
}

// GetUser returns one user, as ListUsers has it (integrations-v1 §10).
func (s *Server) GetUser(ctx context.Context, req *connect.Request[nodev1.GetUserRequest]) (*connect.Response[nodev1.GetUserResponse], error) {
	u, err := s.Store.UserByName(ctx, req.Msg.Name)
	if err != nil {
		return nil, toConnect(err)
	}
	pb, err := s.userPB(ctx, u)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.GetUserResponse{User: pb}), nil
}

// SetUserExpiry sets when a user expires (integrations-v1 §10), audited as
// user.expires=<RFC 3339 time, never or now>.
func (s *Server) SetUserExpiry(ctx context.Context, req *connect.Request[nodev1.SetUserExpiryRequest]) (*connect.Response[nodev1.SetUserExpiryResponse], error) {
	m := req.Msg
	var at *time.Time
	what := "never"
	if m.ExpiresAt != 0 {
		t := time.Unix(m.ExpiresAt, 0).UTC()
		at, what = &t, t.Format(time.RFC3339)
		if !t.After(time.Now()) {
			what = "now"
		}
	}
	u, err := s.Store.SetUserExpiry(ctx, m.Name, at)
	if err := s.done(ctx, "user.expires="+what, m.Name, err); err != nil {
		return nil, err
	}
	pb, err := s.userPB(ctx, u)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.SetUserExpiryResponse{User: pb}), nil
}
