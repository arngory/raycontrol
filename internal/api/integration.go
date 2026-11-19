package api

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
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
	done, suffix := func(bool) {}, ""
	if m.ExpiresAt != 0 {
		t := time.Unix(m.ExpiresAt, 0).UTC()
		at, what = &t, t.Format(time.RFC3339)
		now := time.Now()
		if !t.After(now) {
			what = "now"
		}
		if !t.After(now.Add(expirySoon)) {
			// billing's expiry now is a disable by another name: a mass
			// action as SetUserEnabled{false} is (integrations-v1 §2.4).
			// So is one in a few minutes: a clock ahead, or a loop that
			// got the period wrong.
			var err error
			if done, suffix, err = s.massGuard(ctx, "SetUserExpiry", m.ConfirmMass); err != nil {
				return nil, toConnect(err)
			}
		}
	}
	u, err := s.Store.SetUserExpiry(ctx, m.Name, at)
	done(err == nil)
	if err := s.done(ctx, "user.expires="+what+suffix, m.Name, err); err != nil {
		return nil, err
	}
	pb, err := s.userPB(ctx, u)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.SetUserExpiryResponse{User: pb}), nil
}

// expirySoon is how far ahead an expiry still counts as a mass action.
const expirySoon = 10 * time.Minute

// tinyLimit is a traffic limit no plan has: one under it is a mistake of
// units (bytes for gigabytes) that cuts the user off at once.
const tinyLimit = 1 << 20

// limitCutsOff reports whether billing's traffic change cuts the user off,
// a disable by another name (integrations-v1 §2.4): a limit under
// tinyLimit, or one that leaves less than tinyLimit over what the user has
// used this period (counted on while the call goes). Others' changes are
// not looked at.
func (s *Server) limitCutsOff(ctx context.Context, m *nodev1.SetUserTrafficRequest) (bool, error) {
	if d, ok := caller(ctx); !ok || d.Role != "billing" || m.LimitBytes == nil || *m.LimitBytes <= 0 {
		return false, nil
	}
	if *m.LimitBytes < tinyLimit {
		return true, nil
	}
	if m.ResetUsage {
		return false, nil
	}
	u, err := s.Store.UserByName(ctx, m.Name)
	if err != nil {
		return false, err
	}
	return *m.LimitBytes-u.Used(time.Now()) < tinyLimit, nil
}

// massGuard puts billing's deletion or disable under the hour's limit of
// mass actions (integrations-v1 §2.4): refused over it without confirm,
// audited as api.mass once in a while. Others' actions are not counted.
// done says whether the action went through; suffix marks its audit line.
func (s *Server) massGuard(ctx context.Context, method string, confirm bool) (done func(bool), suffix string, err error) {
	d, ok := caller(ctx)
	if !ok || d.Role != "billing" {
		return func(bool) {}, "", nil
	}
	now := time.Now()
	done, confirmed, err := s.massAction(ctx, confirm, now)
	if errors.Is(err, errMassLimit) {
		s.auditQuietly(ctx, d, "api.mass", method, "refused", now)
	}
	if err != nil {
		return nil, "", err
	}
	if confirmed {
		suffix = " confirm"
	}
	return done, suffix, nil
}

// integrationRates are a role's or a device's limits as the API gives them.
func integrationRates(l limitSet) *nodev1.IntegrationLimits {
	r := func(x limitRate) *nodev1.Rate {
		if x.Burst == 0 {
			return nil
		}
		return &nodev1.Rate{Burst: x.Burst, PerHour: x.PerHour}
	}
	return &nodev1.IntegrationLimits{Read: r(l.Read), Write: r(l.Write), Heavy: r(l.Heavy), Inflight: l.Inflight}
}

// GetIntegrationSettings returns the integrations' settings and their
// devices' calls since rayd started (integrations-v1 §11).
func (s *Server) GetIntegrationSettings(ctx context.Context, _ *connect.Request[nodev1.GetIntegrationSettingsRequest]) (*connect.Response[nodev1.GetIntegrationSettingsResponse], error) {
	set, err := s.integrationSettings(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	counting, err := s.Store.TrafficCountingOn(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	resp := &nodev1.GetIntegrationSettingsResponse{SupportNotes: set.SupportNotes, MassLimit: uint32(set.massLimit()), TrafficCounting: "auto"} //nolint:gosec // G115: from a uint32
	if counting {
		resp.TrafficCounting = "on"
	}
	for _, role := range []string{"billing", "support"} {
		_, own := set.Roles[role]
		resp.Limits = append(resp.Limits, &nodev1.IntegrationLimitsFor{Role: role, Limits: integrationRates(set.limits("", role)), Set: own})
	}
	for _, id := range slices.Sorted(maps.Keys(set.Devices)) {
		resp.Limits = append(resp.Limits, &nodev1.IntegrationLimitsFor{DeviceId: id, Limits: integrationRates(set.Devices[id]), Set: true})
	}
	devices, err := s.Store.ListDevices(ctx, "")
	if err != nil {
		return nil, toConnect(err)
	}
	now := time.Now()
	in := &s.integ
	in.mu.Lock()
	for _, d := range devices {
		if !store.IntegrationRole(d.Role) || d.RevokedAt != nil {
			continue
		}
		pb := &nodev1.IntegrationDevice{Id: d.ID, User: d.UserName, Name: d.Name, Role: d.Role}
		if e, ok := in.devices[d.ID]; ok {
			pb.LastCall, pb.Calls, pb.Denied, pb.Limited = unixOf(e.last), e.calls, e.denied, e.limited
		}
		resp.Devices = append(resp.Devices, pb)
	}
	hourAgo := now.Add(-time.Hour)
	for _, t := range in.mass {
		if t.After(hourAgo) {
			resp.MassActions++
		}
	}
	resp.MassRefused = in.massDone.refused
	in.mu.Unlock()
	return connect.NewResponse(resp), nil
}

// The bounds of a limit root sets: up to 10 000 calls a second, 64 at once.
const (
	maxBurst    = 100_000
	maxPerHour  = 36_000_000
	maxInflight = 64
)

// mergeLimits puts what a request gives over l: a rate given replaces
// that class's, an inflight given (not 0) the calls at once.
func mergeLimits(l limitSet, pb *nodev1.IntegrationLimits) (limitSet, error) {
	if pb == nil {
		return l, fmt.Errorf("%w: no limits given", store.ErrInvalid)
	}
	for _, x := range []struct {
		to   *limitRate
		from *nodev1.Rate
	}{{&l.Read, pb.Read}, {&l.Write, pb.Write}, {&l.Heavy, pb.Heavy}} {
		if x.from == nil {
			continue
		}
		if x.from.Burst == 0 || x.from.Burst > maxBurst || x.from.PerHour == 0 || x.from.PerHour > maxPerHour {
			return l, fmt.Errorf("%w rate %d,%d/h: a burst of 1 to %d, 1 to %d an hour", store.ErrInvalid, x.from.Burst, x.from.PerHour, maxBurst, maxPerHour)
		}
		*x.to = limitRate{Burst: x.from.Burst, PerHour: x.from.PerHour}
	}
	if pb.Inflight > maxInflight {
		return l, fmt.Errorf("%w inflight %d: 1 to %d", store.ErrInvalid, pb.Inflight, maxInflight)
	}
	if pb.Inflight != 0 {
		l.Inflight = pb.Inflight
	}
	return l, nil
}

// limitsText is a set of limits as rayctl takes them, for the audit.
func limitsText(l limitSet) string {
	r := func(x limitRate) string { return fmt.Sprintf("%d,%d/h", x.Burst, x.PerHour) }
	return fmt.Sprintf("read=%s write=%s heavy=%s inflight=%d", r(l.Read), r(l.Write), r(l.Heavy), l.Inflight)
}

// errRootOnly refuses what root sets on the node alone.
var errRootOnly = fmt.Errorf("%w: root on the node only", errForRole)

// SetIntegrationSettings changes the integrations' settings
// (integrations-v1 §2.2, §2.4, §2.6): support's sight of notes and the
// traffic counting by an administrator too, the mass actions' limit and
// the rate limits by root on the node only. Each change is audited.
func (s *Server) SetIntegrationSettings(ctx context.Context, req *connect.Request[nodev1.SetIntegrationSettingsRequest]) (*connect.Response[nodev1.SetIntegrationSettingsResponse], error) {
	m := req.Msg
	root := isRoot(ctx)
	if (m.MassLimit != nil || m.Limits != nil) && !root {
		return nil, toConnect(errRootOnly)
	}
	if m.TrafficCounting != nil && *m.TrafficCounting != "on" && *m.TrafficCounting != "auto" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("traffic counting: on or auto"))
	}
	// The limits checked before anything is set: a request applies whole
	// or not at all, but for a store error between its parts.
	if m.Limits != nil {
		role, device, err := s.limitsTarget(ctx, m.Limits)
		if err == nil {
			set, rerr := s.integrationSettings(ctx)
			if rerr != nil {
				set = integrationSettings{}
			}
			// A trial on copies: the maps are the kept settings'.
			set.Roles, set.Devices = maps.Clone(set.Roles), maps.Clone(set.Devices)
			_, err = applyLimits(&set, role, device, m.Limits.Limits, m.ToDefault)
		}
		if err != nil {
			return nil, toConnect(err)
		}
	}
	if m.SupportNotes != nil {
		state := "off"
		if *m.SupportNotes {
			state = "on"
		}
		err := s.changeIntegrationSettings(ctx, func(set *integrationSettings) error {
			set.SupportNotes = *m.SupportNotes
			return nil
		})
		if err := s.done(ctx, "integration.set support-notes="+state, "", err); err != nil {
			return nil, err
		}
	}
	if m.MassLimit != nil {
		limit := *m.MassLimit
		err := s.changeIntegrationSettings(ctx, func(set *integrationSettings) error {
			set.MassLimit = &limit
			return nil
		})
		if err := s.done(ctx, "integration.set mass-limit="+strconv.FormatUint(uint64(limit), 10), "", err); err != nil {
			return nil, err
		}
	}
	if m.Limits != nil {
		if err := s.setIntegrationLimits(ctx, m.Limits, m.ToDefault); err != nil {
			return nil, err
		}
	}
	if m.TrafficCounting != nil {
		err := s.Store.SetTrafficCountingOn(ctx, *m.TrafficCounting == "on")
		if err := s.done(ctx, "traffic.counting="+*m.TrafficCounting, "", err); err != nil {
			return nil, err
		}
	}
	return connect.NewResponse(&nodev1.SetIntegrationSettingsResponse{}), nil
}

// setIntegrationLimits sets a role's or a device's limits, or with reset
// takes them back to the default (rayctl integration limits).
func (s *Server) setIntegrationLimits(ctx context.Context, pb *nodev1.IntegrationLimitsFor, reset bool) error {
	role, device, err := s.limitsTarget(ctx, pb)
	if err != nil {
		return toConnect(err)
	}
	var text string
	err = s.changeIntegrationSettings(ctx, func(set *integrationSettings) error {
		var err error
		text, err = applyLimits(set, role, device, pb.Limits, reset)
		return err
	})
	if err == nil {
		s.integ.refill()
	}
	return s.done(ctx, "integration.limits "+text, cmp.Or(device, role), err)
}

// limitsTarget is the role, and the device if one, that limits are set
// for: a role of an integration, or a device of one.
func (s *Server) limitsTarget(ctx context.Context, pb *nodev1.IntegrationLimitsFor) (role, device string, err error) {
	role, device = pb.Role, pb.DeviceId
	switch {
	case (role == "") == (device == ""):
		return "", "", fmt.Errorf("%w: limits for a role or a device", store.ErrInvalid)
	case role != "" && !store.IntegrationRole(role):
		return "", "", fmt.Errorf("%w role %q: billing or support", store.ErrInvalid, role)
	case device != "":
		devices, err := s.Store.ListDevices(ctx, "")
		if err != nil {
			return "", "", err
		}
		i := slices.IndexFunc(devices, func(d store.Device) bool { return d.ID == device })
		if i < 0 || !store.IntegrationRole(devices[i].Role) {
			return "", "", fmt.Errorf("integration device %q: %w", device, store.ErrNotFound)
		}
		role = devices[i].Role
	}
	return role, device, nil
}

// applyLimits sets a role's or a device's limits in set, or with reset
// takes away its own: a device's reset leaves its role's as they are. It
// returns the limits as the audit says them.
func applyLimits(set *integrationSettings, role, device string, pb *nodev1.IntegrationLimits, reset bool) (string, error) {
	if reset {
		if device != "" {
			delete(set.Devices, device)
		} else {
			delete(set.Roles, role)
		}
		return "default", nil
	}
	l, err := mergeLimits(set.limits(device, role), pb)
	if err != nil {
		return "", err
	}
	if device != "" {
		if set.Devices == nil {
			set.Devices = map[string]limitSet{}
		}
		set.Devices[device] = l
	} else {
		if set.Roles == nil {
			set.Roles = map[string]limitSet{}
		}
		set.Roles[role] = l
	}
	return limitsText(l), nil
}
