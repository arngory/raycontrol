package provision

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// naive's server name changes in epochs (docs/08-decisions.md R4-42,
// docs/20-naive-sni-rotation.md §8), with nothing new for clients: the
// next name goes into the profile's next link a lead time before the
// switch (subscription-v1 §3), and the client takes that line whole.
//
// The front's routes change once an epoch. The next name is chosen at the
// switch before (at the service's creation, at the first render of a node
// from before R4-42) and routed from then on, before it is published; the
// previous name stays routed until the next switch. So the routes are
// {sni, sni_next}, then {sni, sni_prev, sni_next}, and front.json changes
// only at a switch, which restarts the front (it reads its routes at its
// start only). The publication changes no route: a client whose clock is
// ahead, or that tries next early when link fails, finds the new name
// served; one that never fetched since finds the old one served.
//
// Neither the site's key nor the password changes with the name: the
// lines before and after carry the same niko-pin.

// NaiveState is the name rotation state in the settings of a naive
// service. No secret: a backup carries it as it is.
type NaiveState struct {
	SNI        string `json:"sni"`                   // the name in use, in the links
	SNINext    string `json:"sni_next,omitempty"`    // the name after the next switch, routed already; in subscriptions once published
	NextFrom   int64  `json:"next_from,omitempty"`   // sni_next published, switch at this time
	SNIPrev    string `json:"sni_prev,omitempty"`    // the name before the last switch, routed until the next one
	RotatedAt  int64  `json:"rotated_at,omitempty"`  // last switch; the service's creation before the first
	PreparedAt int64  `json:"prepared_at,omitempty"` // the site's certificate is asked to cover sni_next since then
	RotateSNI  *bool  `json:"rotate_sni,omitempty"`  // scheduled switches: true always, false never; unset: under a wildcard certificate only
	RotateAt   int64  `json:"rotate_at,omitempty"`   // switch requested by the operator for this time
}

// ParseNaiveState reads the name rotation state of a naive service.
func ParseNaiveState(svc store.Service) NaiveState {
	var st NaiveState
	_ = json.Unmarshal([]byte(svc.Settings), &st)
	if st.RotatedAt == 0 {
		st.RotatedAt = svc.CreatedAt.Unix()
	}
	return st
}

// EnsureNaiveNext gives a naive service without a next name one (a node
// from before R4-42, a restored backup made before): rayd renders it at
// once, so that it is routed before it is ever published. It returns the
// service as stored. A node whose domain has no free name left keeps the
// service as it is: the name waits, the render does not.
func EnsureNaiveNext(ctx context.Context, st *store.Store, svc store.Service) (store.Service, error) {
	if svc.Kind != "naive" || ParseNaiveState(svc).SNINext != "" {
		return svc, nil
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	all, err := st.ListServices(ctx)
	if err != nil {
		return svc, err
	}
	for _, s := range all {
		if s.ID == svc.ID {
			svc = s // as it is now: another may have chosen it meanwhile
		}
	}
	if ParseNaiveState(svc).SNINext != "" {
		return svc, nil
	}
	settings, err := naiveNext(ctx, st, all, svc)
	if errors.Is(err, store.ErrInvalid) {
		return svc, nil
	}
	if err != nil {
		return svc, err
	}
	if err := st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings}); err != nil {
		return svc, err
	}
	svc.Settings = settings
	return svc, nil
}

// naiveNext is a naive service's settings with a new next name, one no
// service has in its settings (current, previous or next).
func naiveNext(ctx context.Context, st *store.Store, all []store.Service, svc store.Service) (string, error) {
	name, err := newZone(ctx, st, all)
	if err != nil {
		return "", err
	}
	return setFields(svc.Settings, map[string]any{"sni_next": name})
}

// naiveSwitch is when a naive service's next switch is due (MaxInt64:
// none): the operator's time, or a period after the last switch when a
// scheduled switch moves the name (RenamesAt). A scheduled one moves to the
// next switch of a REALITY of the same site within half a period of it
// (the owner's answer 2 to docs/20 §9): REALITY's switch restarts the front
// when its name changes, and naive's too, and one restart carries both.
func naiveSwitch(ctx context.Context, st *store.Store, all []store.Service, svc store.Service, state NaiveState, e RealityEpoch, now int64) int64 {
	due := int64(math.MaxInt64)
	if e.NaivePeriod > 0 && RenamesAt(ctx, st, all, siteOf(svc), state.RotateSNI, false) {
		period := int64(e.NaivePeriod / time.Second)
		due = state.RotatedAt + period
		join, gap := int64(0), period/2+1
		for _, r := range all {
			if r.Kind != "reality" || !r.Enabled || siteOf(r) == "" || siteOf(r) != siteOf(svc) {
				continue
			}
			// One to come: a REALITY behind its time (waiting for its
			// certificate) is not waited for.
			if at := realityNextSwitch(r, e); at != math.MaxInt64 && at >= now && abs(at-due) < gap {
				join, gap = at, abs(at-due)
			}
		}
		if join != 0 {
			due = join
		}
	}
	if state.RotateAt != 0 {
		due = min(due, state.RotateAt)
	}
	return due
}

// realityNextSwitch is when a REALITY service switches next: its published
// time, or its scheduled one (MaxInt64: none). A switch the operator asked
// for counts once published: its time is set then, from the publication
// on (a lead after it), not at the request.
func realityNextSwitch(r store.Service, e RealityEpoch) int64 {
	rs := ParseRealityState(r)
	switch {
	case rs.NextFrom != 0:
		return rs.NextFrom
	case e.Period > 0:
		return rs.RotatedAt + int64(e.Period/time.Second)
	}
	return math.MaxInt64
}

// naiveEarly is how long before its time a naive switch happens: as early
// as a REALITY of the same site switching at that time (RealityEarly with
// a grace period; published for it, or switched for it in this round), so
// that both are in one round; otherwise not early at all. naive itself
// needs none: the new name is routed already, and a client whose clock is
// ahead finds it served. (A lead as short as RealityEarly, as on a test
// stand, would otherwise switch at the publication.)
func naiveEarly(all []store.Service, svc store.Service, from int64, e RealityEpoch) int64 {
	if e.Grace <= 0 {
		return 0
	}
	for _, r := range all {
		if r.Kind != "reality" || !r.Enabled || siteOf(r) == "" || siteOf(r) != siteOf(svc) {
			continue
		}
		if rs := ParseRealityState(r); rs.NextFrom == from || rs.RotatedAt == from {
			return int64(RealityEarly / time.Second)
		}
	}
	return 0
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// rotateNaive advances the name rotation of one naive service at now.
func rotateNaive(ctx context.Context, st *store.Store, all []store.Service, svc store.Service, now time.Time, e RealityEpoch,
	log *slog.Logger) (bool, error) {
	state := ParseNaiveState(svc)
	t := now.Unix()
	if state.SNINext == "" {
		// The render picks it first (EnsureNaiveNext); a store no render
		// has read since gets it here, published at a later round only.
		settings, err := naiveNext(ctx, st, all, svc)
		if err != nil {
			return false, err
		}
		return true, st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings})
	}
	lead := int64(e.Lead / time.Second)
	if state.NextFrom != 0 {
		if t < state.NextFrom-naiveEarly(all, svc, state.NextFrom, e) {
			return false, nil
		}
		return true, switchNaive(ctx, st, all, svc, state, log)
	}

	due := naiveSwitch(ctx, st, all, svc, state, e, t)
	covered := SiteCovers(ctx, st, all, siteOf(svc), state.SNINext)
	switch {
	case due == math.MaxInt64 && state.PreparedAt != 0:
		// Called off (rotate_sni off, the period 0, the operator's switch
		// given up): the certificate no longer needs the name.
		return true, naiveFields(ctx, st, svc, map[string]any{"prepared_at": nil})
	case due == math.MaxInt64:
		return false, nil
	case !covered && state.PreparedAt == 0:
		// The site's certificate is asked for the next name: at once,
		// for a scheduled switch an epoch ahead (under listed names it is
		// in CT logs from now: rotate_sni=on chose that), at the request
		// for the operator's.
		log.Info("naive: the next server name waits for its certificate", "service", svc.Name)
		return true, naiveFields(ctx, st, svc, map[string]any{"prepared_at": t})
	case t < due-lead:
		return false, nil
	case !covered && t < max(state.PreparedAt, due-lead)+int64(e.Prepare/time.Second):
		return false, nil
	case !covered:
		// Not certified in time: the name stays, for this epoch.
		log.Warn("naive server name stays: the next name got no certificate in time", "service", svc.Name)
		return true, naiveFields(ctx, st, svc, map[string]any{"prepared_at": nil, "rotate_at": nil, "rotated_at": t})
	}
	from := max(due, t+lead)
	if state.RotateAt != 0 && state.RotateAt <= t {
		from = t // now: the operator asked for it
	}
	if err := naiveFields(ctx, st, svc, map[string]any{"next_from": from, "prepared_at": nil}); err != nil {
		return false, err
	}
	log.Info("naive: next server name published", "service", svc.Name, "switch", time.Unix(from, 0).UTC())
	if t < from-naiveEarly(all, svc, from, e) {
		return true, nil
	}
	// The operator's switch at once: the name is routed already.
	svc, err := st.ServiceByName(ctx, svc.Name)
	if err != nil {
		return true, err
	}
	state = ParseNaiveState(svc)
	return true, switchNaive(ctx, st, all, svc, state, log)
}

// switchNaive makes the next name current, the current one previous (it
// stays routed until the next switch), and chooses the name after.
func switchNaive(ctx context.Context, st *store.Store, all []store.Service, svc store.Service, state NaiveState, log *slog.Logger) error {
	name, err := newZone(ctx, st, all)
	if err != nil {
		return err
	}
	fields := map[string]any{"sni": state.SNINext, "sni_prev": state.SNI, "sni_next": name, "rotated_at": state.NextFrom,
		"next_from": nil, "rotate_at": nil, "prepared_at": nil}
	if err := naiveFields(ctx, st, svc, fields); err != nil {
		return err
	}
	log.Info("naive server name switched; the previous one is accepted until the next switch", "service", svc.Name)
	return nil
}

func naiveFields(ctx context.Context, st *store.Store, svc store.Service, fields map[string]any) error {
	settings, err := setFields(svc.Settings, fields)
	if err != nil {
		return err
	}
	return st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings})
}
