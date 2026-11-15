package provision

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"slices"
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
// previous name stays routed until the next switch, and longer when that
// comes within a period (NaivePrevious). So the routes are {sni, sni_next},
// then {sni, sni_prev, sni_next}, and front.json changes only at a switch,
// which restarts the front (it reads its routes at its start only). The
// publication changes no route: a client whose clock is ahead, or that
// tries next early when link fails, finds the new name served; one that
// never fetched since finds the old one served.
//
// Neither the site's key nor the password changes with the name: the
// lines before and after carry the same niko-pin.

// NaiveState is the name rotation state in the settings of a naive
// service. No secret: a backup carries it as it is.
type NaiveState struct {
	SNI        string `json:"sni"`                   // the name in use, in the links
	SNINext    string `json:"sni_next,omitempty"`    // the name after the next switch, routed already; in subscriptions once published
	NextFrom   int64  `json:"next_from,omitempty"`   // sni_next published, switch at this time
	SNIPrev    string `json:"sni_prev,omitempty"`    // the name before the last switch (at rotated_at), routed until a switch after
	RotatedAt  int64  `json:"rotated_at,omitempty"`  // last switch; the service's creation before the first
	PreparedAt int64  `json:"prepared_at,omitempty"` // the site's certificate is asked to cover sni_next since then
	RotateSNI  *bool  `json:"rotate_sni,omitempty"`  // scheduled switches: true always, false never; unset: under a wildcard certificate only
	RotateAt   int64  `json:"rotate_at,omitempty"`   // switch requested by the operator for this time
	// The names before sni_prev still routed, newest first: left less than
	// a period before the last switch (NaivePrevious). A release before
	// knows sni_prev alone, which stays the newest.
	SNIOlder []NaiveRetired `json:"sni_older,omitempty"`
}

// NaiveRetired is a previous name of a naive service older than sni_prev,
// with the switch that left it.
type NaiveRetired struct {
	SNI       string `json:"sni"`
	RetiredAt int64  `json:"retired_at"`
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

// Previous are the previous names the front routes, newest first:
// sni_prev, then sni_older.
func (s NaiveState) Previous() []string {
	var out []string
	if s.SNIPrev != "" {
		out = append(out, s.SNIPrev)
	}
	for _, o := range s.SNIOlder {
		if o.SNI != "" {
			out = append(out, o.SNI)
		}
	}
	return out
}

// NaivePrevCap is how many previous names of a naive service the front
// routes at most.
const NaivePrevCap = 3

// DefaultNaiveSNIPeriod is rayd serve -naive-sni-period's default, and how
// long previous names stay with -naive-sni-period 0.
const DefaultNaiveSNIPeriod = 90 * 24 * time.Hour

// NaivePrevious is what a naive switch at a time does to the previous
// names (the owner's answer 3 to docs/20 §9: the previous name is accepted
// the whole epoch). Each name left at a switch stays routed until the first
// switch a period or more after that one (-naive-sni-period; 90 days with
// 0): a device that fetched nothing since knows only the link it had. At
// the cadence of the period that is the next switch, as before; a switch
// asked for within the period (rayctl service rotate -now, twice, or after
// the scheduled one when the new name is blocked at once) keeps the name
// before too. At most NaivePrevCap, the oldest dropped first. Names go only
// at a switch: front.json changes once a switch still. kept are the
// previous names after the switch, newest first (the name in use before
// it first), dropped those it takes off the front.
func NaivePrevious(state NaiveState, at int64, period time.Duration) (kept []NaiveRetired, dropped []string) {
	if period <= 0 {
		period = DefaultNaiveSNIPeriod
	}
	keep := int64(period / time.Second)
	all := append([]NaiveRetired{{SNI: state.SNI, RetiredAt: at}, {SNI: state.SNIPrev, RetiredAt: state.RotatedAt}}, state.SNIOlder...)
	for _, n := range all {
		switch {
		case n.SNI == "" || n.SNI == state.SNINext || slices.ContainsFunc(kept, func(k NaiveRetired) bool { return k.SNI == n.SNI }) ||
			slices.Contains(dropped, n.SNI):
		case at-n.RetiredAt >= keep || len(kept) == NaivePrevCap:
			dropped = append(dropped, n.SNI)
		default:
			kept = append(kept, n)
		}
	}
	return kept, dropped
}

// retiredNames are the names of a list of previous ones.
func retiredNames(list []NaiveRetired) []string {
	out := make([]string, 0, len(list))
	for _, n := range list {
		out = append(out, n.SNI)
	}
	return out
}

// EnsureNaiveNext gives a naive service without a next name one (a node
// from before R4-42, a restored backup made before): rayd renders it at
// once, so that it is routed before it is ever published. It returns the
// service as stored. A node whose domain has no free name left keeps the
// service as it is: the name waits, the render does not. On a node
// without a domain (the render's, Model.Domain) naive's name does not
// change: it returns at once, with no lock and no read.
func EnsureNaiveNext(ctx context.Context, st *store.Store, svc store.Service, domain string) (store.Service, error) {
	if svc.Kind != "naive" || domain == "" || ParseNaiveState(svc).SNINext != "" {
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

// naiveDue is when a naive service's next switch is due.
type naiveDue struct {
	at      int64 // MaxInt64: none
	reality bool  // at is the switch of a REALITY of the same site, which this one joins
	waits   bool  // that REALITY waits for its new name's certificate: its time is set at its publication
}

// joinSlack is how far apart a naive switch and a REALITY switch of its
// site may be and still go in one round, in seconds: 5 minutes, a quarter
// of the lead at most. A round runs every minute at its own phase, so a
// naive switch published a lead ahead of REALITY's would land up to a
// minute after it; a lead short by that much is harmless.
func joinSlack(e RealityEpoch) int64 {
	return int64(min(5*time.Minute, e.Lead/4) / time.Second)
}

// naiveSwitch is when a naive service's next switch is due: the operator's
// time, or a period after the last switch when a scheduled switch moves
// the name (RenamesAt). A scheduled one moves to the next switch of a
// REALITY of the same site within half a period of it (the owner's answer
// 2 to docs/20 §9): REALITY's switch restarts the front when its name
// changes, and naive's too, and one restart carries both.
func naiveSwitch(ctx context.Context, st *store.Store, all []store.Service, svc store.Service, state NaiveState, e RealityEpoch, now int64) naiveDue {
	d := naiveDue{at: math.MaxInt64}
	if e.NaivePeriod > 0 && RenamesAt(ctx, st, all, siteOf(svc), state.RotateSNI, false) {
		period := int64(e.NaivePeriod / time.Second)
		d.at = state.RotatedAt + period
		join, gap := -1, period/2+1
		for i, r := range all {
			if r.Kind != "reality" || !r.Enabled || siteOf(r) == "" || siteOf(r) != siteOf(svc) {
				continue
			}
			// One to come: a REALITY behind its time (rayd was down) is not
			// waited for.
			if at := realityNextSwitch(r, e); at != math.MaxInt64 && at >= now && abs(at-d.at) < gap {
				join, gap = i, abs(at-d.at)
			}
		}
		if join >= 0 {
			// Its scheduled time until it publishes. One that waits for its
			// new name's certificate publishes -reality-prepare after it
			// began at most, with its time a lead after that if it comes
			// late: naive publishes in that round, with that time.
			rs := ParseRealityState(all[join])
			d = naiveDue{at: realityNextSwitch(all[join], e), reality: true,
				waits: rs.NextFrom == 0 && rs.PreparedAt != 0 && now < rs.PreparedAt+int64(e.Prepare/time.Second)+joinSlack(e)}
		}
	}
	if state.RotateAt != 0 && state.RotateAt < d.at {
		d = naiveDue{at: state.RotateAt}
	}
	return d
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

// naiveSwitchNow reports whether a naive switch published for from happens
// in the round at t. With a REALITY switch of its site for a time within
// the slack of from, it goes in that switch's round (switched: the REALITY
// switches of this round by site, their times), so up to RealityEarly and
// the slack before from: one render, one restart of the front carries
// both. Otherwise it goes at from, unless such a REALITY switch is still to
// come: then it waits for it, the slack at most. The moment matters to no
// client: the front routes the next name from before its publication, and
// the name before it until the switch after.
func naiveSwitchNow(all []store.Service, svc store.Service, from, t int64, switched map[string][]int64, slack int64) bool {
	site := siteOf(svc)
	if site != "" && slices.ContainsFunc(switched[site], func(at int64) bool { return abs(at-from) <= slack }) {
		return true
	}
	if t < from {
		return false
	}
	return site == "" || !slices.ContainsFunc(all, func(r store.Service) bool {
		if r.Kind != "reality" || !r.Enabled || siteOf(r) != site {
			return false
		}
		rs := ParseRealityState(r)
		return rs.NextFrom != 0 && abs(rs.NextFrom-from) <= slack && t < rs.NextFrom+slack
	})
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// rotateNaive advances the name rotation of one naive service at now;
// switched are the REALITY switches of this round, by site.
func rotateNaive(ctx context.Context, st *store.Store, all []store.Service, svc store.Service, now time.Time, e RealityEpoch,
	switched map[string][]int64, log *slog.Logger) (bool, error) {
	state := ParseNaiveState(svc)
	t := now.Unix()
	if state.SNINext == "" {
		// Without the node's domain there is no name to move to: the
		// name stays, nothing to do (as before R4-42).
		if domain, err := Domain(ctx, st); err != nil || domain == "" {
			return false, err
		}
		// The render picks it first (EnsureNaiveNext); a store no render
		// has read since gets it here, published at a later round only.
		settings, err := naiveNext(ctx, st, all, svc)
		if err != nil {
			return false, err
		}
		return true, st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings})
	}
	lead, slack := int64(e.Lead/time.Second), joinSlack(e)
	changed := false
	if state.NextFrom == 0 {
		due := naiveSwitch(ctx, st, all, svc, state, e, t)
		covered := SiteCovers(ctx, st, all, siteOf(svc), state.SNINext)
		switch {
		case due.at == math.MaxInt64 && state.PreparedAt != 0:
			// Called off (rotate_sni off, the period 0, the operator's switch
			// given up): the certificate no longer needs the name.
			return true, naiveFields(ctx, st, svc, map[string]any{"prepared_at": nil})
		case due.at == math.MaxInt64:
			return false, nil
		case !covered && state.PreparedAt == 0:
			// The site's certificate is asked for the next name: at once,
			// for a scheduled switch an epoch ahead (under listed names it is
			// in CT logs from now: rotate_sni=on chose that), at the request
			// for the operator's.
			log.Info("naive: the next server name waits for its certificate", "service", svc.Name)
			return true, naiveFields(ctx, st, svc, map[string]any{"prepared_at": t})
		case t < due.at-lead:
			return false, nil
		case due.waits:
			// The REALITY it joins waits for its certificate: its time is
			// set at its publication, and this one publishes with it.
			return false, nil
		case !covered && t < max(state.PreparedAt, due.at-lead)+int64(e.Prepare/time.Second):
			return false, nil
		case !covered:
			// Not certified in time: the name stays, for this epoch.
			log.Warn("naive server name stays: the next name got no certificate in time", "service", svc.Name)
			return true, naiveFields(ctx, st, svc, map[string]any{"prepared_at": nil, "rotate_at": nil, "rotated_at": t})
		}
		from := max(due.at, t+lead)
		if due.reality && due.at >= t+lead-slack {
			// REALITY's time exactly, though this round came up to the
			// slack after its lead began: both switch in one round.
			from = due.at
		}
		if state.RotateAt != 0 && state.RotateAt <= t {
			from = t // now: the operator asked for it
		}
		if err := naiveFields(ctx, st, svc, map[string]any{"next_from": from, "prepared_at": nil}); err != nil {
			return false, err
		}
		log.Info("naive: next server name published", "service", svc.Name, "switch", time.Unix(from, 0).UTC())
		var err error
		if svc, err = st.ServiceByName(ctx, svc.Name); err != nil {
			return true, err
		}
		state, changed = ParseNaiveState(svc), true
	}
	// The operator's switch at once: the name is routed already.
	if !naiveSwitchNow(all, svc, state.NextFrom, t, switched, slack) {
		return changed, nil
	}
	return true, switchNaive(ctx, st, all, svc, state, e.NaivePeriod, log)
}

// switchNaive makes the next name current, the current one previous (it
// stays routed until a switch a period after this one, NaivePrevious, as
// the previous ones left within the period before), and chooses the name
// after.
func switchNaive(ctx context.Context, st *store.Store, all []store.Service, svc store.Service, state NaiveState, period time.Duration,
	log *slog.Logger) error {
	name, err := newZone(ctx, st, all)
	if err != nil {
		return err
	}
	kept, dropped := NaivePrevious(state, state.NextFrom, period)
	fields := map[string]any{"sni": state.SNINext, "sni_prev": nil, "sni_older": nil, "sni_next": name, "rotated_at": state.NextFrom,
		"next_from": nil, "rotate_at": nil, "prepared_at": nil}
	if len(kept) > 0 {
		fields["sni_prev"] = kept[0].SNI
	}
	if len(kept) > 1 {
		fields["sni_older"] = kept[1:]
	}
	if err := naiveFields(ctx, st, svc, fields); err != nil {
		return err
	}
	log.Info("naive server name switched; the previous ones are accepted until a switch a period after theirs", "service", svc.Name,
		"previous", retiredNames(kept), "dropped", dropped)
	return nil
}

func naiveFields(ctx context.Context, st *store.Store, svc store.Service, fields map[string]any) error {
	settings, err := setFields(svc.Settings, fields)
	if err != nil {
		return err
	}
	return st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings})
}
