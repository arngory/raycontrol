package provision

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// REALITY keys rotate in epochs (docs/08-decisions.md, R4-7): the next set
// (X25519 and ML-DSA-65 keys, the ML-KEM-768 seed of the second layer,
// shortIds and, with the node's own site, the server name) goes into
// subscriptions a lead time before the switch and replaces the current one
// at the switch. Xray holds one private key per inbound, so the previous set
// gets a second inbound for a grace period (R4-19): the current inbound
// hands it what it does not recognise, in place of the site, and it hands
// the site what it does not recognise in turn.
//
// The server name only ever moves to another random subdomain of the
// node's own domain (self-steal): nothing outside the node is looked up,
// scanned or borrowed. It moves only when the new name resolves to the node
// (a wildcard record) and the site's certificate covers it.

// RealitySecrets are the secrets of one REALITY key set.
var RealitySecrets = []string{SecretRealityKey, SecretRealityMLDSA, SecretMLKEMSeed, SecretShortIDs}

// NextSecret is the name of the next value of a secret.
func NextSecret(name string) string { return name + ".next" }

// PrevSecret is the name of the previous value of a secret, kept for the
// grace period after a switch (R4-19).
func PrevSecret(name string) string { return name + ".prev" }

// RealityEarly is how long before its time a switch happens when the
// previous keys stay accepted: a client that moves at the time on a clock a
// little ahead finds the new keys, and one that has not moved yet still gets
// in with the previous ones (REALITY allows clocks 2 minutes apart).
const RealityEarly = 2 * time.Minute

// RealityState is the rotation state in the settings of a REALITY service.
type RealityState struct {
	RotatedAt  int64  `json:"rotated_at,omitempty"`  // last switch; the service's creation before the first
	PreparedAt int64  `json:"prepared_at,omitempty"` // next keys made, waiting for the name's certificate
	NextFrom   int64  `json:"next_from,omitempty"`   // next keys published, switch at this time
	SNINext    string `json:"sni_next,omitempty"`    // the server name after the switch, if it changes
	RotateSNI  *bool  `json:"rotate_sni,omitempty"`  // false keeps the server name
	RotateAt   int64  `json:"rotate_at,omitempty"`   // switch requested by the operator for this time
	Urgent     bool   `json:"urgent,omitempty"`      // switch at once, the current set not kept (leaked keys)
	PrevUntil  int64  `json:"prev_until,omitempty"`  // the previous set is accepted until then (R4-19)
	SNIPrev    string `json:"sni_prev,omitempty"`    // the server name of the previous set
}

// ParseRealityState reads the rotation state of a service.
func ParseRealityState(svc store.Service) RealityState {
	var st RealityState
	_ = json.Unmarshal([]byte(svc.Settings), &st)
	if st.RotatedAt == 0 {
		st.RotatedAt = svc.CreatedAt.Unix()
	}
	return st
}

// RealityEpoch is the schedule of REALITY key rotation.
type RealityEpoch struct {
	Period  time.Duration // a key set is current this long
	Lead    time.Duration // the next set is in subscriptions this long before the switch
	Prepare time.Duration // a new server name may take this long to get its certificate
	Grace   time.Duration // the previous set is accepted this long after the switch (0: not at all)
}

// Check reports a schedule that cannot work.
func (e RealityEpoch) Check() error {
	if e.Period > 0 && e.Lead+e.Prepare >= e.Period {
		return errors.New("REALITY rotation: lead and preparation must be shorter than the period")
	}
	return nil
}

// settingsMu serializes what rewrites the settings of a service from what
// it read: the rotations (REALITY keys, seal keys) and the operator's
// requests (rotate, set), so that none undoes another's change.
var settingsMu sync.Mutex

// RotateReality advances the key rotation of every enabled REALITY service
// at now and returns how many changed. resolves checks that a name points
// to the node; nil keeps the server names. With a zero period only the
// switches the operator asks for happen.
func RotateReality(ctx context.Context, st *store.Store, now time.Time, e RealityEpoch,
	resolves func(ctx context.Context, name string) error, log *slog.Logger) (int, error) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	if log == nil {
		log = slog.Default()
	}
	all, err := st.ListServices(ctx)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, svc := range all {
		if svc.Kind != "reality" || !svc.Enabled {
			continue
		}
		ok, err := rotateOne(ctx, st, all, svc, now, e, resolves, log)
		if err != nil {
			return changed, fmt.Errorf("reality %s: %w", svc.Name, err)
		}
		if ok {
			changed++
		}
	}
	return changed, nil
}

func rotateOne(ctx context.Context, st *store.Store, all []store.Service, svc store.Service, now time.Time, e RealityEpoch,
	resolves func(ctx context.Context, name string) error, log *slog.Logger) (bool, error) {
	state := ParseRealityState(svc)
	t := now.Unix()
	// The switch is due a period after the last one, or when the operator
	// asked for it.
	due := int64(math.MaxInt64)
	if e.Period > 0 {
		due = state.RotatedAt + int64(e.Period/time.Second)
	}
	if state.RotateAt != 0 {
		due = min(due, state.RotateAt)
	}
	lead := int64(e.Lead / time.Second)
	early := int64(0)
	if e.Grace > 0 {
		early = int64(RealityEarly / time.Second)
	}

	switch {
	case state.NextFrom != 0 && t >= state.NextFrom-early:
		grace := e.Grace
		if state.Urgent {
			grace = 0 // leaked keys or a blocked name: nothing of the old set stays
		}
		return true, switchReality(ctx, st, all, svc, state, grace, log)

	case state.PrevUntil != 0 && t >= state.PrevUntil:
		return true, dropPrevReality(ctx, st, svc, log)

	case state.NextFrom != 0:
		return false, nil

	case state.PreparedAt != 0:
		if state.SNINext != "" && !SiteCovers(ctx, st, all, siteOf(svc), state.SNINext) {
			if t < state.PreparedAt+int64(e.Prepare/time.Second) {
				return false, nil
			}
			log.Warn("REALITY server name stays: the new name got no certificate in time", "service", svc.Name)
			state.SNINext = ""
		}
		return true, publishReality(ctx, st, svc, state, max(due, t+lead), t)

	case due != math.MaxInt64 && t >= due-lead-int64(e.Prepare/time.Second):
		next := map[string][]byte{}
		if err := realitySecrets(next); err != nil {
			return false, err
		}
		set := map[string][]byte{}
		for name, v := range next {
			set[NextSecret(name)] = v
		}
		state.PreparedAt = t
		if site := siteOf(svc); site != "" && resolves != nil && (state.RotateSNI == nil || *state.RotateSNI) {
			name, err := newZone(ctx, st, all)
			if err != nil {
				return false, err
			}
			if err := resolves(ctx, name); err != nil {
				log.Info("REALITY server name stays: a new subdomain does not resolve to the node (add a wildcard record *.<domain>)",
					"service", svc.Name, "err", err)
			} else {
				state.SNINext = name
			}
		}
		settings, err := setFields(svc.Settings, map[string]any{"prepared_at": state.PreparedAt, "sni_next": state.SNINext})
		if err != nil {
			return false, err
		}
		if err := st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings, Set: set}); err != nil {
			return false, err
		}
		svc.Settings = settings
		if state.SNINext == "" {
			// Nothing to wait for: publish at once.
			return true, publishReality(ctx, st, svc, state, max(due, t+lead), t)
		}
		log.Info("REALITY rotation prepared, waiting for the certificate of the new name", "service", svc.Name)
		return true, nil
	}
	return false, nil
}

// publishReality puts the next set into subscriptions with its switch time.
func publishReality(ctx context.Context, st *store.Store, svc store.Service, state RealityState, from, now int64) error {
	if state.RotateAt != 0 && state.RotateAt <= now {
		from = now // switch now: the operator asked for it
	}
	settings, err := setFields(svc.Settings, map[string]any{"next_from": from, "sni_next": state.SNINext})
	if err != nil {
		return err
	}
	return st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings})
}

// switchReality makes the next set current; with a new server name, the
// site follows when it had the old one. With a grace period the current
// set becomes the previous one until then (R4-19).
func switchReality(ctx context.Context, st *store.Store, all []store.Service, svc store.Service, state RealityState,
	grace time.Duration, log *slog.Logger) error {
	secrets, err := st.ServiceSecrets(ctx, svc.ID)
	if err != nil {
		return err
	}
	u := store.ServiceUpdate{Set: map[string][]byte{}}
	for _, name := range RealitySecrets {
		v, ok := secrets[NextSecret(name)]
		if !ok {
			// Lost (a restored backup?): start the round again.
			log.Warn("REALITY next keys are missing, preparing new ones", "service", svc.Name)
			settings, err := setFields(svc.Settings, map[string]any{"prepared_at": nil, "next_from": nil, "sni_next": nil})
			if err != nil {
				return err
			}
			return st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings})
		}
		u.Set[name] = v
		u.Delete = append(u.Delete, NextSecret(name))
	}
	var old struct {
		SNI string `json:"sni"`
	}
	_ = json.Unmarshal([]byte(svc.Settings), &old)
	fields := map[string]any{"rotated_at": state.NextFrom, "prepared_at": nil, "next_from": nil, "sni_next": nil, "rotate_at": nil,
		"urgent": nil, "prev_until": nil, "sni_prev": nil}
	if state.SNINext != "" {
		fields["sni"] = state.SNINext
	}
	for _, name := range RealitySecrets {
		if v, ok := secrets[name]; ok && grace > 0 {
			u.Set[PrevSecret(name)] = v
		} else {
			u.Delete = append(u.Delete, PrevSecret(name))
		}
	}
	if grace > 0 {
		fields["prev_until"] = state.NextFrom + int64(grace/time.Second)
		fields["sni_prev"] = old.SNI
	}
	if u.Settings, err = setFields(svc.Settings, fields); err != nil {
		return err
	}
	if err := st.UpdateService(ctx, svc.ID, u); err != nil {
		return err
	}
	log.Info("REALITY keys switched", "service", svc.Name, "name_changed", state.SNINext != "")
	if state.SNINext == "" {
		return nil
	}
	for _, s := range all {
		if s.Kind == "site" && s.Name == siteOf(svc) && SiteName(s) == old.SNI {
			settings, err := setFields(s.Settings, map[string]any{"sni": state.SNINext})
			if err != nil {
				return err
			}
			return st.UpdateService(ctx, s.ID, store.ServiceUpdate{Settings: settings})
		}
	}
	return nil
}

// dropPrevReality ends the grace period of the previous set.
func dropPrevReality(ctx context.Context, st *store.Store, svc store.Service, log *slog.Logger) error {
	settings, err := setFields(svc.Settings, map[string]any{"prev_until": nil, "sni_prev": nil})
	if err != nil {
		return err
	}
	u := store.ServiceUpdate{Settings: settings}
	for _, name := range RealitySecrets {
		u.Delete = append(u.Delete, PrevSecret(name))
	}
	log.Info("REALITY previous keys no longer accepted", "service", svc.Name)
	return st.UpdateService(ctx, svc.ID, u)
}

// RequestRealityRotation asks for the next switch of a REALITY service:
// a lead time away (clients get the next keys first), or at once (clients
// that have not fetched their subscription since lose the profile until
// they do; for leaked keys or a blocked name).
func RequestRealityRotation(ctx context.Context, st *store.Store, name string, now time.Time, lead time.Duration, immediately bool) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		return err
	}
	if svc.Kind != "reality" {
		return fmt.Errorf("%w: %s is not a REALITY service", store.ErrInvalid, name)
	}
	at := now.Add(lead)
	if immediately {
		at = now
	}
	fields := map[string]any{"rotate_at": at.Unix()}
	if immediately {
		// Nothing of the current set stays after the switch (R4-19).
		fields["urgent"] = true
	}
	if state := ParseRealityState(svc); state.NextFrom != 0 && at.Unix() < state.NextFrom {
		fields["next_from"] = max(at.Unix(), now.Unix()) // a published switch only moves earlier
	}
	settings, err := setFields(svc.Settings, fields)
	if err != nil {
		return err
	}
	return st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings})
}

// SiteOf returns the node's site a service relies on: the one REALITY
// steals from ("" for a foreign target), the one whose certificate
// Hysteria2 uses.
func SiteOf(svc store.Service) string { return siteOf(svc) }

func siteOf(svc store.Service) string {
	var s struct {
		Site string `json:"site"`
	}
	_ = json.Unmarshal([]byte(svc.Settings), &s)
	return s.Site
}

// SiteNames returns the names a site's certificate covers: its own and
// those of the REALITY services that steal from it (names), and the names
// they move to at their next switch (next).
func SiteNames(site store.Service, all []store.Service) (names, next []string) {
	add := func(list []string, n string) []string {
		if n != "" && !slices.Contains(names, n) && !slices.Contains(next, n) {
			list = append(list, n)
		}
		return list
	}
	names = add(names, SiteName(site))
	// Every service under this site's certificate: REALITY, hy2-masq, DoH.
	for _, s := range all {
		if s.Kind != "site" && s.Enabled && siteOf(s) == site.Name {
			var cur struct {
				SNI string `json:"sni"`
			}
			_ = json.Unmarshal([]byte(s.Settings), &cur)
			names = add(names, cur.SNI)
		}
	}
	for _, s := range all {
		if s.Kind == "reality" && s.Enabled && siteOf(s) == site.Name {
			state := ParseRealityState(s)
			// The previous name while its keys are accepted (R4-19): a probe
			// under it still meets the site's own certificate.
			if state.PrevUntil != 0 {
				names = add(names, state.SNIPrev)
			}
			next = add(next, state.SNINext)
		}
	}
	return names, next
}

// SiteCovers reports whether the certificate of a site covers name.
func SiteCovers(ctx context.Context, st *store.Store, all []store.Service, site, name string) bool {
	for _, s := range all {
		if s.Kind != "site" || s.Name != site {
			continue
		}
		secrets, err := st.ServiceSecrets(ctx, s.ID)
		if err != nil {
			return false
		}
		return ChainCovers(secrets[SecretTLSChain], name)
	}
	return false
}

// ChainCovers reports whether the leaf of a PEM chain is for name, by one
// of its names or a wildcard.
func ChainCovers(chainPEM []byte, name string) bool {
	block, _ := pem.Decode(chainPEM)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	return err == nil && leaf.VerifyHostname(name) == nil
}

// setFields sets fields of a settings object, deleting those set to nil
// or to their zero value.
func setFields(settings string, fields map[string]any) (string, error) {
	m := map[string]any{}
	if settings != "" {
		if err := json.Unmarshal([]byte(settings), &m); err != nil {
			return "", err
		}
	}
	for k, v := range fields {
		switch v {
		case nil, "", int64(0):
			delete(m, k)
		default:
			m[k] = v
		}
	}
	b, err := json.Marshal(m)
	return string(b), err
}

// Dependents are the enabled services that work through the service name:
// the DNS tunnels and Yggdrasil through inner, the services of a site
// through that site. Disabling or deleting it while they are on would leave
// them unrenderable (Q-1).
func Dependents(ctx context.Context, st *store.Store, name string) ([]string, error) {
	all, err := st.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(all, func(s store.Service) bool { return s.Name == name })
	if i < 0 {
		return nil, nil // the store says not found
	}
	target := all[i]
	var out []string
	for _, s := range all {
		if !s.Enabled || s.Name == name {
			continue
		}
		switch {
		case target.Kind == "inner" && NeedsInner(s.Kind),
			target.Kind == "site" && siteOf(s) == name:
			out = append(out, s.Name)
		}
	}
	return out, nil
}

// CheckRequirements refuses to turn on a service whose stage is off: what
// exits through inner while inner is disabled or missing, a REALITY whose
// decoy site is disabled or missing. It would not render (Q-1).
func CheckRequirements(ctx context.Context, st *store.Store, name string) error {
	all, err := st.ListServices(ctx)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(all, func(s store.Service) bool { return s.Name == name })
	if i < 0 {
		return nil // the store says not found
	}
	return requirements(all[i], all, false)
}

// requirements checks svc against the others; creating allows a missing
// inner, which CreateService then adds.
func requirements(svc store.Service, all []store.Service, creating bool) error {
	if NeedsInner(svc.Kind) {
		i := slices.IndexFunc(all, func(s store.Service) bool { return s.Kind == "inner" })
		switch {
		case i >= 0 && !all[i].Enabled:
			return fmt.Errorf("%w: %s works through %s, which is disabled: enable it first", store.ErrInvalid, svc.Name, all[i].Name)
		case i < 0 && !creating:
			return fmt.Errorf("%w: %s works through the inner stage, which is missing", store.ErrInvalid, svc.Name)
		}
	}
	if site := siteOf(svc); site != "" {
		i := slices.IndexFunc(all, func(s store.Service) bool { return s.Name == site })
		switch {
		case i < 0:
			return fmt.Errorf("%w: %s works through the site %s, which is missing", store.ErrInvalid, svc.Name, site)
		case !all[i].Enabled:
			return fmt.Errorf("%w: %s works through %s, which is disabled: enable it first", store.ErrInvalid, svc.Name, site)
		}
	}
	return nil
}

// CheckNoDependents refuses to take away a service others work through.
func CheckNoDependents(ctx context.Context, st *store.Store, name string) error {
	deps, err := Dependents(ctx, st, name)
	if err != nil {
		return err
	}
	if len(deps) > 0 {
		return fmt.Errorf("%w: %s works through %s: disable or delete it first", store.ErrInvalid, strings.Join(deps, ", "), name)
	}
	return nil
}
