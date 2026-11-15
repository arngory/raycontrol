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
// (a wildcard record) and the site's certificate covers it. By default
// (rotate_sni unset) it moves at a scheduled switch only under a wildcard
// certificate (WildcardSite, R4-42): otherwise the new name would be in CT
// logs days before the switch, beside every other name of the node. A
// switch the operator asks for moves it anyway; rotate_sni on moves it at
// every switch, off at none.

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
	RotateSNI  *bool  `json:"rotate_sni,omitempty"`  // false keeps the server name, true moves it at every switch; unset: auto (RenamesAt)
	RotateAt   int64  `json:"rotate_at,omitempty"`   // switch requested by the operator for this time
	Urgent     bool   `json:"urgent,omitempty"`      // switch at once, the current set not kept (leaked keys)
	PrevUntil  int64  `json:"prev_until,omitempty"`  // the previous set is accepted until then (R4-19)
	SNIPrev    string `json:"sni_prev,omitempty"`    // the server name of the previous set, routed by the front until the next switch
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

// ShownSettings are the settings of a service as shown outside rayd (the
// API's services, to remote admins too): without a next server name not
// yet published, REALITY's waiting for its certificate, naive's chosen an
// epoch ahead (R4-42). The front routes naive's from then, and under a
// wildcard certificate nothing else names it until a client sends it: a
// listing pasted into a ticket must not either. prepared_at stays: a time,
// no name (rayctl says from it that a next name waits for its
// certificate), and under listed names the name is in CT logs with its
// order anyway.
func ShownSettings(svc store.Service) string {
	if svc.Kind != "reality" && svc.Kind != "naive" {
		return svc.Settings
	}
	var st struct {
		SNINext  string `json:"sni_next"`
		NextFrom int64  `json:"next_from"`
	}
	if err := json.Unmarshal([]byte(svc.Settings), &st); err != nil || st.SNINext == "" || st.NextFrom != 0 {
		return svc.Settings
	}
	shown, err := setFields(svc.Settings, map[string]any{"sni_next": nil})
	if err != nil {
		return "{}"
	}
	return shown
}

// RealityEpoch is the schedule of REALITY key rotation, and of naive's
// name (R4-42), which shares its lead and preparation.
type RealityEpoch struct {
	Period  time.Duration // a key set is current this long
	Lead    time.Duration // the next set is in subscriptions this long before the switch
	Prepare time.Duration // a new server name may take this long to get its certificate
	Grace   time.Duration // the previous set is accepted this long after the switch (0: not at all)
	// NaivePeriod: a naive name is current this long (0: it changes only
	// when the operator asks). The previous name needs no grace: it is
	// accepted until the next switch.
	NaivePeriod time.Duration
}

// Check reports a schedule that cannot work.
func (e RealityEpoch) Check() error {
	if e.Period > 0 && e.Lead+e.Prepare >= e.Period {
		return errors.New("REALITY rotation: lead and preparation must be shorter than the period")
	}
	if e.NaivePeriod > 0 && e.Lead+e.Prepare >= e.NaivePeriod {
		return errors.New("naive name rotation: lead and preparation must be shorter than the period")
	}
	return nil
}

// settingsMu serializes what rewrites the settings of a service from what
// it read: the rotations (REALITY keys, seal keys) and the operator's
// requests (rotate, set), so that none undoes another's change.
var settingsMu sync.Mutex

// RotateReality advances the key rotation of every enabled REALITY service
// at now, then the name rotation of every enabled naive service (R4-42):
// in one round, so that a naive switch joined to REALITY's happens with it,
// and one render, one restart of the front, carries both. It returns how
// many changed. resolves checks that a name points to the node; nil keeps
// REALITY's server names. With a zero period only the switches the
// operator asks for happen. A service that fails is skipped: the error
// names it, and the others still rotate.
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
	// One service that fails does not hold the others' rotation back
	// (review Q-4): its error is returned with the count of those that
	// changed.
	changed := 0
	var errs []error
	// The REALITY switches of this round, their times by site: a naive
	// switch for about that time goes in this round with them.
	switched := map[string][]int64{}
	for _, svc := range all {
		if svc.Kind != "reality" || !svc.Enabled {
			continue
		}
		ok, err := rotateOne(ctx, st, all, svc, now, e, resolves, log)
		if err != nil {
			errs = append(errs, fmt.Errorf("reality %s: %w", svc.Name, err))
			continue
		}
		if ok {
			changed++
			// A name chosen in this round is taken for the next service.
			if all, err = st.ListServices(ctx); err != nil {
				return changed, errors.Join(append(errs, err)...)
			}
			before := ParseRealityState(svc)
			if i := slices.IndexFunc(all, func(s store.Service) bool { return s.ID == svc.ID }); i >= 0 && before.NextFrom != 0 {
				if after := ParseRealityState(all[i]); after.NextFrom == 0 && after.RotatedAt == before.NextFrom {
					switched[siteOf(svc)] = append(switched[siteOf(svc)], before.NextFrom)
				}
			}
		}
	}
	for _, s := range all {
		if s.Kind != "naive" || !s.Enabled {
			continue
		}
		// The list as it is now: with REALITY's switches of this round,
		// and a name chosen for a service in it taken for the next.
		current, err := st.ListServices(ctx)
		if err != nil {
			return changed, errors.Join(append(errs, err)...)
		}
		i := slices.IndexFunc(current, func(c store.Service) bool { return c.ID == s.ID })
		if i < 0 {
			continue
		}
		svc := current[i]
		ok, err := rotateNaive(ctx, st, current, svc, now, e, switched, log)
		if err != nil {
			errs = append(errs, fmt.Errorf("naive %s: %w", svc.Name, err))
			continue
		}
		if ok {
			changed++
		}
	}
	return changed, errors.Join(errs...)
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
		rename := false
		if site := siteOf(svc); site != "" && resolves != nil {
			rename = RenamesAt(ctx, st, all, site, state.RotateSNI, state.RotateAt != 0)
			domain, _ := Domain(ctx, st)
			switch {
			case !rename && domain == "":
				log.Info("REALITY server name stays: the node has no domain for a new one (rayd init -domain)", "service", svc.Name)
			case !rename && state.RotateSNI == nil:
				log.Info("REALITY server name stays: its site has no wildcard certificate (R4-42; rotate_sni=on moves it all the same)",
					"service", svc.Name)
			}
		}
		if rename {
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

// dropPrevReality ends the grace period of the previous set. Its name stays
// in the front's route until the next switch (render): the end of the grace
// changes no route, so it restarts no front.
func dropPrevReality(ctx context.Context, st *store.Store, svc store.Service, log *slog.Logger) error {
	settings, err := setFields(svc.Settings, map[string]any{"prev_until": nil})
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

// RequestRotation asks for the next switch of a service, a lead time away
// (clients get what is next first) or at once:
//
//   - REALITY's keys (and its server name, self-steal): at once, clients
//     that have not fetched their subscription since lose the profile
//     until they do (leaked keys, a blocked name);
//   - naive's server name (R4-42), whatever rotate_sni says: at once, the
//     previous name stays accepted until a switch a period after its own
//     (NaivePrevious; no secret leaked), and clients move with their next
//     subscription.
//
// Under a certificate of listed names (HTTP-01) the new name waits for its
// certificate first, -reality-prepare at most.
func RequestRotation(ctx context.Context, st *store.Store, name string, now time.Time, lead time.Duration, immediately bool) error {
	_, err := RequestRotationNames(ctx, st, name, now, lead, immediately, 0)
	return err
}

// NaiveSwitchNames are what a naive switch asked for does to the previous
// names, were it at the time asked (later, a name may be older than the
// period by then): Kept stay routed after it, newest first (the name in
// use now first), Dropped leave the front.
type NaiveSwitchNames struct {
	Kept, Dropped []string
}

// RequestRotationNames is RequestRotation, and for naive what the switch
// does to its previous names under -naive-sni-period (0: the default).
func RequestRotationNames(ctx context.Context, st *store.Store, name string, now time.Time, lead time.Duration, immediately bool,
	naivePeriod time.Duration) (NaiveSwitchNames, error) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		return NaiveSwitchNames{}, err
	}
	if svc.Kind == "slipstream" {
		// One certificate a server, one pin a client: a new key would cut
		// every client off until its next subscription.
		return NaiveSwitchNames{}, fmt.Errorf("%w: %s (slipstream) has no rotation: its clients pin the server's one key (spec/slipstream-v1.md §3); a new key is a new service", store.ErrInvalid, name)
	}
	if svc.Kind != "reality" && svc.Kind != "naive" {
		return NaiveSwitchNames{}, fmt.Errorf("%w: %s is neither REALITY nor naive (rotation: reality, naive's name, dnstt's seal key, masterdns's key, a site's certificate key)", store.ErrInvalid, name)
	}
	if svc.Kind == "naive" {
		// naive's switch is its name's, and a new name is a subdomain of
		// the node's domain: none to move to without one.
		domain, err := Domain(ctx, st)
		if err != nil {
			return NaiveSwitchNames{}, err
		}
		if domain == "" {
			return NaiveSwitchNames{}, fmt.Errorf("%w: %s keeps its server name %s: the node has no domain, and a new name would be a subdomain of it "+
				"(rayd init -domain DOMAIN, with *.DOMAIN pointing to the node, gives naive names to move to)", store.ErrInvalid, name, SiteName(svc))
		}
	}
	at := now.Add(lead)
	if immediately {
		at = now
	}
	fields := map[string]any{"rotate_at": at.Unix()}
	published := ParseRealityState(svc).NextFrom // naive's next_from alike
	if immediately && svc.Kind == "reality" {
		// Nothing of the current set stays after the switch (R4-19).
		fields["urgent"] = true
	}
	switchAt := at.Unix()
	if published != 0 && at.Unix() < published {
		fields["next_from"] = max(at.Unix(), now.Unix()) // a published switch only moves earlier
	}
	if published != 0 {
		switchAt = min(switchAt, published)
	}
	var names NaiveSwitchNames
	if svc.Kind == "naive" {
		kept, dropped := NaivePrevious(ParseNaiveState(svc), switchAt, naivePeriod)
		names = NaiveSwitchNames{Kept: retiredNames(kept), Dropped: dropped}
	}
	settings, err := setFields(svc.Settings, fields)
	if err != nil {
		return NaiveSwitchNames{}, err
	}
	return names, st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings})
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
// those of the services under it, with the previous names still accepted
// (names), and the names REALITY and naive move to at their next switch
// (next). naive's next name is asked for only once its switch wants it
// (prepared_at, R4-42) or it is published: under listed names (HTTP-01) a
// name in the certificate is in CT logs from its order, and one a client
// may never use should not be.
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
		if s.Kind == "naive" && s.Enabled && siteOf(s) == site.Name {
			// The previous names while routed (NaivePrevious): a client
			// on one checks the certificate against it.
			state := ParseNaiveState(s)
			for _, n := range state.Previous() {
				names = add(names, n)
			}
			switch {
			case state.NextFrom != 0:
				// Published: clients may take it from now (up to 2 minutes
				// before its time, or when link fails), and a renewal that
				// lost it would fail them.
				names = add(names, state.SNINext)
			case state.PreparedAt != 0:
				next = add(next, state.SNINext)
			}
		}
	}
	return names, next
}

// RenamesAt reports whether a switch moves a server name to a new one
// (REALITY R4-7, naive R4-42), by the service's rotate_sni: on (true) at
// every switch, off (false) at none; unset (auto) at a switch the operator
// asked for, and at a scheduled one only when the site's names come under
// a wildcard certificate (WildcardSite). Under a certificate of listed
// names (HTTP-01) the new name would be in CT logs from its order, days
// before clients use it, in one list with every other name of the node.
//
// Never on a node without a domain: a new name is a subdomain of it, so
// there is none to move to (newZone), and the name stays as the operator
// gave it.
func RenamesAt(ctx context.Context, st *store.Store, all []store.Service, site string, rotateSNI *bool, asked bool) bool {
	if domain, err := Domain(ctx, st); err != nil || domain == "" {
		return false
	}
	if rotateSNI != nil {
		return *rotateSNI
	}
	return asked || WildcardSite(ctx, st, all, site)
}

// WildcardSite reports whether the names of a site come under one
// certificate *.<domain>, so that a new name of the node shows in no CT
// log (R4-10): the site's certificate is one, or the node orders through
// DNS-01 (a Cloudflare token) and every name of the site is one label under
// the domain, as the certificate manager then orders *.<domain> alone.
func WildcardSite(ctx context.Context, st *store.Store, all []store.Service, site string) bool {
	domain, err := Domain(ctx, st)
	if err != nil || domain == "" {
		return false
	}
	i := slices.IndexFunc(all, func(s store.Service) bool { return s.Kind == "site" && s.Name == site })
	if i < 0 {
		return false
	}
	if secrets, err := st.ServiceSecrets(ctx, all[i].ID); err == nil && chainNames(secrets[SecretTLSChain], "*."+domain) {
		return true
	}
	if c, _, err := Cloudflare(ctx, st); err != nil || c == nil {
		return false
	}
	names, next := SiteNames(all[i], all)
	return UnderWildcard(append(names, next...), domain)
}

// UnderWildcard reports whether *.domain covers every name: each one label
// below the domain.
func UnderWildcard(names []string, domain string) bool {
	for _, n := range names {
		label, ok := strings.CutSuffix(CanonicalZone(n), "."+CanonicalZone(domain))
		if !ok || label == "" || strings.Contains(label, ".") {
			return false
		}
	}
	return len(names) > 0
}

// chainNames reports whether the leaf of a PEM chain lists name as it is
// (a wildcard name too).
func chainNames(chainPEM []byte, name string) bool {
	block, _ := pem.Decode(chainPEM)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	return err == nil && slices.ContainsFunc(leaf.DNSNames, func(n string) bool { return strings.EqualFold(n, name) })
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
	if err := requirements(all[i], all, false); err != nil {
		return err
	}
	// Zones kept from before they were checked (v0.13 took nested ones):
	// enabled together, the front would refuse its whole config.
	var enabled []store.Service
	for _, o := range all {
		if o.Enabled && o.Name != name {
			enabled = append(enabled, o)
		}
	}
	for _, z := range Zones(all[i]) {
		if other := zoneConflict(z, enabled); other != "" {
			return fmt.Errorf("%w: zone %s of %s is, or nests with, a zone of %s, which is enabled: a name under both would be either's", store.ErrInvalid, z, name, other)
		}
	}
	return nil
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
