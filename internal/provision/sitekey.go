package provision

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// The key of a site's certificate (spec/cert-pin-v1.md). naive, hy2-masq
// and DoH answer with the site's certificate, and their lines carry pins
// (niko-pin): of the key of the certificate in use, of the next key, made
// ahead, and for an hour after a switch of the key before. A client takes
// a leaf with one of these keys and no other, whatever CA signed it, so:
//
//   - an issuance keeps the key: a renewal or new names change no pin;
//   - the key changes only to the next one, and only once that has been in
//     subscriptions for the lead: when the operator asks (rayctl service
//     rotate SITE) or by itself, at an issuance, once the key is a period
//     old;
//   - the switch makes a new next key, whose lead starts then;
//   - a key the operator no longer trusts, with the next one beside it in
//     the same store, gives way to one made for that order (-fresh), which
//     no client holds: the cut is the price.
//
// Only rayd's certificate manager makes the next key. Where it does not
// run (no ACME), and for a certificate the operator imported (rayctl
// service cert), the node cannot promise the key of the next certificate:
// there is no next key in use, and the lines carry no pins.

// The defaults of rayd's -site-key-period and -site-key-lead.
const (
	DefaultSiteKeyPeriod = 180 * 24 * time.Hour
	DefaultSiteKeyLead   = 14 * 24 * time.Hour
)

// SiteKeyMinAge is how long a subscription lives (sub.Lifetime; sub's
// tests keep the two equal): a client may still use the list it fetched
// that long ago. A key in subscriptions for less is missing from lists in
// use, so the lead is never shorter, and a forced switch is refused while
// the key it would leave is younger: the key it would move to was made
// with that one.
const SiteKeyMinAge = 72 * time.Hour

// forceAnyAge drops the age rule of a forced switch (UnsafeForceSwitchAtAnyAge).
var forceAnyAge atomic.Bool

// UnsafeForceSwitchAtAnyAge lets a forced switch leave a key of any age,
// for a test stand that walks through both switches in minutes (rayd serve
// -supervise with RAYCONTROL_UNSAFE_SITE_KEY_FORCE_ANY_AGE). Never on a node
// in use: there the rule is what keeps a repeated -force from cutting
// every client that has not fetched its subscription since.
func UnsafeForceSwitchAtAnyAge() { forceAnyAge.Store(true) }

// forceMinAge is how old the key in use must be for a forced switch.
func forceMinAge() time.Duration {
	if forceAnyAge.Load() {
		return 0
	}
	return SiteKeyMinAge
}

// SitePrevPinFor is how long the pin of the key before stays in the lists
// after a switch that was not forced. The processes take the new
// certificate seconds to minutes after it is stored; a client that fetches
// its subscription in between holds the new list and meets the old leaf.
const SitePrevPinFor = time.Hour

// SiteKeyPolicy is when a site's key changes by itself.
type SiteKeyPolicy struct {
	// Period: at an issuance the key gives way to the next one once it has
	// been current this long (0: only when the operator asks).
	Period time.Duration
	// Lead: and only when the next key has been in subscriptions this long.
	Lead time.Duration
}

// Check reports a schedule that cannot work.
func (p SiteKeyPolicy) Check() error {
	switch {
	case p.Period < 0 || p.Lead < 0:
		return errors.New("site key rotation: the period and the lead cannot be negative")
	case p.Lead < SiteKeyMinAge:
		return fmt.Errorf("site key rotation: the lead must be at least %v, a subscription's lifetime: clients use a list that old", SiteKeyMinAge)
	case p.Period > 0 && p.Lead >= p.Period:
		return errors.New("site key rotation: the lead must be shorter than the period")
	}
	return nil
}

// How the operator asked for a switch (SiteKeyState.RotateHow).
const (
	SiteSwitchLead  = ""      // the next key has had its lead
	SiteSwitchForce = "force" // to the next key before its lead: the key in use leaked
	SiteSwitchFresh = "fresh" // to a key made for the order: the store leaked, the next key with it
)

// SiteKeyState is the key rotation state in the settings of a site.
type SiteKeyState struct {
	KeyAt   int64  `json:"tls_key_at,omitempty"`   // the key in use is current since then
	NextAt  int64  `json:"tls_next_at,omitempty"`  // the next key is in subscriptions since then
	NextPin string `json:"tls_next_pin,omitempty"` // the next key's pin, a public value
	// The operator asked for a switch then and rayd has not made it yet;
	// to the next key of that pin, unless a fresh key was asked for.
	RotateAt  int64  `json:"tls_rotate_at,omitempty"`
	RotatePin string `json:"tls_rotate_pin,omitempty"`
	RotateHow string `json:"tls_rotate_how,omitempty"`
	// The pin of the key before the last switch, in the lists until then.
	// The pin only: the key itself is gone with the switch.
	PrevPin   string `json:"tls_prev_pin,omitempty"`
	PrevUntil int64  `json:"tls_prev_until,omitempty"`
	Imported  bool   `json:"tls_imported,omitempty"` // the certificate is the operator's own (SetCertificate)
}

// ParseSiteKeyState reads the key rotation state of a site.
func ParseSiteKeyState(svc store.Service) SiteKeyState {
	var s SiteKeyState
	_ = json.Unmarshal([]byte(svc.Settings), &s)
	return s
}

// ErrSiteChanged is StoreSiteCertificate's refusal: the site's certificate
// or keys are not the ones the order was planned with.
var ErrSiteChanged = errors.New("the site's certificate or keys changed during the order")

// newSiteKey makes a key for a site's certificate. RSA: its longer chain
// fits REALITY with ML-DSA-65 (R2-8, R2-12).
func newSiteKey() (crypto.Signer, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	return key, der, err
}

func parseSiteKey(der []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("the site's key is not a signer")
	}
	return signer, nil
}

// PublicKeyPin is base64url(SHA-256(SubjectPublicKeyInfo)) of a public
// key: what SPKIPin gives for a certificate of that key.
func PublicKeyPin(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// siteLeaf is the leaf of a site's stored chain.
func siteLeaf(secrets map[string][]byte) (*x509.Certificate, bool) {
	block, _ := pem.Decode(secrets[SecretTLSChain])
	if block == nil {
		return nil, false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	return leaf, err == nil
}

// leafPin is the pin of a certificate's key, from the bytes clients hash.
func leafPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// nextKeyPin is the pin of a site's next key: the one stored when the key
// was made (subscriptions ask for every line; parsing an RSA key each time
// costs), or, for a key from before the pin was stored, from the key.
func nextKeyPin(state SiteKeyState, secrets map[string][]byte) (string, bool) {
	der := secrets[NextSecret(SecretTLSKey)]
	if len(der) == 0 {
		return "", false
	}
	if state.NextPin != "" {
		return state.NextPin, true
	}
	key, err := parseSiteKey(der)
	if err != nil {
		return "", false
	}
	pin, err := PublicKeyPin(key.Public())
	return pin, err == nil
}

// SiteKeyPins are the pins of a site's certificate for the lines of the
// services under it at now (niko-pin, spec/cert-pin-v1.md §2): first the
// key of the leaf in use, then the next key, then, for SitePrevPinFor
// after a switch that was not forced, the key before. None for a site
// without a certificate, with the operator's own, or without a next key
// (no certificate manager): the node promises nothing about the key of the
// certificate after this one there.
//
// svc and secrets must be one read (store.ServicesWithSecrets): the
// settings say whose the certificate is.
func SiteKeyPins(svc store.Service, secrets map[string][]byte, now time.Time) []string {
	state := ParseSiteKeyState(svc)
	if svc.Kind != "site" || state.Imported {
		return nil
	}
	leaf, ok := siteLeaf(secrets)
	if !ok {
		return nil
	}
	next, ok := nextKeyPin(state, secrets)
	cur := leafPin(leaf)
	if !ok || next == cur {
		return nil
	}
	pins := []string{cur, next}
	if state.PrevPin != "" && now.Unix() < state.PrevUntil && !slices.Contains(pins, state.PrevPin) {
		pins = append(pins, state.PrevPin)
	}
	return pins
}

// ownSiteKey reports a key the node could have made (newSiteKey). Another
// kind is the operator's, from a certificate imported before imports were
// marked: its chain from ACME may be too short for REALITY (R2-8), so it
// is not ordered with again.
func ownSiteKey(key crypto.Signer) bool {
	_, ok := key.Public().(*rsa.PublicKey)
	return ok
}

// needsNextKey reports a site with a certificate of the node's own and no
// next key, or a next key whose pin is not stored yet.
func needsNextKey(svc store.Service, secrets map[string][]byte) (key, pin bool) {
	state := ParseSiteKeyState(svc)
	if svc.Kind != "site" || state.Imported {
		return false, false
	}
	if len(secrets[NextSecret(SecretTLSKey)]) > 0 {
		return false, state.NextPin == ""
	}
	_, ok := siteLeaf(secrets)
	return ok, false
}

// keyAtOr is when the key in use became current: as recorded, or, for a
// certificate from before the record (raycontrol before cert-pin-v1 made a
// key with every certificate), when its certificate starts.
func keyAtOr(state SiteKeyState, secrets map[string][]byte, now time.Time) int64 {
	if state.KeyAt != 0 {
		return state.KeyAt
	}
	if leaf, ok := siteLeaf(secrets); ok && leaf.NotBefore.Before(now) {
		return leaf.NotBefore.Unix()
	}
	return now.Unix()
}

// EnsureSiteNextKey gives a site that has a certificate of the node's own
// and no next key that key (a node updated to cert-pin-v1), and reports
// whether it made one. The pins go into subscriptions with it, and its
// lead starts at now. The certificate manager calls it at every check:
// where the manager does not run, no next key is made (see above).
func EnsureSiteNextKey(ctx context.Context, st *store.Store, id int64, now time.Time) (bool, error) {
	svc, secrets, err := st.ServiceWithSecrets(ctx, id)
	if err != nil {
		return false, err
	}
	makeKey, makePin := needsNextKey(svc, secrets)
	if !makeKey && !makePin {
		return false, nil
	}
	var next []byte
	if makeKey {
		// Before the lock: an RSA key takes its time.
		if _, next, err = newSiteKey(); err != nil {
			return false, err
		}
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	if svc, secrets, err = st.ServiceWithSecrets(ctx, id); err != nil {
		return false, err
	}
	state := ParseSiteKeyState(svc)
	switch k, p := needsNextKey(svc, secrets); {
	case k && next != nil:
		key, err := parseSiteKey(next)
		if err != nil {
			return false, err
		}
		pin, err := PublicKeyPin(key.Public())
		if err != nil {
			return false, err
		}
		settings, err := setFields(svc.Settings, map[string]any{"tls_next_at": now.Unix(), "tls_next_pin": pin,
			"tls_key_at": keyAtOr(state, secrets, now)})
		if err != nil {
			return false, err
		}
		return true, st.UpdateService(ctx, id, store.ServiceUpdate{Settings: settings, Set: map[string][]byte{NextSecret(SecretTLSKey): next}})
	case p:
		// A next key from before its pin was stored: the pin beside it.
		pin, ok := nextKeyPin(state, secrets)
		if !ok {
			return false, nil
		}
		settings, err := setFields(svc.Settings, map[string]any{"tls_next_pin": pin})
		if err != nil {
			return false, err
		}
		return false, st.UpdateService(ctx, id, store.ServiceUpdate{Settings: settings})
	}
	return false, nil
}

// SiteIssue is how a site's next certificate is ordered and stored
// (PlanSiteIssue, StoreSiteCertificate).
type SiteIssue struct {
	// Key is the key the certificate is ordered for.
	Key crypto.Signer
	// Switch: Key is not the key in use, and storing the certificate makes
	// it current.
	Switch bool
	// What names the key for the log: "kept" (the key in use), "next" (the
	// next key takes over), "new" (one made for this order: a site's first
	// certificate, or the one after the operator's when no next key was
	// left) or "fresh" (one made because the operator asked for it).
	What string

	keyDER []byte
	// prevPin: the pin of the key this switch leaves, to stay in the lists
	// for SitePrevPinFor; "" after a forced or fresh switch and where no
	// line carried pins.
	prevPin string
	// dropAsk: the operator's switch cannot be made as asked (its next key
	// is gone from the store): the request goes, or every check would
	// order again.
	dropAsk bool
	seen    [sha256.Size]byte
}

// siteSeen is what an order is planned with: the certificate, both keys,
// whose the certificate is and what the operator asked.
func siteSeen(state SiteKeyState, secrets map[string][]byte) [sha256.Size]byte {
	h := sha256.New()
	for _, b := range [][]byte{secrets[SecretTLSChain], secrets[SecretTLSKey], secrets[NextSecret(SecretTLSKey)],
		[]byte(state.RotateHow), []byte(state.RotatePin)} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	if state.Imported {
		h.Write([]byte{1})
	}
	return [sha256.Size]byte(h.Sum(nil))
}

// PlanSiteIssue picks the key of a site's next certificate at now:
//
//   - the key in use, whatever the reason of the order (a renewal, new
//     names): no pin changes;
//   - the next key, when the operator asked for the switch
//     (RequestSiteKeyRotation, which checked the lead or was forced) and
//     the next key is still the one the request was checked against, or
//     when the key in use is p.Period old and the next one has been in
//     subscriptions for p.Lead;
//   - a key made for this order, when the operator asked for a fresh one,
//     and for a site without a key of the node's own: its first
//     certificate, or the one that replaces the operator's (no line
//     carried a pin meanwhile). There the next key is taken if there is
//     one: clients that hold its pin, from before the operator's
//     certificate, get in again.
//
// It changes nothing; StoreSiteCertificate does, with the chain.
func PlanSiteIssue(ctx context.Context, st *store.Store, id int64, now time.Time, p SiteKeyPolicy) (SiteIssue, error) {
	var plan SiteIssue
	svc, secrets, err := st.ServiceWithSecrets(ctx, id)
	if err != nil {
		return plan, err
	}
	state := ParseSiteKeyState(svc)
	plan.seen = siteSeen(state, secrets)
	cur, curErr := parseSiteKey(secrets[SecretTLSKey])
	nextDER := secrets[NextSecret(SecretTLSKey)]
	next, nextErr := parseSiteKey(nextDER)
	nextPin := ""
	if nextErr == nil {
		if nextPin, err = PublicKeyPin(next.Public()); err != nil {
			return plan, err
		}
	}
	due := p.Period > 0 && state.KeyAt != 0 && state.NextAt != 0 &&
		now.Unix() >= state.KeyAt+int64(p.Period/time.Second) && now.Unix() >= state.NextAt+int64(p.Lead/time.Second)
	own := !state.Imported && curErr == nil && ownSiteKey(cur)
	asked := state.RotateAt != 0
	fresh := asked && state.RotateHow == SiteSwitchFresh && !state.Imported
	// The request is for the next key it was checked against, named by its
	// pin: a key made since (the store lost the other) has had no lead.
	// Not by the times of the two: a clock set back would drop a request.
	toNext := asked && !fresh && nextErr == nil && state.RotatePin == nextPin
	// The key this switch leaves stays in the lists for a while, where the
	// lines carried pins and the operator did not say the key leaked.
	leaving := ""
	if leaf, ok := siteLeaf(secrets); ok && len(SiteKeyPins(svc, secrets, now)) > 0 {
		leaving = leafPin(leaf)
	}
	switch {
	case fresh || (!own && nextErr != nil):
		if plan.Key, plan.keyDER, err = newSiteKey(); err != nil {
			return plan, err
		}
		plan.What = "new"
		if fresh {
			plan.What = "fresh"
		}
	case !own:
		plan.Key, plan.keyDER, plan.What, plan.prevPin = next, nextDER, "next", leaving
	case toNext || due:
		plan.Key, plan.keyDER, plan.What = next, nextDER, "next"
		if !toNext || state.RotateHow != SiteSwitchForce {
			plan.prevPin = leaving
		}
	default:
		plan.Key, plan.What = cur, "kept"
		plan.dropAsk = asked
		return plan, nil
	}
	plan.Switch = true
	return plan, nil
}

// StoreSiteCertificate stores the chain (PEM, leaf first) ordered with
// plan. With a switch the plan's key becomes the one in use and a new next
// key is made, in subscriptions from now. It is ErrSiteChanged when the
// site is not as planned (the operator's certificate came meanwhile, or
// another order's, or another request): nothing is stored then.
func StoreSiteCertificate(ctx context.Context, st *store.Store, id int64, chainPEM []byte, plan SiteIssue, now time.Time) error {
	leaf, ok := siteLeaf(map[string][]byte{SecretTLSChain: chainPEM})
	if !ok {
		return errors.New("no certificate in the chain")
	}
	// The pins promise this key: a certificate for another one must not
	// reach the clients.
	if want, err := PublicKeyPin(plan.Key.Public()); err != nil || leafPin(leaf) != want {
		return errors.Join(errors.New("the certificate is not for the key it was ordered with"), err)
	}
	var next []byte
	var nextPin string
	if plan.Switch {
		// Before the lock: an RSA key takes its time.
		key, der, err := newSiteKey()
		if err != nil {
			return err
		}
		if nextPin, err = PublicKeyPin(key.Public()); err != nil {
			return err
		}
		next = der
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	svc, secrets, err := st.ServiceWithSecrets(ctx, id)
	if err != nil {
		return err
	}
	if siteSeen(ParseSiteKeyState(svc), secrets) != plan.seen {
		return ErrSiteChanged
	}
	u := store.ServiceUpdate{Set: map[string][]byte{SecretTLSChain: chainPEM}}
	fields := map[string]any{}
	if plan.Switch || plan.dropAsk {
		fields["tls_rotate_at"], fields["tls_rotate_pin"], fields["tls_rotate_how"] = nil, nil, nil
	}
	if plan.Switch {
		u.Set[SecretTLSKey], u.Set[NextSecret(SecretTLSKey)] = plan.keyDER, next
		fields["tls_key_at"], fields["tls_next_at"], fields["tls_next_pin"], fields["tls_imported"] = now.Unix(), now.Unix(), nextPin, nil
		fields["tls_prev_pin"], fields["tls_prev_until"] = nil, nil
		if plan.prevPin != "" {
			fields["tls_prev_pin"], fields["tls_prev_until"] = plan.prevPin, now.Add(SitePrevPinFor).Unix()
		}
	}
	if len(fields) > 0 {
		if u.Settings, err = setFields(svc.Settings, fields); err != nil {
			return err
		}
	}
	// Together: a render between them would pair a key with another chain,
	// a subscription a pin with another key.
	return st.UpdateService(ctx, id, u)
}

// RequestSiteKeyRotation asks for a site's switch to another key at now;
// rayd's certificate manager orders the certificate at its next check, at
// once when woken, and switches when it is stored. How:
//
//   - SiteSwitchLead: to the next key. Clients that hold its pin go on; so
//     it is store.ErrPrecondition unless that key has been in subscriptions
//     for lead (checkGrace's pattern).
//   - SiteSwitchForce: to the next key now, whatever its lead (the key in
//     use leaked): clients that have not fetched since it was made fail
//     their pin until they do. Refused while the key in use is younger
//     than SiteKeyMinAge: the next key was made with it, and a second
//     forced switch in a row lands on a key that lists still in use lack.
//   - SiteSwitchFresh: to a key made for the order, with a new next key
//     (the store leaked, so both keys did): no client holds its pin, all
//     fail until they fetch.
//
// A request already waiting is answered as done; a stronger one replaces
// its way.
func RequestSiteKeyRotation(ctx context.Context, st *store.Store, name string, now time.Time, lead time.Duration, how string) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	byName, err := st.ServiceByName(ctx, name)
	if err != nil {
		return err
	}
	if byName.Kind != "site" {
		return fmt.Errorf("%w: %s is a %s service, not a site", store.ErrInvalid, name, byName.Kind)
	}
	svc, secrets, err := st.ServiceWithSecrets(ctx, byName.ID)
	if err != nil {
		return err
	}
	state := ParseSiteKeyState(svc)
	if state.Imported {
		return fmt.Errorf("%w: %s has a certificate of your own (rayctl service cert): its key changes with the certificate you import; "+
			"the lines under it carry no pins (spec/cert-pin-v1.md)", store.ErrInvalid, name)
	}
	if _, ok := siteLeaf(secrets); !ok {
		return fmt.Errorf("%w: %s has no certificate yet: there is no key to switch from", store.ErrPrecondition, name)
	}
	strength := func(how string) int {
		return slices.Index([]string{SiteSwitchLead, SiteSwitchForce, SiteSwitchFresh}, how)
	}
	if strength(how) < 0 {
		return fmt.Errorf("%w: a switch %q: want none, force or fresh", store.ErrInvalid, how)
	}
	if state.RotateAt != 0 {
		// Asked already: the order is on its way. First, before any check
		// of now: the same request again must get the same answer.
		if strength(how) <= strength(state.RotateHow) {
			return nil
		}
		settings, err := setFields(svc.Settings, map[string]any{"tls_rotate_how": how})
		if err != nil {
			return err
		}
		return st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings})
	}
	fields := map[string]any{"tls_rotate_at": now.Unix(), "tls_rotate_how": how}
	if how != SiteSwitchFresh {
		pin, ok := nextKeyPin(state, secrets)
		if !ok || state.NextAt == 0 {
			return fmt.Errorf("%w: %s has no next key yet: rayd makes it at a certificate check, ten minutes after its start "+
				"at the earliest (it issues none with -acme-directory empty), and the switch waits for its lead",
				store.ErrPrecondition, name)
		}
		fields["tls_rotate_pin"] = pin
		since := time.Unix(state.NextAt, 0)
		switch {
		case how == SiteSwitchForce && state.KeyAt != 0 && now.Before(time.Unix(state.KeyAt, 0).Add(forceMinAge())):
			return fmt.Errorf("%w: %s: its key is in use only since %s, and the next one was made then: lists that clients may use "+
				"until %s do not hold its pin. A second forced switch now would cut every client that has not fetched since. "+
				"If the key in use leaked too, order a fresh one (rayctl service rotate %s -fresh)",
				store.ErrPrecondition, name, time.Unix(state.KeyAt, 0).UTC().Format(time.RFC3339),
				time.Unix(state.KeyAt, 0).Add(SiteKeyMinAge).UTC().Format(time.RFC3339), name)
		case how == SiteSwitchLead && now.Before(since.Add(lead)):
			return fmt.Errorf("%w: %s: its next certificate key is in subscriptions only since %s (clients that have not fetched their "+
				"subscription since do not hold its pin); a switch now would cut them off naive, hy2-masq and DoH until they do: "+
				"switch after %s, or anyway with force (rayctl service rotate %s -force)",
				store.ErrPrecondition, name, since.UTC().Format(time.RFC3339), since.Add(lead).UTC().Format(time.RFC3339), name)
		}
	}
	settings, err := setFields(svc.Settings, fields)
	if err != nil {
		return err
	}
	return st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings})
}
