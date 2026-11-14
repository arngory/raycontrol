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
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// The key of a site's certificate (spec/cert-pin-v1.md). naive, hy2-masq
// and DoH answer with the site's certificate, and their lines carry the
// pins of two keys (niko-pin): the one of the certificate in use and the
// next one, made ahead. A client takes a leaf with either key and no
// other, whatever CA signed it, so:
//
//   - an issuance keeps the key: a renewal or new names change no pin;
//   - the key changes only to the next one, and only once that has been in
//     subscriptions for the lead: when the operator asks (rayctl service
//     rotate SITE) or by itself, at an issuance, once the key is a period
//     old;
//   - the switch makes a new next key, whose lead starts then.
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
	case p.Period > 0 && p.Lead >= p.Period:
		return errors.New("site key rotation: the lead must be shorter than the period")
	}
	return nil
}

// SiteKeyState is the key rotation state in the settings of a site.
type SiteKeyState struct {
	KeyAt    int64 `json:"tls_key_at,omitempty"`    // the key in use is current since then
	NextAt   int64 `json:"tls_next_at,omitempty"`   // the next key is in subscriptions since then
	RotateAt int64 `json:"tls_rotate_at,omitempty"` // the operator asked for the switch then; rayd has not made it yet
	Imported bool  `json:"tls_imported,omitempty"`  // the certificate is the operator's own (SetCertificate)
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

// SiteKeyPins are the pins of a site's certificate for the lines of the
// services under it (niko-pin, spec/cert-pin-v1.md §2): the key of the
// leaf in use, then the next key. None for a site without a certificate,
// with the operator's own, or without a next key (no certificate manager):
// the node promises nothing about the key of the certificate after this
// one there.
func SiteKeyPins(svc store.Service, secrets map[string][]byte) []string {
	if svc.Kind != "site" || ParseSiteKeyState(svc).Imported {
		return nil
	}
	leaf, ok := siteLeaf(secrets)
	if !ok {
		return nil
	}
	next, err := parseSiteKey(secrets[NextSecret(SecretTLSKey)])
	if err != nil {
		return nil
	}
	cur := leafPin(leaf)
	after, err := PublicKeyPin(next.Public())
	if err != nil || after == cur {
		return nil
	}
	return []string{cur, after}
}

// leafPin is the pin of a certificate's key, from the bytes clients hash.
func leafPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:])
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
// next key.
func needsNextKey(svc store.Service, secrets map[string][]byte) bool {
	if svc.Kind != "site" || ParseSiteKeyState(svc).Imported || len(secrets[NextSecret(SecretTLSKey)]) > 0 {
		return false
	}
	_, ok := siteLeaf(secrets)
	return ok
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
	read := func() (store.Service, map[string][]byte, error) {
		svc, err := serviceByID(ctx, st, id)
		if err != nil {
			return svc, nil, err
		}
		secrets, err := st.ServiceSecrets(ctx, id)
		return svc, secrets, err
	}
	svc, secrets, err := read()
	if err != nil || !needsNextKey(svc, secrets) {
		return false, err
	}
	// Before the lock: an RSA key takes its time.
	_, next, err := newSiteKey()
	if err != nil {
		return false, err
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	if svc, secrets, err = read(); err != nil || !needsNextKey(svc, secrets) {
		return false, err
	}
	state := ParseSiteKeyState(svc)
	settings, err := setFields(svc.Settings, map[string]any{"tls_next_at": now.Unix(), "tls_key_at": keyAtOr(state, secrets, now)})
	if err != nil {
		return false, err
	}
	return true, st.UpdateService(ctx, id, store.ServiceUpdate{Settings: settings, Set: map[string][]byte{NextSecret(SecretTLSKey): next}})
}

func serviceByID(ctx context.Context, st *store.Store, id int64) (store.Service, error) {
	all, err := st.ListServices(ctx)
	if err != nil {
		return store.Service{}, err
	}
	for _, s := range all {
		if s.ID == id {
			return s, nil
		}
	}
	return store.Service{}, fmt.Errorf("service %d: %w", id, store.ErrNotFound)
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
	// next key takes over) or "new" (one made for this order: a site's
	// first certificate, or the one after the operator's when no next key
	// was left).
	What string

	keyDER   []byte
	makeNext bool
	// dropAsk: the operator's switch was asked for and there is no next key
	// to switch to (a damaged store): the request goes, or every check
	// would order again.
	dropAsk bool
	seen    [sha256.Size]byte
}

// siteSeen is what an order is planned with: the certificate, both keys
// and whose the certificate is.
func siteSeen(state SiteKeyState, secrets map[string][]byte) [sha256.Size]byte {
	h := sha256.New()
	for _, name := range []string{SecretTLSChain, SecretTLSKey, NextSecret(SecretTLSKey)} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(secrets[name])))
		h.Write(n[:])
		h.Write(secrets[name])
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
//     (RequestSiteKeyRotation, which checked the lead) or when the key in
//     use is p.Period old and the next one has been in subscriptions for
//     p.Lead;
//   - for a site without a key of the node's own, another one: its first
//     certificate, or the one that replaces the operator's (no line
//     carried a pin meanwhile). The next key is taken if there is one:
//     clients that hold its pin, from before the operator's certificate,
//     get in again.
//
// It changes nothing; StoreSiteCertificate does, with the chain.
func PlanSiteIssue(ctx context.Context, st *store.Store, id int64, now time.Time, p SiteKeyPolicy) (SiteIssue, error) {
	var plan SiteIssue
	svc, err := serviceByID(ctx, st, id)
	if err != nil {
		return plan, err
	}
	secrets, err := st.ServiceSecrets(ctx, id)
	if err != nil {
		return plan, err
	}
	state := ParseSiteKeyState(svc)
	plan.seen = siteSeen(state, secrets)
	cur, curErr := parseSiteKey(secrets[SecretTLSKey])
	nextDER := secrets[NextSecret(SecretTLSKey)]
	next, nextErr := parseSiteKey(nextDER)
	due := p.Period > 0 && state.KeyAt != 0 && state.NextAt != 0 &&
		now.Unix() >= state.KeyAt+int64(p.Period/time.Second) && now.Unix() >= state.NextAt+int64(p.Lead/time.Second)
	own := !state.Imported && curErr == nil && ownSiteKey(cur)
	// The operator's request is for the next key it was checked against:
	// one made since (the store lost the other) has had no lead.
	asked := state.RotateAt != 0 && state.NextAt != 0 && state.NextAt <= state.RotateAt
	switch {
	case !own && nextErr == nil:
		plan.Key, plan.keyDER, plan.What = next, nextDER, "next"
	case !own:
		if plan.Key, plan.keyDER, err = newSiteKey(); err != nil {
			return plan, err
		}
		plan.What = "new"
	case nextErr == nil && (asked || due):
		plan.Key, plan.keyDER, plan.What = next, nextDER, "next"
	default:
		plan.Key, plan.What = cur, "kept"
		plan.makeNext = nextErr != nil
		plan.dropAsk = state.RotateAt != 0
		return plan, nil
	}
	plan.Switch, plan.makeNext = true, true
	return plan, nil
}

// StoreSiteCertificate stores the chain (PEM, leaf first) ordered with
// plan. With a switch the plan's key becomes the one in use and a new next
// key is made, in subscriptions from now. It is ErrSiteChanged when the
// site is not as planned (the operator's certificate came meanwhile, or
// another order's): nothing is stored then.
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
	var err error
	if plan.makeNext {
		// Before the lock: an RSA key takes its time.
		if _, next, err = newSiteKey(); err != nil {
			return err
		}
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	svc, err := serviceByID(ctx, st, id)
	if err != nil {
		return err
	}
	secrets, err := st.ServiceSecrets(ctx, id)
	if err != nil {
		return err
	}
	state := ParseSiteKeyState(svc)
	if siteSeen(state, secrets) != plan.seen {
		return ErrSiteChanged
	}
	u := store.ServiceUpdate{Set: map[string][]byte{SecretTLSChain: chainPEM}}
	fields := map[string]any{}
	if plan.Switch {
		u.Set[SecretTLSKey] = plan.keyDER
		fields["tls_key_at"], fields["tls_rotate_at"], fields["tls_imported"] = now.Unix(), nil, nil
	}
	if plan.makeNext {
		u.Set[NextSecret(SecretTLSKey)] = next
		fields["tls_next_at"] = now.Unix()
		if !plan.Switch {
			fields["tls_key_at"] = keyAtOr(state, secrets, now)
		}
	}
	if plan.dropAsk {
		fields["tls_rotate_at"] = nil
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

// RequestSiteKeyRotation asks for a site's switch to its next key at now:
// rayd's certificate manager orders a certificate with that key at its
// next check and switches when it is stored. Clients that hold the pin of
// the next key go on; the others fail their pin until they fetch their
// subscription, and those of Niko 1.45.0 take a hy2-masq leaf by its pin
// alone. So it is store.ErrPrecondition unless the next key has been in
// subscriptions for lead, or force (checkGrace's pattern).
func RequestSiteKeyRotation(ctx context.Context, st *store.Store, name string, now time.Time, lead time.Duration, force bool) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		return err
	}
	if svc.Kind != "site" {
		return fmt.Errorf("%w: %s is a %s service, not a site", store.ErrInvalid, name, svc.Kind)
	}
	secrets, err := st.ServiceSecrets(ctx, svc.ID)
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
	if _, err := parseSiteKey(secrets[NextSecret(SecretTLSKey)]); err != nil || state.NextAt == 0 {
		return fmt.Errorf("%w: %s has no next key yet: rayd makes it at its next certificate check (it issues none with "+
			"-acme-directory empty), and the switch waits for its lead", store.ErrPrecondition, name)
	}
	if ready := time.Unix(state.NextAt, 0).Add(lead); now.Before(ready) && !force {
		return fmt.Errorf("%w: %s: its next certificate key is in subscriptions only since %s (clients that have not fetched their "+
			"subscription since do not hold its pin); a switch now would cut them off naive, hy2-masq and DoH until they do: "+
			"switch after %s, or anyway with force (rayctl service rotate %s -force)",
			store.ErrPrecondition, name, time.Unix(state.NextAt, 0).UTC().Format(time.RFC3339), ready.UTC().Format(time.RFC3339), name)
	}
	if state.RotateAt != 0 {
		return nil // asked already: the order is on its way
	}
	settings, err := setFields(svc.Settings, map[string]any{"tls_rotate_at": now.Unix()})
	if err != nil {
		return err
	}
	return st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings})
}
