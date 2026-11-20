package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

const settingAccount = "acme_account_key"

// AccountKey loads the node's ACME account key, creating it on first use.
func AccountKey(ctx context.Context, st *store.Store) (crypto.Signer, error) {
	der, err := st.GetSetting(ctx, settingAccount)
	if errors.Is(err, store.ErrNotFound) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		if der, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
			return nil, err
		}
		return key, st.SetSetting(ctx, settingAccount, der)
	}
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("acme account key is not a signer")
	}
	return signer, nil
}

// Manager keeps the certificates of the node's sites: issued when missing
// or when the name changed, renewed with a third of the lifetime left.
//
// A site keeps its key from one certificate to the next, and has the key
// after it ready (spec/cert-pin-v1.md): the lines of naive, hy2-masq and
// DoH pin both. The key changes only to that next one, when the operator
// asks or by Keys (provision.PlanSiteIssue).
type Manager struct {
	Store *store.Store
	// Issue gets a chain for names and the key (Issuer.Issue).
	Issue func(ctx context.Context, names []string, key crypto.Signer) ([][]byte, error)
	// Keys is when a site's key changes by itself, at an issuance; zero:
	// only when the operator asks.
	Keys provision.SiteKeyPolicy
	// NextKeyFrom: a site that has a certificate and no next key (a node
	// just updated to cert-pin-v1) gets one only from then on (rayd: ten
	// minutes after its start, as the subscription's seq takes the clock).
	// An update that fails in its first minutes goes back to a version
	// that knows no pins: none must have reached a client by then.
	NextKeyFrom time.Time
	// Check, if set, refuses a certificate before it is stored: rayd gives
	// what the site process checks when it loads one (a chain long enough
	// for REALITY). Stored unchecked, the site would keep the old
	// certificate until it expired while the others served the new one.
	Check func(chainPEM, keyPEM []byte) error
	// Notify runs after a certificate is stored (rayd re-renders).
	Notify func()
	// Report, if set, gets each order's outcome per site (O-2).
	Report func(site string, err error)
	Log    *slog.Logger
	// Every is the check interval; failures back off from it up to a day.
	Every time.Duration
	// Wildcard returns the node's domain when certificates can be wildcards
	// (DNS-01): one *.domain then covers every name of a site, those REALITY
	// moves to included, and no name of the node shows in CT logs (R4-10).
	Wildcard func(ctx context.Context) string
	// RelayNames, if set, gives the relays' names of a site's services,
	// for its orders under HTTP-01 (spec/relay-names-v1.md §5, §6): those
	// Orderable go in after the site's own, as many as the CA takes
	// (MaxNames). Not asked with a wildcard, which covers them. They make
	// no order of their own while the site has the operator's certificate
	// (it is not asked to cover them), but the order that replaces it
	// takes them. A relay whose name fails an order (NamesError) waits
	// out a back-off of its own, and the order goes again at once without
	// its names, the other relays' kept: one broken relay holds back
	// neither the site's certificate nor the other relays' names.
	RelayNames func(ctx context.Context, site string) []RelayName
	// RelayReport, if set, gets the outcome for the relays' names of each
	// order that had them: nil once they are in the certificate, the
	// error of the relay's failure (its detail, addresses with it: for
	// root's rayctl relay list), and ErrTooManyNames for those left out.
	RelayReport func(site string, names []string, err error)
	// RelayHoldUntil: until then a due site whose certificate covers a
	// relay's name not orderable now waits, unless it expires within
	// RelayHoldMargin. rayd: two minutes after its start, for the relays'
	// feeds to come back; an order before would leave out their names.
	RelayHoldUntil time.Time

	once  sync.Once
	fails map[string]int
	next  map[string]time.Time
	last  map[string]time.Time   // the last failed try of a site
	asked map[string]askedSwitch // the operator's switch that got its try past the back-off
	wake  chan struct{}
	retry atomic.Bool

	// The relays whose names failed an order (NamesError), by relay: how
	// many times in a row, when their names go into an order again, and
	// when they last failed.
	relayFails map[string]int
	relayNext  map[string]time.Time
	relayLast  map[string]time.Time
	// leftOut: the names a site's last check left out for MaxNames, as
	// logged (once a change).
	leftOut map[string]string

	mu    sync.Mutex
	again map[string]bool // RetrySite's sites, for the next Once
}

// askedSwitch names a request for a site's switch: its time and how. An
// upgrade (-force, then -fresh) keeps the time and is a request of its own.
type askedSwitch struct {
	at  int64
	how string
}

// Wake makes Run check now, as when a site needs a new name; failures keep
// their back-off.
func (m *Manager) Wake() {
	select {
	case m.wakeCh() <- struct{}{}:
	default:
	}
}

// RetryGap spaces the tries that operators' changes start: at most four an
// hour, under Let's Encrypt's five failed validations an hour per name.
const RetryGap = 15 * time.Minute

// backoff is the wait after fails failures in a row: an hour, doubling up
// to a day.
func backoff(fails int) time.Duration { return min(time.Hour<<min(fails-1, 5), 24*time.Hour) }

// Retry makes Run try the failed sites now too, on an operator's change
// that may have fixed them (a DNS token, the records): RetryGap after
// their last try at the earliest. The count of failures stays, so a site
// that fails again waits longer.
func (m *Manager) Retry() {
	m.retry.Store(true)
	m.Wake()
}

// RetrySite makes Run try one site now, as Retry does for all: RetryGap
// after its last failed try at the earliest. The API runs it after a
// switch is asked again while a request as strong waits: that request had
// its try past the back-off, and a repeat must not wait out a day.
func (m *Manager) RetrySite(name string) {
	m.mu.Lock()
	if m.again == nil {
		m.again = map[string]bool{}
	}
	m.again[name] = true
	m.mu.Unlock()
	m.Wake()
}

func (m *Manager) wakeCh() chan struct{} {
	m.once.Do(func() { m.wake = make(chan struct{}, 1) })
	return m.wake
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

// Run checks now, then every Every, until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	every := m.Every
	if every <= 0 {
		every = time.Hour
	}
	for {
		m.Once(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-m.wakeCh():
		case <-time.After(m.wait(every, time.Now())):
		}
	}
}

// wait is how long Run sleeps: every, or less when a site's next try comes
// sooner (one Retry moved forward). Run's goroutine only, as Once.
func (m *Manager) wait(every time.Duration, now time.Time) time.Duration {
	for _, next := range m.next {
		if d := next.Sub(now); d < every {
			every = max(d, time.Second)
		}
	}
	// The first next keys of an updated node: then, not an interval later.
	// Likewise a relay's names past their back-off, and the end of the
	// hold for the relays' feeds.
	soon := append([]time.Time{m.NextKeyFrom, m.RelayHoldUntil}, slices.Collect(maps.Values(m.relayNext))...)
	for _, at := range soon {
		if d := at.Sub(now); d > 0 && d < every {
			every = max(d, time.Second)
		}
	}
	return every
}

// Once issues what is due and returns how many certificates it stored.
func (m *Manager) Once(ctx context.Context, now time.Time) int {
	if m.fails == nil {
		m.fails, m.next, m.last = map[string]int{}, map[string]time.Time{}, map[string]time.Time{}
	}
	if m.asked == nil {
		m.asked = map[string]askedSwitch{}
	}
	m.mu.Lock()
	again := m.again
	m.again = nil
	m.mu.Unlock()
	// From the last try, not from next: changes in a row (a cron job) keep
	// the gap however many there are.
	all := m.retry.Swap(false)
	for name, next := range m.next {
		if !all && !again[name] {
			continue
		}
		if soon := m.last[name].Add(RetryGap); soon.Before(next) {
			m.next[name] = soon
		}
	}
	for relay, next := range m.relayNext {
		if soon := m.relayLast[relay].Add(RetryGap); all && soon.Before(next) {
			m.relayNext[relay] = soon
		}
	}
	services, err := m.Store.ListServices(ctx)
	if err != nil {
		m.log().Error("certificates", "err", err)
		return 0
	}
	stored := 0
	for _, svc := range services {
		if svc.Kind != "site" || !svc.Enabled {
			continue
		}
		// The key after the one in use (cert-pin-v1 §4): a site from before
		// it gets it at the first check from NextKeyFrom on, and its pins go
		// into subscriptions. Whatever the back-off: no order is made for it.
		if !now.Before(m.NextKeyFrom) {
			if made, err := provision.EnsureSiteNextKey(ctx, m.Store, svc.ID, now); err != nil {
				m.log().Error("certificates: next key", "service", svc.Name, "err", err)
			} else if made {
				m.log().Info("next certificate key made; its pin is in subscriptions from now", "service", svc.Name)
			}
		}
		// The operator's switch (rayctl service rotate SITE) is an order
		// with another key, and it gets one try now whatever the back-off
		// of earlier failures: a leaked key must not serve a day longer
		// because a renewal failed last week. One try a request; if it
		// fails too, the back-off goes on. An upgrade (-force, then -fresh)
		// is another request; the same one again is RetrySite's.
		state := provision.ParseSiteKeyState(svc)
		rotate := state.RotateAt != 0
		if ask := (askedSwitch{state.RotateAt, state.RotateHow}); rotate && m.asked[svc.Name] != ask {
			m.asked[svc.Name] = ask
		} else if now.Before(m.next[svc.Name]) {
			continue
		}
		// The names in use and those REALITY moves to at its next switch
		// (R4-7); when the new ones fail, the names in use still renew.
		names, next := provision.SiteNames(svc, services)
		secrets, err := m.Store.ServiceSecrets(ctx, svc.ID)
		if err != nil {
			m.log().Error("certificates", "service", svc.Name, "err", err)
			continue
		}
		chain := secrets[provision.SecretTLSChain]
		own := append(slices.Clone(names), next...)
		wildcard := ""
		if m.Wildcard != nil {
			wildcard = m.Wildcard(ctx)
		}
		var candidates []RelayName
		if m.RelayNames != nil && wildcard == "" {
			candidates = m.RelayNames(ctx, svc.Name)
		}
		relay := m.relayNames(svc.Name, candidates, len(own), now)
		// The operator's certificate is not asked to cover the relays'
		// names (§5): they make no order while it is on the site. The one
		// that replaces it takes them.
		dueFor := append(slices.Clone(own), relay...)
		if state.Imported {
			dueFor = own
		}
		// Due, or the operator asked for another key: the switch is an
		// issuance with it.
		if !due(chain, dueFor, now) && !rotate {
			continue
		}
		if m.holdForRelays(chain, candidates, now) && !rotate {
			m.log().Info("certificate waits for the relays' feeds to come back: it has their names", "service", svc.Name,
				"until", m.RelayHoldUntil)
			continue
		}
		order := func(relay []string) []string {
			want := append(slices.Clone(own), relay...)
			if wildcard != "" && provision.UnderWildcard(want, wildcard) {
				return []string{"*." + wildcard}
			}
			return want
		}
		// At most maxOrders a site a check: with the relays' names, again
		// without those of the relays that failed (the others kept), and
		// without any relay's or without the next names.
		orders := 1
		err = m.issue(ctx, svc, order(relay), now)
		for len(relay) > 0 && err != nil && !errors.Is(err, provision.ErrSiteChanged) && orders < maxOrders {
			failed := m.relaysFailed(svc.Name, candidates, relay, err, now)
			kept := slices.DeleteFunc(slices.Clone(relay), func(n string) bool { return slices.Contains(failed, n) })
			if len(failed) == 0 {
				kept = nil // no relay's fault: the site's own names alone
			}
			m.log().Warn("certificate with the relays' names not issued, ordering again without them", "service", svc.Name,
				"relay_names", len(relay), "left_out", len(relay)-len(kept), "err", logErr(err, relay))
			relay = kept
			// What the site has does for what is left: no order.
			if !due(chain, append(slices.Clone(own), relay...), now) && !rotate {
				err, orders = nil, 0
				break
			}
			err = m.issue(ctx, svc, order(relay), now)
			orders++
		}
		if len(relay) > 0 && err != nil && !errors.Is(err, provision.ErrSiteChanged) {
			m.relaysFailed(svc.Name, candidates, relay, err, now)
		}
		if orders == 0 {
			continue // the relays' names failed; the site's certificate does
		}
		if err == nil && len(relay) > 0 {
			m.relaysIn(svc.Name, candidates, relay)
		}
		wild := wildcard != "" && provision.UnderWildcard(own, wildcard)
		if err != nil && !errors.Is(err, provision.ErrSiteChanged) && len(next) > 0 && len(relay) == 0 && orders < maxOrders &&
			!wild && (rotate || due(chain, names, now)) {
			m.log().Warn("certificate with the next name not issued, renewing without it", "service", svc.Name, "err", err)
			err = m.issue(ctx, svc, names, now)
		}
		if errors.Is(err, provision.ErrSiteChanged) {
			// The operator's certificate came during the order: theirs
			// stays, and the next check looks at it. No failure.
			m.log().Info("certificate not stored: the site changed during the order", "service", svc.Name)
			delete(m.asked, svc.Name) // a request that came meanwhile gets its try
			m.Wake()
			continue
		}
		if m.Report != nil {
			m.Report(svc.Name, logErr(err, relay))
		}
		if err != nil {
			m.fails[svc.Name]++
			wait := backoff(m.fails[svc.Name])
			m.next[svc.Name] = now.Add(wait)
			m.last[svc.Name] = now
			m.log().Warn("certificate not issued, retrying later", "service", svc.Name, "in", wait, "err", logErr(err, relay))
			continue
		}
		delete(m.fails, svc.Name)
		delete(m.next, svc.Name)
		delete(m.last, svc.Name)
		stored++
		// At once, not after the other sites' orders, which take their
		// time: subscriptions carry this certificate's pins from the
		// moment it is stored, and the processes take it only when rayd
		// renders it.
		if m.Notify != nil {
			m.Notify()
		}
	}
	return stored
}

// MaxNames is how many names one certificate takes (Let's Encrypt's
// limit): the relays' names beyond it, after the site's own, are left out
// of the order (RelayNames) and reported (ErrTooManyNames).
const MaxNames = 100

// ErrTooManyNames is the report of a relay's name left out of an order
// for MaxNames.
var ErrTooManyNames = fmt.Errorf("the site's certificate has room for %d names, the site's own first", MaxNames)

// RelayName is a relay's name for a site's certificate (Manager.RelayNames).
// Orderable: it may go into an order now, its relay forwarding TCP 80 to
// the node for the window (its rayspa's feed open now) and the name
// resolving to that relay alone.
type RelayName struct {
	Relay, Name string
	Orderable   bool
}

// maxOrders bounds the orders of a site in one check: the CA counts the
// failed validations (5 an hour a name), and an order takes minutes.
const maxOrders = 3

// RelayHoldMargin: a certificate that expires within it is renewed
// whatever the relays' feeds (RelayHoldUntil).
const RelayHoldMargin = 7 * 24 * time.Hour

// relayNames are the relays' names to order with a site's own (have of
// them): those orderable, of relays out of their back-off, the first
// MaxNames-have. The rest are left out and reported, and logged once
// while it stays so.
func (m *Manager) relayNames(site string, candidates []RelayName, have int, now time.Time) []string {
	var names []string
	for _, c := range candidates {
		if c.Orderable && !now.Before(m.relayNext[c.Relay]) {
			names = append(names, c.Name)
		}
	}
	var left []string
	if room := max(MaxNames-have, 0); len(names) > room {
		names, left = names[:room], names[room:]
	}
	if m.leftOut == nil {
		m.leftOut = map[string]string{}
	}
	if key := strings.Join(left, ","); key != m.leftOut[site] {
		m.leftOut[site] = key
		if len(left) > 0 {
			m.log().Warn("relays' names left out of the site's certificate: the CA takes no more names", "service", site,
				"left_out", len(left), "max", MaxNames)
		}
	}
	if len(left) > 0 && m.RelayReport != nil {
		m.RelayReport(site, left, ErrTooManyNames)
	}
	return names
}

// holdForRelays reports whether a due certificate waits for the relays'
// feeds after rayd's start (RelayHoldUntil): it covers a relay's name that
// is not orderable now, and does not expire within RelayHoldMargin.
func (m *Manager) holdForRelays(chainPEM []byte, candidates []RelayName, now time.Time) bool {
	if !now.Before(m.RelayHoldUntil) {
		return false
	}
	leaf := leafOf(chainPEM)
	if leaf == nil || !leaf.NotAfter.After(now.Add(RelayHoldMargin)) {
		return false
	}
	return slices.ContainsFunc(candidates, func(c RelayName) bool { return !c.Orderable && leaf.VerifyHostname(c.Name) == nil })
}

// relaysFailed takes an order's failure with the relays' names it had: the
// relays whose names the CA or the DNS check refused (NamesError) wait out
// a back-off, and get the error. It returns the names of those relays in
// the order, none when the failure was no relay's.
func (m *Manager) relaysFailed(site string, candidates []RelayName, ordered []string, err error, now time.Time) []string {
	var ne *NamesError
	if !errors.As(err, &ne) {
		return nil
	}
	if m.relayFails == nil {
		m.relayFails, m.relayNext, m.relayLast = map[string]int{}, map[string]time.Time{}, map[string]time.Time{}
	}
	var relays []string
	for _, c := range candidates {
		if slices.Contains(ne.Names, c.Name) && slices.Contains(ordered, c.Name) && !slices.Contains(relays, c.Relay) {
			relays = append(relays, c.Relay)
			m.relayFails[c.Relay]++
			m.relayNext[c.Relay], m.relayLast[c.Relay] = now.Add(backoff(m.relayFails[c.Relay])), now
		}
	}
	var names []string
	for _, c := range candidates {
		if slices.Contains(relays, c.Relay) && slices.Contains(ordered, c.Name) {
			names = append(names, c.Name)
		}
	}
	if len(names) > 0 && m.RelayReport != nil {
		m.RelayReport(site, slices.Clone(names), err)
	}
	return names
}

// relaysIn takes the relays' names a stored certificate has: their relays'
// back-off ends, and the names are reported as in.
func (m *Manager) relaysIn(site string, candidates []RelayName, names []string) {
	for _, c := range candidates {
		if slices.Contains(names, c.Name) {
			delete(m.relayFails, c.Relay)
			delete(m.relayNext, c.Relay)
			delete(m.relayLast, c.Relay)
		}
	}
	if m.RelayReport != nil {
		m.RelayReport(site, slices.Clone(names), nil)
	}
}

// logErr is an order's error as the log and the site's status take it:
// a NamesError of a relay's name gives its reason and how many names, not
// its detail, which may carry the relay's address (the CA's answer, the
// DNS check's) and goes to RelayReport alone.
func logErr(err error, relay []string) error {
	var ne *NamesError
	if errors.As(err, &ne) && slices.ContainsFunc(ne.Names, func(n string) bool { return slices.Contains(relay, n) }) {
		return fmt.Errorf("%d of the relays' names: %s (rayctl relay list)", len(ne.Names), ne.Reason)
	}
	return err
}

// leafOf is the leaf of a PEM chain, nil when there is none.
func leafOf(chainPEM []byte) *x509.Certificate {
	block, _ := pem.Decode(chainPEM)
	if block == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return leaf
}

// due reports whether a chain is missing, lacks one of the names, or is
// up for renewal.
func due(chainPEM []byte, names []string, now time.Time) bool {
	block, _ := pem.Decode(chainPEM)
	if block == nil {
		return true
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	for _, n := range names {
		if leaf.VerifyHostname(n) != nil {
			return true
		}
	}
	return !now.Before(RenewAt(leaf))
}

// issue orders a certificate for names with the site's key (the one in use,
// unless it is time for the next: provision.PlanSiteIssue) and stores it.
func (m *Manager) issue(ctx context.Context, svc store.Service, names []string, now time.Time) error {
	plan, err := provision.PlanSiteIssue(ctx, m.Store, svc.ID, now, m.Keys)
	if err != nil {
		return err
	}
	chain, err := m.Issue(ctx, names, plan.Key)
	if err != nil {
		return err
	}
	var pemChain bytes.Buffer
	for _, der := range chain {
		if err := pem.Encode(&pemChain, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return err
		}
	}
	if m.Check != nil {
		keyDER, err := x509.MarshalPKCS8PrivateKey(plan.Key)
		if err != nil {
			return err
		}
		if err := m.Check(pemChain.Bytes(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
			return fmt.Errorf("the certificate is not one the site can serve: %w", err)
		}
	}
	if err := provision.StoreSiteCertificate(ctx, m.Store, svc.ID, pemChain.Bytes(), plan, now); err != nil {
		return err
	}
	// Which key, never the key or its pin.
	m.log().Info("certificate stored", "service", svc.Name, "names", len(names), "key", plan.What)
	return nil
}
