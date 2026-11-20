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
	"slices"
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
	// RelayNames, if set, gives the relays' names to order with a site's
	// own, under HTTP-01 (spec/relay-names-v1.md §5, §6): rayd gives those
	// of the relays that forward TCP 80 to the node for the window and
	// resolve to their relay. None with a wildcard, which covers them, nor
	// while the site has the operator's certificate: it is not asked to
	// cover them (§5), and the next order the site's own names make takes
	// them. After the site's names, as many as the CA takes (MaxNames).
	// An order with them that fails is made at once without them, and
	// they wait out a back-off of their own: they never hold back the
	// site's certificate.
	RelayNames func(ctx context.Context, site string) []string
	// RelayReport, if set, gets the outcome for the relays' names of each
	// order that had them (nil: they are in the certificate), and those
	// left out for MaxNames (ErrTooManyNames).
	RelayReport func(site string, names []string, err error)

	once  sync.Once
	fails map[string]int
	next  map[string]time.Time
	last  map[string]time.Time   // the last failed try of a site
	asked map[string]askedSwitch // the operator's switch that got its try past the back-off
	wake  chan struct{}
	retry atomic.Bool

	// The relays' names of a site whose order failed (RelayNames): how
	// many times in a row, when they go into an order again, and when
	// they last failed.
	relayFails map[string]int
	relayNext  map[string]time.Time
	relayLast  map[string]time.Time

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
	if d := m.NextKeyFrom.Sub(now); d > 0 && d < every {
		every = max(d, time.Second)
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
	for name, next := range m.relayNext {
		if soon := m.relayLast[name].Add(RetryGap); (all || again[name]) && soon.Before(next) {
			m.relayNext[name] = soon
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
		relay := m.relayNames(ctx, svc, len(own), now)
		want := append(slices.Clone(own), relay...)
		// Due, or the operator asked for another key: the switch is an
		// issuance with it.
		if !due(chain, want, now) && !rotate {
			continue
		}
		order := want
		if m.Wildcard != nil {
			if d := m.Wildcard(ctx); d != "" && provision.UnderWildcard(want, d) {
				order = []string{"*." + d}
			}
		}
		err = m.issue(ctx, svc, order, now)
		if len(relay) > 0 && !errors.Is(err, provision.ErrSiteChanged) {
			m.relayOutcome(svc.Name, relay, err, now)
			if err != nil {
				m.log().Warn("certificate with the relays' names not issued, ordering without them", "service", svc.Name,
					"relay_names", len(relay), "err", err)
				want, order = own, own
				// What the site has does for its own names: no order.
				if !due(chain, want, now) && !rotate {
					continue
				}
				err = m.issue(ctx, svc, order, now)
			}
		}
		if err != nil && !errors.Is(err, provision.ErrSiteChanged) && len(next) > 0 && len(order) == len(want) && (rotate || due(chain, names, now)) {
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
			m.Report(svc.Name, err)
		}
		if err != nil {
			m.fails[svc.Name]++
			wait := backoff(m.fails[svc.Name])
			m.next[svc.Name] = now.Add(wait)
			m.last[svc.Name] = now
			m.log().Warn("certificate not issued, retrying later", "service", svc.Name, "in", wait, "err", err)
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

// relayNames are the relays' names to order with a site's own (have of
// them): none while they wait out a failure, with a wildcard, or with the
// operator's certificate on the site.
func (m *Manager) relayNames(ctx context.Context, svc store.Service, have int, now time.Time) []string {
	if m.RelayNames == nil || now.Before(m.relayNext[svc.Name]) || provision.ParseSiteKeyState(svc).Imported {
		return nil
	}
	if m.Wildcard != nil && m.Wildcard(ctx) != "" {
		return nil
	}
	names := m.RelayNames(ctx, svc.Name)
	if room := max(MaxNames-have, 0); len(names) > room {
		m.log().Warn("relays' names left out of the site's certificate: the CA takes no more names", "service", svc.Name,
			"left_out", len(names)-room, "max", MaxNames)
		if m.RelayReport != nil {
			m.RelayReport(svc.Name, slices.Clone(names[room:]), ErrTooManyNames)
		}
		names = names[:room]
	}
	return names
}

// relayOutcome keeps the back-off of a site's relays' names after an order
// that had them, and reports it.
func (m *Manager) relayOutcome(site string, names []string, err error, now time.Time) {
	if m.relayFails == nil {
		m.relayFails, m.relayNext, m.relayLast = map[string]int{}, map[string]time.Time{}, map[string]time.Time{}
	}
	if err != nil {
		m.relayFails[site]++
		m.relayNext[site], m.relayLast[site] = now.Add(backoff(m.relayFails[site])), now
	} else {
		delete(m.relayFails, site)
		delete(m.relayNext, site)
		delete(m.relayLast, site)
	}
	if m.RelayReport != nil {
		m.RelayReport(site, slices.Clone(names), err)
	}
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
