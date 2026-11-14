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
	"log/slog"
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

	once  sync.Once
	fails map[string]int
	next  map[string]time.Time
	last  map[string]time.Time // the last failed try of a site
	wake  chan struct{}
	retry atomic.Bool
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
	return every
}

// Once issues what is due and returns how many certificates it stored.
func (m *Manager) Once(ctx context.Context, now time.Time) int {
	if m.fails == nil {
		m.fails, m.next, m.last = map[string]int{}, map[string]time.Time{}, map[string]time.Time{}
	}
	// From the last try, not from next: changes in a row (a cron job) keep
	// the gap however many there are.
	if m.retry.Swap(false) {
		for name, next := range m.next {
			if soon := m.last[name].Add(RetryGap); soon.Before(next) {
				m.next[name] = soon
			}
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
		// it gets it at the first check, and its pins go into subscriptions.
		// Whatever the back-off: no order is made for it.
		if made, err := provision.EnsureSiteNextKey(ctx, m.Store, svc.ID, now); err != nil {
			m.log().Error("certificates: next key", "service", svc.Name, "err", err)
		} else if made {
			m.log().Info("next certificate key made; its pin is in subscriptions from now", "service", svc.Name)
		}
		if now.Before(m.next[svc.Name]) {
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
		want := append(slices.Clone(names), next...)
		// Due, or the operator asked for the next key (rayctl service
		// rotate SITE): the switch is an issuance with it.
		rotate := provision.ParseSiteKeyState(svc).RotateAt != 0
		if !due(chain, want, now) && !rotate {
			continue
		}
		order := want
		if m.Wildcard != nil {
			if d := m.Wildcard(ctx); d != "" && underWildcard(want, d) {
				order = []string{"*." + d}
			}
		}
		err = m.issue(ctx, svc, order, now)
		if err != nil && !errors.Is(err, provision.ErrSiteChanged) && len(next) > 0 && len(order) == len(want) && (rotate || due(chain, names, now)) {
			m.log().Warn("certificate with the next name not issued, renewing without it", "service", svc.Name, "err", err)
			err = m.issue(ctx, svc, names, now)
		}
		if errors.Is(err, provision.ErrSiteChanged) {
			// The operator's certificate came during the order: theirs
			// stays, and the next check looks at it. No failure.
			m.log().Info("certificate not stored: the site changed during the order", "service", svc.Name)
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
	}
	if stored > 0 && m.Notify != nil {
		m.Notify()
	}
	return stored
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

// underWildcard reports whether *.domain covers every name: each one label
// below the domain.
func underWildcard(names []string, domain string) bool {
	for _, n := range names {
		label, ok := strings.CutSuffix(n, "."+domain)
		if !ok || label == "" || strings.Contains(label, ".") {
			return false
		}
	}
	return len(names) > 0
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
	if err := provision.StoreSiteCertificate(ctx, m.Store, svc.ID, pemChain.Bytes(), plan, now); err != nil {
		return err
	}
	// Which key, never the key or its pin.
	m.log().Info("certificate stored", "service", svc.Name, "names", len(names), "key", plan.What)
	return nil
}
