package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
type Manager struct {
	Store *store.Store
	// Issue gets a chain for names (Issuer.Issue).
	Issue func(ctx context.Context, names []string, key crypto.Signer) ([][]byte, error)
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
		case <-time.After(every):
		}
	}
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
		if svc.Kind != "site" || !svc.Enabled || now.Before(m.next[svc.Name]) {
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
		if !due(chain, want, now) {
			continue
		}
		order := want
		if m.Wildcard != nil {
			if d := m.Wildcard(ctx); d != "" && underWildcard(want, d) {
				order = []string{"*." + d}
			}
		}
		err = m.issue(ctx, svc, order)
		if err != nil && len(next) > 0 && len(order) == len(want) && due(chain, names, now) {
			m.log().Warn("certificate with the next name not issued, renewing without it", "service", svc.Name, "err", err)
			err = m.issue(ctx, svc, names)
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

func (m *Manager) issue(ctx context.Context, svc store.Service, names []string) error {
	// RSA: its longer chain fits REALITY with ML-DSA-65 (R2-8, R2-12).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	chain, err := m.Issue(ctx, names, key)
	if err != nil {
		return err
	}
	var pemChain bytes.Buffer
	for _, der := range chain {
		if err := pem.Encode(&pemChain, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return err
		}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	// Together: a render between the two would pair a key with another chain.
	if err := m.Store.UpdateService(ctx, svc.ID, store.ServiceUpdate{Set: map[string][]byte{
		provision.SecretTLSKey: keyDER, provision.SecretTLSChain: pemChain.Bytes(),
	}}); err != nil {
		return err
	}
	m.log().Info("certificate stored", "service", svc.Name, "names", len(names))
	return nil
}
