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
	Log    *slog.Logger
	// Every is the check interval; failures back off from it up to a day.
	Every time.Duration

	fails map[string]int
	next  map[string]time.Time
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
		case <-time.After(every):
		}
	}
}

// Once issues what is due and returns how many certificates it stored.
func (m *Manager) Once(ctx context.Context, now time.Time) int {
	if m.fails == nil {
		m.fails, m.next = map[string]int{}, map[string]time.Time{}
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
		name := provision.SiteName(svc)
		secrets, err := m.Store.ServiceSecrets(ctx, svc.ID)
		if err != nil {
			m.log().Error("certificates", "service", svc.Name, "err", err)
			continue
		}
		if !due(secrets[provision.SecretTLSChain], name, now) {
			continue
		}
		if err := m.issue(ctx, svc, name); err != nil {
			m.fails[svc.Name]++
			wait := min(time.Hour<<min(m.fails[svc.Name]-1, 5), 24*time.Hour)
			m.next[svc.Name] = now.Add(wait)
			m.log().Warn("certificate not issued, retrying later", "service", svc.Name, "name", name, "in", wait, "err", err)
			continue
		}
		delete(m.fails, svc.Name)
		delete(m.next, svc.Name)
		stored++
	}
	if stored > 0 && m.Notify != nil {
		m.Notify()
	}
	return stored
}

// due reports whether a chain is missing, for another name, or up for
// renewal.
func due(chainPEM []byte, name string, now time.Time) bool {
	block, _ := pem.Decode(chainPEM)
	if block == nil {
		return true
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !slices.Contains(leaf.DNSNames, name) {
		return true
	}
	return !now.Before(RenewAt(leaf))
}

func (m *Manager) issue(ctx context.Context, svc store.Service, name string) error {
	// RSA: its longer chain fits REALITY with ML-DSA-65 (R2-8, R2-12).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	chain, err := m.Issue(ctx, []string{name}, key)
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
	// Key first: a chain without its key is never rendered.
	if err := m.Store.SetServiceSecret(ctx, svc.ID, provision.SecretTLSKey, keyDER); err != nil {
		return err
	}
	if err := m.Store.SetServiceSecret(ctx, svc.ID, provision.SecretTLSChain, pemChain.Bytes()); err != nil {
		return err
	}
	m.log().Info("certificate stored", "service", svc.Name, "name", name)
	return nil
}
