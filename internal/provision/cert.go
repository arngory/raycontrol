package provision

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"time"

	"github.com/arngory/raycontrol/internal/site"
	"github.com/arngory/raycontrol/internal/store"
)

// Certificate is what SetCertificate stored.
type Certificate struct {
	Names       []string // the site's names in use, all covered
	NotAfter    time.Time
	MissingNext []string // names of REALITY's next switch it does not cover
	// Unpinned: the lines of the services under the site carried the pins
	// of the node's keys (SiteKeyPins), and this certificate has another
	// key. Clients fail their pin until they get their subscription again,
	// whose lines carry none now (spec/cert-pin-v1.md §7).
	Unpinned bool
}

// SetCertificate puts the operator's own certificate on a site in place of
// one from ACME: a CA of their own, another ACME client, a test CA. It must
// pair with the key, be valid now, cover every name the site serves and be
// long enough for REALITY (R2-8), as the site process checks it.
//
// The site is marked as having the operator's certificate: the node cannot
// promise the key of the one after it, so the lines of naive, hy2-masq and
// DoH under the site carry no pins from now (spec/cert-pin-v1.md §7), and a
// key change the operator asked for is off. The next key stays: the
// certificate manager takes it when it issues for the site again
// (PlanSiteIssue).
func SetCertificate(ctx context.Context, st *store.Store, name string, chainPEM, keyPEM []byte, now time.Time) (Certificate, error) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	var out Certificate
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		return out, err
	}
	if svc.Kind != "site" {
		return out, fmt.Errorf("%w service %s is a %s; certificates belong to a site", store.ErrInvalid, name, svc.Kind)
	}
	cert, err := site.LoadCertificate(chainPEM, keyPEM, RealityChainMin(), nil)
	if err != nil {
		return out, fmt.Errorf("%w certificate: %w", store.ErrInvalid, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return out, fmt.Errorf("%w certificate: %w", store.ErrInvalid, err)
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return out, fmt.Errorf("%w certificate valid from %s to %s, not now", store.ErrInvalid,
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	all, err := st.ListServices(ctx)
	if err != nil {
		return out, err
	}
	names, next := SiteNames(svc, all)
	for _, n := range names {
		if leaf.VerifyHostname(n) != nil {
			return out, fmt.Errorf("%w certificate does not cover %s, a name the site serves", store.ErrInvalid, n)
		}
	}
	for _, n := range next {
		if leaf.VerifyHostname(n) != nil {
			out.MissingNext = append(out.MissingNext, n)
		}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return out, fmt.Errorf("%w key: %w", store.ErrInvalid, err)
	}
	var chain bytes.Buffer
	for _, der := range cert.Certificate {
		if err := pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return out, err
		}
	}
	secrets, err := st.ServiceSecrets(ctx, svc.ID)
	if err != nil {
		return out, err
	}
	pinned := SiteKeyPins(svc, secrets)
	settings, err := setFields(svc.Settings, map[string]any{"tls_imported": true, "tls_rotate_at": nil})
	if err != nil {
		return out, err
	}
	// Together, as the certificate manager stores them.
	if err := st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings, Set: map[string][]byte{
		SecretTLSKey: keyDER, SecretTLSChain: chain.Bytes(),
	}}); err != nil {
		return out, err
	}
	out.Names, out.NotAfter = names, leaf.NotAfter
	out.Unpinned = len(pinned) > 0 && !slices.Contains(pinned, leafPin(leaf))
	return out, nil
}
