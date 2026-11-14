package roots

import (
	"bytes"
	"crypto/x509"
	"sync"
	"time"
)

// EmbeddedPool is the embedded list as a pool.
var EmbeddedPool = sync.OnceValue(func() *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range Embedded() {
		p.AddCert(c)
	}
	return p
})

// ChainKind is what a client of the node would make of a certificate
// chain of the administrator's (rayctl service cert).
type ChainKind int

const (
	// Public: the chain leads to a root of the embedded list, which the
	// clients' lists hold too (Chrome's without CAs based in China, and
	// Mozilla's).
	Public ChainKind = iota
	// Private: the chain leads to a root it carries itself, one not in
	// the list (a private CA).
	Private
	// Incomplete: the chain stops at a certificate whose issuer is in
	// neither the chain nor the list.
	Incomplete
	// Invalid: the chain leads to a root, of the list or its own, but
	// does not verify for another reason (a leaf without serverAuth, an
	// expired intermediate).
	Invalid
)

// ChainCheck is CheckChain's answer.
type ChainCheck struct {
	Kind ChainKind
	// Root is the root the chain leads to (Public, Private, Invalid); for
	// Incomplete, Top is the last certificate and Issuer its issuer.
	Root, Top, Issuer string
	// Listed: an Invalid chain's root is in the embedded list.
	Listed bool
	// Reason is why an Invalid chain does not verify.
	Reason string
}

// CheckChain says which of the three a PEM chain, leaf first, is at now,
// against the embedded list: a warning for the administrator, never a
// refusal (a private CA is a legitimate choice).
func CheckChain(chainPEM []byte, now time.Time) ChainCheck {
	cs, err := ParsePEM(chainPEM)
	if err != nil {
		return ChainCheck{Kind: Incomplete}
	}
	leaf, rest := cs[0], cs[1:]
	inter := x509.NewCertPool()
	own := x509.NewCertPool()
	for _, c := range rest {
		inter.AddCert(c)
		if selfSigned(c) {
			own.AddCert(c)
		}
	}
	opts := x509.VerifyOptions{Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	opts.Roots = EmbeddedPool()
	chains, pubErr := leaf.Verify(opts)
	if pubErr == nil {
		return ChainCheck{Kind: Public, Root: name(chains[0][len(chains[0])-1])}
	}
	opts.Roots = own
	chains, ownErr := leaf.Verify(opts)
	if ownErr == nil {
		return ChainCheck{Kind: Private, Root: name(chains[0][len(chains[0])-1])}
	}
	if selfSigned(leaf) {
		return ChainCheck{Kind: Private, Root: name(leaf)} // its own root
	}
	// Up from the leaf as far as the chain goes: a root of the list on
	// the way, or its own at the top, and the chain is complete but
	// refused for another reason (Verify's).
	top := leaf
	for range len(cs) {
		if r := issuerIn(top, Embedded()); r != nil {
			return ChainCheck{Kind: Invalid, Root: name(r), Listed: true, Reason: pubErr.Error()}
		}
		if listed(top) {
			return ChainCheck{Kind: Invalid, Root: name(top), Listed: true, Reason: pubErr.Error()}
		}
		parent := issuerIn(top, rest)
		if parent == nil || parent == top {
			break
		}
		top = parent
	}
	if top != leaf && selfSigned(top) {
		return ChainCheck{Kind: Invalid, Root: name(top), Reason: ownErr.Error()}
	}
	return ChainCheck{Kind: Incomplete, Top: name(top), Issuer: issuerName(top)}
}

// listed reports whether c is a root of the embedded list (by its key, as
// the list was made).
func listed(c *x509.Certificate) bool {
	if !selfSigned(c) {
		return false
	}
	for _, r := range Embedded() {
		if bytes.Equal(r.RawSubjectPublicKeyInfo, c.RawSubjectPublicKeyInfo) && bytes.Equal(r.RawSubject, c.RawSubject) {
			return true
		}
	}
	return false
}

func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

func issuerIn(c *x509.Certificate, cs []*x509.Certificate) *x509.Certificate {
	if selfSigned(c) {
		return nil
	}
	for _, p := range cs {
		if bytes.Equal(p.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(p) == nil {
			return p
		}
	}
	return nil
}

func name(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

func issuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	return c.Issuer.String()
}
