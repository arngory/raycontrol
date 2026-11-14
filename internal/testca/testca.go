// Package testca makes certificates for tests: a root, an intermediate and
// a leaf, RSA, with a chain long enough for REALITY with ML-DSA-65 (R2-8),
// as an ACME certificate is. Never for a real node.
package testca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync/atomic"
	"time"
)

// Chain is a leaf for the names under a fresh test root.
type Chain struct {
	ChainPEM []byte // leaf, intermediate, root
	KeyPEM   []byte // the leaf's key, PKCS#8
	RootPEM  []byte // what clients trust
}

// CA is a test root and its intermediate. It signs leaves for keys given to
// it, as an ACME CA does for the key of a CSR: the same key may get one
// certificate after another.
type CA struct {
	RootPEM []byte // what clients trust

	root, inter *x509.Certificate
	interKey    *rsa.PrivateKey
	serial      atomic.Int64
}

func (c *CA) mk(cn string, isCA bool, dns []string, pub crypto.PublicKey, parent *x509.Certificate, signer *rsa.PrivateKey,
	notBefore, notAfter time.Time) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(c.serial.Add(1)), Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
		NotBefore: notBefore, NotAfter: notAfter, IsCA: isCA, BasicConstraintsValid: true}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// NewCA makes a root and an intermediate valid from notBefore to notAfter.
func NewCA(notBefore, notAfter time.Time) (*CA, error) {
	c := &CA{}
	c.serial.Store(time.Now().UnixNano())
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	if c.interKey, err = rsa.GenerateKey(rand.Reader, 4096); err != nil {
		return nil, err
	}
	if c.root, err = c.mk("raycontrol test root", true, nil, &rootKey.PublicKey, nil, rootKey, notBefore, notAfter); err != nil {
		return nil, err
	}
	if c.inter, err = c.mk("raycontrol test intermediate", true, nil, &c.interKey.PublicKey, c.root, rootKey, notBefore, notAfter); err != nil {
		return nil, err
	}
	c.RootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.root.Raw})
	return c, nil
}

// Issue signs a leaf for names (a wildcard such as *.example.test counts)
// and the public key pub, valid from notBefore to notAfter, and returns the
// chain in DER: leaf, intermediate, root.
func (c *CA) Issue(names []string, pub crypto.PublicKey, notBefore, notAfter time.Time) ([][]byte, error) {
	cn := ""
	if len(names) > 0 {
		cn = names[0]
	}
	leaf, err := c.mk(cn, false, names, pub, c.inter, c.interKey, notBefore, notAfter)
	if err != nil {
		return nil, err
	}
	return [][]byte{leaf.Raw, c.inter.Raw, c.root.Raw}, nil
}

// PEM is a chain of Issue as PEM, leaf first.
func PEM(chain [][]byte) []byte {
	var out bytes.Buffer
	for _, der := range chain {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return out.Bytes()
}

// New makes a chain for names (a wildcard such as *.example.test counts)
// valid from notBefore to notAfter, with a key of its own.
func New(names []string, notBefore, notAfter time.Time) (Chain, error) {
	var out Chain
	ca, err := NewCA(notBefore, notAfter)
	if err != nil {
		return out, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return out, err
	}
	chain, err := ca.Issue(names, &key.PublicKey, notBefore, notAfter)
	if err != nil {
		return out, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return out, err
	}
	out.ChainPEM = PEM(chain)
	out.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	out.RootPEM = ca.RootPEM
	return out, nil
}
