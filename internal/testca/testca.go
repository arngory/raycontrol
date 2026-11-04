// Package testca makes certificates for tests: a root, an intermediate and
// a leaf, RSA, with a chain long enough for REALITY with ML-DSA-65 (R2-8),
// as an ACME certificate is. Never for a real node.
package testca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// Chain is a leaf for the names under a fresh test root.
type Chain struct {
	ChainPEM []byte // leaf, intermediate, root
	KeyPEM   []byte // the leaf's key, PKCS#8
	RootPEM  []byte // what clients trust
}

// New makes a chain for names (a wildcard such as *.example.test counts)
// valid from notBefore to notAfter.
func New(names []string, notBefore, notAfter time.Time) (Chain, error) {
	var out Chain
	keys := make([]*rsa.PrivateKey, 3)
	for i, bits := range []int{4096, 4096, 2048} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return out, err
		}
		keys[i] = k
	}
	serial := time.Now().UnixNano()
	mk := func(cn string, isCA bool, dns []string, key *rsa.PrivateKey, parent *x509.Certificate, signer *rsa.PrivateKey) (*x509.Certificate, error) {
		serial++
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
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
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(der)
	}
	root, err := mk("raycontrol test root", true, nil, keys[0], nil, keys[0])
	if err != nil {
		return out, err
	}
	inter, err := mk("raycontrol test intermediate", true, nil, keys[1], root, keys[0])
	if err != nil {
		return out, err
	}
	cn := ""
	if len(names) > 0 {
		cn = names[0]
	}
	leaf, err := mk(cn, false, names, keys[2], inter, keys[1])
	if err != nil {
		return out, err
	}
	var chain bytes.Buffer
	for _, c := range []*x509.Certificate{leaf, inter, root} {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(keys[2])
	if err != nil {
		return out, err
	}
	out.ChainPEM = chain.Bytes()
	out.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	out.RootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	return out, nil
}
