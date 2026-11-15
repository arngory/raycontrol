// Package rootstest gives tests a node trust of their own (roots.Node):
// the embedded list, plus what the test names, so that the clients under
// test verify their test servers through the package that decides in
// production, not through a client of the test's.
package rootstest

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/arngory/raycontrol/internal/roots"
)

// Use makes roots.Node a trust with settings s and a system store holding
// system, until the test ends. Tests that call it must not run in
// parallel with others that use roots.Node.
func Use(t testing.TB, s roots.Settings, system ...*x509.Certificate) *roots.Trust {
	t.Helper()
	tr := &roots.Trust{Fixed: &s, System: func() (*x509.CertPool, error) {
		p := x509.NewCertPool()
		for _, c := range system {
			p.AddCert(c)
		}
		return p, nil
	}}
	old := roots.Node
	roots.Node = tr
	t.Cleanup(func() { roots.Node = old })
	return tr
}

// File writes certificates to a PEM file in the test's directory and
// returns its path: the extra file of roots.Settings.
func File(t testing.TB, certs ...*x509.Certificate) string {
	t.Helper()
	var b []byte
	for _, c := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	p := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
