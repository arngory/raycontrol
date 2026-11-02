package provision

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func target(t *testing.T, pad int, cfg func(*tls.Config)) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "target.test"}, DNSNames: []string{"target.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	if pad > 0 {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1}, Value: make([]byte, pad)}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	realityRoots = x509.NewCertPool()
	realityRoots.AddCert(cert)
	t.Cleanup(func() { realityRoots = nil })
	c := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h2", "http/1.1"}}
	if cfg != nil {
		cfg(c)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.NotFoundHandler())
	return ln.Addr().String()
}

func TestCheckRealityTarget(t *testing.T) {
	ctx := context.Background()
	if err := CheckRealityTarget(ctx, target(t, 4096, nil), "target.test"); err != nil {
		t.Fatalf("good target: %v", err)
	}
	for name, tc := range map[string]struct {
		pad  int
		cfg  func(*tls.Config)
		sni  string
		want string
	}{
		"short chain": {pad: 0, want: "certificate chain"},
		"no ML-KEM":   {pad: 4096, cfg: func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519} }, want: "X25519MLKEM768"},
		"TLS 1.2":     {pad: 4096, cfg: func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }, want: "TLS 1.3"},
		"no HTTP/2":   {pad: 4096, cfg: func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} }, want: "HTTP/2"},
		"wrong name":  {pad: 4096, sni: "other.test", want: "certificate"},
	} {
		sni := tc.sni
		if sni == "" {
			sni = "target.test"
		}
		err := CheckRealityTarget(ctx, target(t, tc.pad, tc.cfg), sni)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error about %s", name, err, tc.want)
		}
	}
	if err := CheckRealityTarget(ctx, "/run/niko/site/site.sock", "x.example.com"); err != nil {
		t.Fatalf("unix target: %v", err)
	}
}

func TestRealityTarget(t *testing.T) {
	for in, want := range map[string]string{
		`{"target":"www.example.org:443"}`:               "www.example.org:443 www.example.org",
		`{"target":"203.0.113.9:443","sni":"a.example"}`: "203.0.113.9:443 a.example",
		`{"target":"203.0.113.9:443"}`:                   "error",
		`{}`:                                             "error",
		`{"target":"www.example.org"}`:                   "error",
		`{"target":"/run/site.sock","sni":"s.example"}`:  "/run/site.sock s.example",
	} {
		target, sni, err := RealityTargetFromJSON(in)
		got := target + " " + sni
		if err != nil {
			got = "error"
		}
		if got != want {
			t.Errorf("%s: %q, want %q (%v)", in, got, want, err)
		}
	}
}
