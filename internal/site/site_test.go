package site

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	a, err := Generate([]byte("seed one"), "k3f.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Generate([]byte("seed one"), "k3f.example.com", now)
	other, _ := Generate([]byte("seed two"), "k3f.example.com", now)
	for _, f := range []string{"index.html", "about.html", "journal/index.html", "404.html", "style.css", "robots.txt"} {
		if len(a[f]) == 0 {
			t.Fatalf("%s missing", f)
		}
		if !bytes.Equal(a[f], again[f]) {
			t.Fatalf("%s differs for the same seed", f)
		}
	}
	if bytes.Equal(a["index.html"], other["index.html"]) {
		t.Fatal("two seeds, same site")
	}
	posts := 0
	for name := range a {
		if strings.HasPrefix(name, "journal/") && name != "journal/index.html" {
			posts++
			if !strings.Contains(string(a["journal/index.html"]), name[len("journal/"):]) {
				t.Errorf("journal does not link %s", name)
			}
		}
	}
	if posts < 4 {
		t.Fatalf("%d posts", posts)
	}
	if !strings.Contains(string(a["about.html"]), "studio@k3f.example.com") || strings.Contains(string(a["index.html"]), "{{") {
		t.Fatalf("about:\n%s", a["about.html"])
	}
}

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCert(t *testing.T, parent *ca, name string, isCA bool) *ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tmpl.DNSNames = []string{name}
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &ca{c, key}
}

func pemOf(certs ...*ca) []byte {
	var b bytes.Buffer
	for _, c := range certs {
		pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
	}
	return b.Bytes()
}

func TestServe(t *testing.T) {
	root := newCert(t, nil, "Test Root", true)
	inter := newCert(t, root, "Test Intermediate", true)
	leaf := newCert(t, inter, "k3f.example.com", false)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leaf.key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)

	short := chainLen([][]byte{leaf.cert.Raw, inter.cert.Raw})
	cert, err := LoadCertificate(pemOf(leaf, inter), keyPEM, short+1, roots)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 3 || !bytes.Equal(cert.Certificate[2], root.cert.Raw) {
		t.Fatalf("chain not completed with the root: %d certificates", len(cert.Certificate))
	}
	if _, err := LoadCertificate(pemOf(leaf, inter), keyPEM, 1<<20, roots); err == nil {
		t.Fatal("a chain too short for REALITY accepted")
	}

	dir := t.TempDir()
	files, _ := Generate([]byte("seed"), "k3f.example.com", time.Now())
	for name, b := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, "www", name)), 0o755)
		os.WriteFile(filepath.Join(dir, "www", name), b, 0o644)
	}
	sock := filepath.Join(dir, "tls.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, ln, filepath.Join(dir, "www"), cert, slog.New(slog.NewTextHandler(io.Discard, nil)))

	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := tls.Dial("unix", sock, &tls.Config{ServerName: "k3f.example.com", RootCAs: pool, NextProtos: []string{"h2"},
				CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}})
			if err != nil {
				return nil, err
			}
			st := c.ConnectionState()
			if st.Version != tls.VersionTLS13 || st.CurveID != tls.X25519MLKEM768 || st.NegotiatedProtocol != "h2" {
				t.Errorf("TLS %x curve %v alpn %q", st.Version, st.CurveID, st.NegotiatedProtocol)
			}
			return c, nil
		},
		ForceAttemptHTTP2: true,
	}
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for path, want := range map[string]int{"/": 200, "/about.html": 200, "/journal/": 200, "/journal": 301, "/nope": 404, "/../etc/passwd": 404} {
		resp, err := hc.Get("https://k3f.example.com" + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", path, resp.StatusCode, want)
		}
		if want == 404 && !strings.Contains(string(body), "Not found") {
			t.Errorf("%s: no 404 page", path)
		}
		if resp.ProtoMajor != 2 {
			t.Errorf("%s over %s", path, resp.Proto)
		}
	}
}
