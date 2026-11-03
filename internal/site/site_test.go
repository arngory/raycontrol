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
	"net/http/httptest"
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
	pages, _ := Responder(AnswerPages, filepath.Join(dir, "www"))
	go Serve(ctx, ln, pages, cert, slog.New(slog.NewTextHandler(io.Discard, nil)))

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

func TestServeTLS12(t *testing.T) {
	root := newCert(t, nil, "Test Root", true)
	leaf := newCert(t, root, "k3f.example.com", false)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leaf.key)
	cert, err := LoadCertificate(pemOf(leaf), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "tls.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, ln, Handler(t.TempDir()), cert, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// A probe that speaks only TLS 1.2 gets a handshake, like at most sites.
	c, err := tls.Dial("unix", sock, &tls.Config{ServerName: "k3f.example.com", InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}) //nolint:gosec // looking at the version
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if v := c.ConnectionState().Version; v != tls.VersionTLS12 {
		t.Fatalf("version %x", v)
	}
}

// Whoever REALITY hands the site gets nothing usable by default: an empty
// 404 or 403, or no answer at all (R4-8).
func TestResponder(t *testing.T) {
	for mode, code := range map[string]int{"": 404, Answer404: 404, Answer403: 403} {
		h, err := Responder(mode, "")
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(h)
		resp, err := http.Post(srv.URL+"/wp-login.php?x=1", "text/plain", strings.NewReader("probe"))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		srv.Close()
		if resp.StatusCode != code || len(body) != 0 || resp.Header.Get("Server") != "" || resp.Header.Get("Content-Type") != "" {
			t.Errorf("%q: %d %q %v", mode, resp.StatusCode, body, resp.Header)
		}
	}

	old := SilentHold
	SilentHold = 200 * time.Millisecond
	defer func() { SilentHold = old }()
	h, _ := Responder(AnswerSilent, "")
	srv := httptest.NewServer(h)
	defer srv.Close()
	start := time.Now()
	resp, err := http.Get(srv.URL + "/")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("silent site answered %s", resp.Status)
	}
	if time.Since(start) < SilentHold {
		t.Fatalf("dropped after %v, before the hold", time.Since(start))
	}

	if _, err := Responder(AnswerPages, ""); err == nil {
		t.Error("pages without a directory")
	}
	if _, err := Responder("teapot", ""); err == nil {
		t.Error("unknown answer accepted")
	}
}

// Routed: a routed name goes to its socket still encrypted; anything else
// is served by the site (R2-13).
