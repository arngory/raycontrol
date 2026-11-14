package certfile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/testca"
)

// node is a TLS server whose certificate comes from a Loader's files, and
// the CA that signs for its key, as ACME does at every renewal.
type node struct {
	t          *testing.T
	ca         *testca.CA
	key        *rsa.PrivateKey
	chain, pem string // the files
	l          *Loader
	addr       string
	roots      *x509.CertPool
}

func newKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// write replaces a file as rayd does: a finished file renamed over it.
func write(t *testing.T, path string, content []byte) {
	t.Helper()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		t.Fatal(err)
	}
}

func newNode(t *testing.T) *node {
	t.Helper()
	ca, err := testca.NewCA(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	n := &node{t: t, ca: ca, chain: filepath.Join(dir, "chain.pem"), pem: filepath.Join(dir, "key.pem"), roots: x509.NewCertPool()}
	n.roots.AppendCertsFromPEM(ca.RootPEM)
	var keyPEM []byte
	n.key, keyPEM = newKey(t)
	write(t, n.pem, keyPEM)
	write(t, n.chain, n.issue(n.key))
	n.l = &Loader{Chain: n.chain, Key: n.pem}
	if err := n.l.Load(); err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: n.l.GetCertificate})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	n.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }() // an echo: the connection is in use
		}
	}()
	return n
}

// issue is a new certificate for key: another leaf each time.
func (n *node) issue(key *rsa.PrivateKey) []byte {
	n.t.Helper()
	chain, err := n.ca.Issue([]string{"site.example.test"}, &key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		n.t.Fatal(err)
	}
	return testca.PEM(chain)
}

// dial makes a new handshake and returns the connection and the leaf the
// server answered with.
func (n *node) dial() (*tls.Conn, []byte) {
	n.t.Helper()
	c, err := tls.Dial("tcp", n.addr, &tls.Config{RootCAs: n.roots, ServerName: "site.example.test"})
	if err != nil {
		n.t.Fatal(err)
	}
	n.t.Cleanup(func() { c.Close() })
	return c, c.ConnectionState().PeerCertificates[0].Raw
}

func leafOf(t *testing.T, chainPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(chainPEM)
	if block == nil {
		t.Fatal("no certificate")
	}
	return block.Bytes
}

func echo(t *testing.T, c *tls.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatalf("an open connection: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != msg {
		t.Fatalf("an open connection: %q %v", got, err)
	}
}

// A renewed chain is served at the next handshake, and the connection that
// was open goes on. Files that make no certificate (truncated, empty,
// garbage, a chain for another key, a missing file) leave the one in use,
// and say why once.
func TestLoaderReload(t *testing.T) {
	n := newNode(t)
	first, _ := os.ReadFile(n.chain)
	open, leaf := n.dial()
	if !bytes.Equal(leaf, leafOf(t, first)) {
		t.Fatal("the first handshake did not get the certificate of the files")
	}
	echo(t, open, "before")
	// Nothing changed: nothing reloaded.
	if changed, err := n.l.Reload(); changed || err != nil {
		t.Fatalf("unchanged files: %v %v", changed, err)
	}

	renewed := n.issue(n.key)
	write(t, n.chain, renewed)
	if changed, err := n.l.Reload(); !changed || err != nil {
		t.Fatalf("a renewed chain: %v %v", changed, err)
	}
	if _, leaf := n.dial(); !bytes.Equal(leaf, leafOf(t, renewed)) {
		t.Fatal("a new handshake did not get the renewed certificate")
	}
	echo(t, open, "after the renewal") // not cut

	otherKey, otherKeyPEM := newKey(t)
	for name, content := range map[string][]byte{
		"a truncated chain":       renewed[:len(renewed)/3],
		"an empty chain":          {},
		"garbage":                 []byte("not a certificate\n"),
		"a key in the chain file": otherKeyPEM,
		"a chain for another key": n.issue(otherKey),
	} {
		write(t, n.chain, content)
		changed, err := n.l.Reload()
		if changed || err == nil {
			t.Fatalf("%s: reloaded %v, err %v", name, changed, err)
		}
		// The error is the parser's: none of the file's contents.
		if strings.Contains(err.Error(), "BEGIN") || (len(content) > 40 && strings.Contains(err.Error(), string(content[30:40]))) {
			t.Fatalf("%s: the error carries the file: %v", name, err)
		}
		// The same contents again: not parsed, not reported again.
		if changed, err := n.l.Reload(); changed || err != nil {
			t.Fatalf("%s, second look: %v %v", name, changed, err)
		}
		if _, leaf := n.dial(); !bytes.Equal(leaf, leafOf(t, renewed)) {
			t.Fatalf("%s replaced the certificate in use", name)
		}
	}
	// The file gone (never so with rayd's rename, but a hand may do it).
	if err := os.Remove(n.chain); err != nil {
		t.Fatal(err)
	}
	if changed, err := n.l.Reload(); changed || err == nil {
		t.Fatalf("a missing chain: %v %v", changed, err)
	}
	if changed, err := n.l.Reload(); changed || err != nil {
		t.Fatalf("a missing chain, second look: %v %v", changed, err)
	}
	if _, leaf := n.dial(); !bytes.Equal(leaf, leafOf(t, renewed)) {
		t.Fatal("a missing chain replaced the certificate in use")
	}
	echo(t, open, "after the broken files")

	// A good one again: taken, also when it is the one that was in use
	// before the broken ones.
	write(t, n.chain, renewed)
	if changed, err := n.l.Reload(); !changed || err != nil {
		t.Fatalf("the chain back: %v %v", changed, err)
	}
	last := n.issue(n.key)
	write(t, n.chain, last)
	if changed, err := n.l.Reload(); !changed || err != nil {
		t.Fatalf("the next renewal: %v %v", changed, err)
	}
	if _, leaf := n.dial(); !bytes.Equal(leaf, leafOf(t, last)) {
		t.Fatal("the next renewal is not served")
	}
	echo(t, open, "at the end")

	// A new key with its chain, both files (the unit restarts for it on a
	// node; a process that could read the new key would take it).
	write(t, n.pem, otherKeyPEM)
	rekeyed := n.issue(otherKey)
	write(t, n.chain, rekeyed)
	if changed, err := n.l.Reload(); !changed || err != nil {
		t.Fatalf("a new key and chain: %v %v", changed, err)
	}
	if _, leaf := n.dial(); !bytes.Equal(leaf, leafOf(t, rekeyed)) {
		t.Fatal("the certificate of the new key is not served")
	}
}

// logs collects a logger's lines.
type logs struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Watch takes a new chain by itself, while handshakes go on, and logs a
// reload and a broken file once each, without the files' contents.
func TestLoaderWatch(t *testing.T) {
	n := newNode(t)
	var out logs
	n.l.Log = slog.New(slog.NewTextHandler(&out, nil))
	n.l.Every = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.l.Watch(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	// Handshakes all the while: the race detector sees them with the reloads.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			c, err := tls.Dial("tcp", n.addr, &tls.Config{RootCAs: n.roots, ServerName: "site.example.test"})
			if err != nil {
				t.Errorf("a handshake during the reloads: %v", err)
				return
			}
			c.Close()
		}
	}()
	defer func() { close(stop); wg.Wait() }()

	served := func(want []byte) bool {
		for range 500 {
			if _, leaf := n.dial(); bytes.Equal(leaf, want) {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	renewed := n.issue(n.key)
	write(t, n.chain, renewed)
	if !served(leafOf(t, renewed)) {
		t.Fatal("the renewed chain is not served")
	}
	write(t, n.chain, renewed[:len(renewed)/2])
	time.Sleep(100 * time.Millisecond) // ten looks at the broken file
	if _, leaf := n.dial(); !bytes.Equal(leaf, leafOf(t, renewed)) {
		t.Fatal("a truncated chain replaced the certificate in use")
	}
	last := n.issue(n.key)
	write(t, n.chain, last)
	if !served(leafOf(t, last)) {
		t.Fatal("the chain after the broken one is not served")
	}

	got := out.String()
	if c := strings.Count(got, "certificate reloaded"); c != 2 {
		t.Errorf("%d reloads logged, want 2:\n%s", c, got)
	}
	if c := strings.Count(got, "certificate not reloaded"); c != 1 {
		t.Errorf("the broken file logged %d times, want once:\n%s", c, got)
	}
	// No certificate and no key in the log, whole or in part.
	keyPEM, _ := os.ReadFile(n.pem)
	for _, secret := range [][]byte{keyPEM, renewed, last} {
		block, _ := pem.Decode(secret)
		b64 := base64.StdEncoding.EncodeToString(block.Bytes)
		if strings.Contains(got, "BEGIN") || strings.Contains(got, b64[:24]) || strings.Contains(got, b64[len(b64)/2:len(b64)/2+24]) {
			t.Fatalf("the log carries a file's contents:\n%s", got)
		}
	}
}

// Without a certificate the first load fails, and nothing is served.
func TestLoaderLoad(t *testing.T) {
	dir := t.TempDir()
	l := &Loader{Chain: filepath.Join(dir, "chain.pem"), Key: filepath.Join(dir, "key.pem")}
	if err := l.Load(); err == nil {
		t.Fatal("loaded without files")
	}
	if _, err := l.GetCertificate(nil); err == nil || l.Current() != nil {
		t.Fatal("a certificate before the first load")
	}
	_, keyPEM := newKey(t)
	write(t, l.Key, keyPEM)
	write(t, l.Chain, []byte("garbage"))
	if err := l.Load(); err == nil {
		t.Fatal("loaded garbage")
	}
	// Parse decides what a certificate is (the site wants a chain long
	// enough for REALITY).
	n := newNode(t)
	refuse := &Loader{Chain: n.chain, Key: n.pem, Parse: func(chain, key []byte) (tls.Certificate, error) {
		return tls.Certificate{}, net.ErrClosed
	}}
	if err := refuse.Load(); err == nil {
		t.Fatal("Parse's refusal was not kept")
	}
}
