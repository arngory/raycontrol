package certs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCheckDNS(t *testing.T) {
	node := netip.MustParseAddr("203.0.113.7")
	is := &Issuer{Expect: []netip.Addr{node}, Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
		switch name {
		case "ok.example.com":
			return []netip.Addr{netip.MustParseAddr("::ffff:203.0.113.7")}, nil
		case "other.example.com":
			return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
		}
		return nil, errors.New("no such host")
	}}
	ctx := context.Background()
	if err := is.CheckDNS(ctx, []string{"ok.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := is.CheckDNS(ctx, []string{"ok.example.com", "other.example.com"}); err == nil || !strings.Contains(err.Error(), "not to the node") {
		t.Fatalf("other address: %v", err)
	}
	if err := is.CheckDNS(ctx, []string{"missing.example.com"}); err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("missing name: %v", err)
	}
}

func TestResponder(t *testing.T) {
	r := &responder{tokens: map[string]string{}}
	r.set("tok", "tok.thumb")
	srv := httptest.NewServer(r)
	defer srv.Close()
	for path, want := range map[string]int{
		"/.well-known/acme-challenge/tok":   200,
		"/.well-known/acme-challenge/other": 404,
		"/":                                 404,
		"/index.html":                       404,
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", path, resp.StatusCode, want)
		}
	}
}

func TestRenewAt(t *testing.T) {
	start := time.Unix(1767225600, 0)
	leaf := &x509.Certificate{NotBefore: start, NotAfter: start.Add(90 * 24 * time.Hour)}
	if got := RenewAt(leaf); !got.Equal(start.Add(60 * 24 * time.Hour)) {
		t.Fatalf("renew at %v", got)
	}
}

// TestIssueWithPebble gets a certificate from Pebble, Let's Encrypt's test
// CA, through HTTP-01. CI starts Pebble (httpPort 5002) and
// pebble-challtestsrv, which resolves every name to 127.0.0.1, and sets
// PEBBLE_DIRECTORY.
func TestIssueWithPebble(t *testing.T) {
	dir := os.Getenv("PEBBLE_DIRECTORY")
	if dir == "" {
		t.Skip("set PEBBLE_DIRECTORY to a running Pebble")
	}
	account, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var windows []uint16
	is := &Issuer{
		Directory:  dir,
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}, //nolint:gosec // Pebble's test CA
		AccountKey: account,
		Listen:     "127.0.0.1:5002",
		Window:     func(port uint16, _ time.Time) { windows = append(windows, port) },
	}
	names := []string{"site.raycontrol.test"}
	chain, err := is.Issue(context.Background(), names, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) < 2 {
		t.Fatalf("chain of %d certificates", len(chain))
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(leaf.DNSNames, names) || !leaf.PublicKey.(*rsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatalf("leaf for %v", leaf.DNSNames)
	}
	if !slices.Equal(windows, []uint16{5002, 0}) {
		t.Fatalf("window calls %v: want open on the responder port, then closed", windows)
	}
}

func TestCheckDNSNodeHost(t *testing.T) {
	is := &Issuer{NodeHost: "n.example.com", Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
		switch name {
		case "n.example.com", "s.example.com":
			return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
	}}
	if err := is.CheckDNS(context.Background(), []string{"s.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := is.CheckDNS(context.Background(), []string{"x.example.com"}); err == nil {
		t.Fatal("a name elsewhere accepted")
	}
}

// challtestsrv publishes DNS-01 records in pebble-challtestsrv, whose DNS
// server Pebble asks.
type challtestsrv string

func (c challtestsrv) post(ctx context.Context, path string, body map[string]string) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, string(c)+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	return nil
}

func (c challtestsrv) Present(ctx context.Context, fqdn, value string) error {
	return c.post(ctx, "/set-txt", map[string]string{"host": fqdn + ".", "value": value})
}

func (c challtestsrv) CleanUp(ctx context.Context, fqdn, _ string) error {
	return c.post(ctx, "/clear-txt", map[string]string{"host": fqdn + "."})
}

// A wildcard certificate through DNS-01: no perimeter window (R4-10).
func TestIssueWildcardWithPebble(t *testing.T) {
	dir := os.Getenv("PEBBLE_DIRECTORY")
	if dir == "" {
		t.Skip("set PEBBLE_DIRECTORY to a running Pebble (and pebble-challtestsrv)")
	}
	mgmt := os.Getenv("PEBBLE_CHALLTESTSRV")
	if mgmt == "" {
		mgmt = "http://127.0.0.1:8055"
	}
	account, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	windows := 0
	is := &Issuer{
		Directory:  dir,
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}, //nolint:gosec // Pebble's test CA
		AccountKey: account,
		Window:     func(uint16, time.Time) { windows++ },
		DNS:        func(context.Context) (DNSSolver, error) { return challtestsrv(mgmt), nil },
	}
	names := []string{"*.raycontrol.test"}
	chain, err := is.Issue(context.Background(), names, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(leaf.DNSNames, names) || leaf.VerifyHostname("k3f.raycontrol.test") != nil || windows != 0 {
		t.Fatalf("leaf for %v, windows %d", leaf.DNSNames, windows)
	}
}

func TestWildcardNeedsDNS(t *testing.T) {
	is := &Issuer{}
	if _, err := is.Issue(context.Background(), []string{"*.example.com"}, nil); err == nil || !strings.Contains(err.Error(), "DNS-01") {
		t.Fatalf("wildcard over HTTP-01: %v", err)
	}
}
