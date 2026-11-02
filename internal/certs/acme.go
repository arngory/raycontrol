// Package certs gets certificates for the node's names from an ACME CA
// (Let's Encrypt by default) with HTTP-01. All ports are closed, so every
// order opens a short window in the perimeter: TCP 80 from any address goes
// to a responder that answers only the order's challenges
// (docs/08-decisions.md, R2-11).
package certs

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// LetsEncrypt is the default ACME directory.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// WindowLen bounds an order: the window closes after it at the latest, also
// in nftables if rayd dies in between.
const WindowLen = 3 * time.Minute

// Issuer runs ACME orders.
type Issuer struct {
	Directory  string        // ACME directory URL
	HTTPClient *http.Client  // nil: the default client
	AccountKey crypto.Signer // the node's ACME account key
	// Listen is the HTTP-01 responder address; "" picks a free port, which
	// the perimeter window points TCP 80 to.
	Listen string
	// Window opens the perimeter window to port until the given time, or
	// closes it when until is zero.
	Window func(port uint16, until time.Time)
	// Expect are the node's addresses; every name must resolve to one of
	// them before an order is placed. NodeHost, if Expect is empty, gives
	// them: an address or a name to resolve. Both empty skip the check.
	Expect   []netip.Addr
	NodeHost string
	Resolve  func(ctx context.Context, name string) ([]netip.Addr, error)
	Log      *slog.Logger
}

func (is *Issuer) log() *slog.Logger {
	if is.Log != nil {
		return is.Log
	}
	return slog.Default()
}

// CheckDNS reports a name that does not resolve to the node.
func (is *Issuer) CheckDNS(ctx context.Context, names []string) error {
	resolve := is.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, name string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
		}
	}
	expect := is.Expect
	if len(expect) == 0 && is.NodeHost != "" {
		if a, err := netip.ParseAddr(is.NodeHost); err == nil {
			expect = []netip.Addr{a.Unmap()}
		} else {
			addrs, err := resolve(ctx, is.NodeHost)
			if err != nil {
				return fmt.Errorf("node host %s: %w", is.NodeHost, err)
			}
			for _, a := range addrs {
				expect = append(expect, a.Unmap())
			}
		}
	}
	if len(expect) == 0 {
		return nil
	}
	for _, name := range names {
		addrs, err := resolve(ctx, name)
		if err != nil {
			return fmt.Errorf("%s does not resolve (add the wildcard record *.<domain> A <node address>): %w", name, err)
		}
		ok := false
		for _, a := range addrs {
			ok = ok || slices.Contains(expect, a.Unmap())
		}
		if !ok {
			return fmt.Errorf("%s resolves to %v, not to the node (%v)", name, addrs, expect)
		}
	}
	return nil
}

// Issue gets a certificate for names with key and returns the chain (DER,
// leaf first).
func (is *Issuer) Issue(ctx context.Context, names []string, key crypto.Signer) ([][]byte, error) {
	if err := is.CheckDNS(ctx, names); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, WindowLen)
	defer cancel()
	client := &acme.Client{Key: is.AccountKey, DirectoryURL: is.Directory, HTTPClient: is.HTTPClient, UserAgent: "raycontrol"}
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("acme account: %w", err)
	}

	resp := &responder{tokens: map[string]string{}}
	listen := is.Listen
	if listen == "" {
		listen = ":0"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: resp, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	if is.Window != nil {
		port := uint16(ln.Addr().(*net.TCPAddr).Port)
		is.Window(port, time.Now().Add(WindowLen))
		defer is.Window(0, time.Time{})
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return nil, fmt.Errorf("acme order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := client.GetAuthorization(ctx, u)
		if err != nil {
			return nil, err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "http-01" {
				chal = c
			}
		}
		if chal == nil {
			return nil, fmt.Errorf("acme: no http-01 challenge for %s", z.Identifier.Value)
		}
		ka, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return nil, err
		}
		resp.set(chal.Token, ka)
		if _, err := client.Accept(ctx, chal); err != nil {
			return nil, fmt.Errorf("acme accept %s: %w", z.Identifier.Value, err)
		}
		if _, err := client.WaitAuthorization(ctx, z.URI); err != nil {
			return nil, fmt.Errorf("acme validation of %s: %w", z.Identifier.Value, err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return nil, fmt.Errorf("acme order: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		return nil, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("acme certificate: %w", err)
	}
	is.log().Info("certificate issued", "names", strings.Join(names, ","))
	return chain, nil
}

// responder answers HTTP-01 challenges and nothing else.
type responder struct {
	mu     sync.Mutex
	tokens map[string]string
}

func (r *responder) set(token, keyAuth string) {
	r.mu.Lock()
	r.tokens[token] = keyAuth
	r.mu.Unlock()
}

func (r *responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	token, ok := strings.CutPrefix(req.URL.Path, "/.well-known/acme-challenge/")
	r.mu.Lock()
	ka, found := r.tokens[token]
	r.mu.Unlock()
	if req.Method != http.MethodGet || !ok || !found {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(ka))
}

// RenewAt is when a certificate should be renewed: with a third of its
// lifetime left (Let's Encrypt shortens lifetimes; this follows).
func RenewAt(leaf *x509.Certificate) time.Time {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotAfter.Add(-life / 3)
}
