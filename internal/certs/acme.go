// Package certs gets certificates for the node's names from an ACME CA
// (Let's Encrypt by default). With a DNS provider (Cloudflare) it uses
// DNS-01 and a wildcard name, and no port opens (R4-10). Without one it uses
// HTTP-01: all ports are closed, so every order opens a short window in the
// perimeter, TCP 80 from any address to a responder that answers only the
// order's challenges (docs/decisions.md, R2-11).
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

	"github.com/arngory/raycontrol/internal/roots"
)

// LetsEncrypt is the default ACME directory.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// WindowLen bounds an order: the window closes after it at the latest, also
// in nftables if rayd dies in between.
const WindowLen = 3 * time.Minute

// DNSOrderLen bounds a DNS-01 order: TXT records take a while to show.
const DNSOrderLen = 8 * time.Minute

// DNSSolver publishes the TXT record of a DNS-01 challenge, returning once
// it is visible, and removes it afterwards (cloudflare.Solver).
type DNSSolver interface {
	Present(ctx context.Context, fqdn, value string) error
	CleanUp(ctx context.Context, fqdn, value string) error
}

// Issuer runs ACME orders.
type Issuer struct {
	Directory  string        // ACME directory URL
	HTTPClient *http.Client  // nil: roots.Node's
	AccountKey crypto.Signer // the node's ACME account key
	// Listen is the HTTP-01 responder address; "" picks a free port, which
	// the perimeter window points TCP 80 to.
	Listen string
	// Window opens the perimeter window for an order of names to port
	// until the given time, or closes it when until is zero.
	Window func(port uint16, until time.Time, names []string)
	// Expect are the node's addresses; every name must resolve to one of
	// them before an order is placed. NodeHost, if Expect is empty, gives
	// them: an address or a name to resolve. Both empty skip the check.
	Expect   []netip.Addr
	NodeHost string
	Resolve  func(ctx context.Context, name string) ([]netip.Addr, error)
	// RelayAddrs, if set, gives the relays' names and the address each
	// resolves to instead of the node's (relay-names-v1 §6): such a name
	// passes CheckDNS when it resolves to its relay alone, and its
	// challenge comes to the node through the relay.
	RelayAddrs func(ctx context.Context) (map[string]netip.Addr, error)
	// DNS returns the DNS-01 solver when the node has a DNS provider (nil
	// solver otherwise): orders then need no perimeter window, and
	// wildcard names become possible (R4-10).
	DNS func(ctx context.Context) (DNSSolver, error)
	Log *slog.Logger
}

func (is *Issuer) log() *slog.Logger {
	if is.Log != nil {
		return is.Log
	}
	return slog.Default()
}

// NamesError is an order refused for some of its names, before it was
// placed (CheckDNS: a relay's name that does not resolve to its relay
// alone) or by the CA (the validation of the name's authorization failed).
// The manager orders again without the relays' names among them
// (relay-names-v1 §5). Err has the detail, addresses in it: for root's
// output (rayctl relay list), not the log, which takes Reason.
type NamesError struct {
	Names  []string
	Reason string
	Err    error
}

func (e *NamesError) Error() string { return e.Err.Error() }
func (e *NamesError) Unwrap() error { return e.Err }

// CheckDNS reports a name that does not resolve to the node, or relays'
// names (RelayAddrs) that do not resolve to their relay alone, all of
// those in one NamesError.
func (is *Issuer) CheckDNS(ctx context.Context, names []string) error {
	resolve := is.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, name string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
		}
	}
	relays, err := is.relayAddrs(ctx)
	if err != nil {
		return err
	}
	var own []string
	bad := &NamesError{Reason: "does not resolve to its relay alone"}
	var errs []error
	for _, name := range names {
		relay, ok := relays[canonical(name)]
		if !ok {
			own = append(own, name)
			continue
		}
		addrs, err := resolve(ctx, name)
		switch {
		case err != nil:
			err = fmt.Errorf("%s does not resolve (add the record of the relay's name, rayctl dns): %w", name, err)
		case len(addrs) == 0 || slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() != relay }):
			err = fmt.Errorf("%s resolves to %v, not to its relay %s alone", name, addrs, relay)
		}
		if err != nil {
			bad.Names, errs = append(bad.Names, name), append(errs, err)
		}
	}
	if err := is.checkOwn(ctx, resolve, own); err != nil {
		return err
	}
	if len(errs) > 0 {
		bad.Err = errors.Join(errs...)
		return bad
	}
	return nil
}

// canonical is a name as RelayAddrs keys it: lower case, no final dot.
func canonical(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

// checkOwn is CheckDNS of the node's own names.
func (is *Issuer) checkOwn(ctx context.Context, resolve func(context.Context, string) ([]netip.Addr, error), names []string) error {
	if len(names) == 0 {
		return nil
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

// relayAddrs is RelayAddrs, none when unset.
func (is *Issuer) relayAddrs(ctx context.Context) (map[string]netip.Addr, error) {
	if is.RelayAddrs == nil {
		return nil, nil
	}
	return is.RelayAddrs(ctx)
}

// RelaySettle is how long an order with a relay's name waits after the
// window opened before its challenges are answered: the relay takes the
// window with its next snapshot, a round trip away, and the CA's first
// try must find it forwarding.
var RelaySettle = 2 * time.Second

// Issue gets a certificate for names with key and returns the chain (DER,
// leaf first): through DNS-01 when the node has a DNS provider, otherwise
// through HTTP-01 in a perimeter window.
func (is *Issuer) Issue(ctx context.Context, names []string, key crypto.Signer) ([][]byte, error) {
	var solver DNSSolver
	if is.DNS != nil {
		s, err := is.DNS(ctx)
		if err != nil {
			return nil, err
		}
		solver = s
	}
	var answer func(ctx context.Context, client *acme.Client, z *acme.Authorization) error
	timeout := WindowLen
	if solver != nil {
		timeout = DNSOrderLen
		answer = func(ctx context.Context, client *acme.Client, z *acme.Authorization) error {
			chal := challenge(z, "dns-01")
			if chal == nil {
				return fmt.Errorf("acme: no dns-01 challenge for %s", z.Identifier.Value)
			}
			value, err := client.DNS01ChallengeRecord(chal.Token)
			if err != nil {
				return err
			}
			fqdn := "_acme-challenge." + strings.TrimPrefix(z.Identifier.Value, "*.")
			if err := solver.Present(ctx, fqdn, value); err != nil {
				return fmt.Errorf("dns-01 %s: %w", fqdn, err)
			}
			defer func() {
				if err := solver.CleanUp(context.WithoutCancel(ctx), fqdn, value); err != nil {
					is.log().Warn("dns-01 record not removed", "err", err)
				}
			}()
			return accept(ctx, client, chal, z)
		}
	} else {
		for _, n := range names {
			if strings.HasPrefix(n, "*.") {
				return nil, fmt.Errorf("%s: a wildcard name needs DNS-01, a DNS provider (rayctl dns cloudflare)", n)
			}
		}
		if err := is.CheckDNS(ctx, names); err != nil {
			return nil, err
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
			is.Window(port, time.Now().Add(WindowLen), names)
			defer is.Window(0, time.Time{}, nil)
			relays, err := is.relayAddrs(ctx)
			if err != nil {
				return nil, err
			}
			if slices.ContainsFunc(names, func(n string) bool { _, ok := relays[canonical(n)]; return ok }) {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(RelaySettle):
				}
			}
		}
		answer = func(ctx context.Context, client *acme.Client, z *acme.Authorization) error {
			chal := challenge(z, "http-01")
			if chal == nil {
				return fmt.Errorf("acme: no http-01 challenge for %s", z.Identifier.Value)
			}
			ka, err := client.HTTP01ChallengeResponse(chal.Token)
			if err != nil {
				return err
			}
			resp.set(chal.Token, ka)
			return accept(ctx, client, chal, z)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// The CA's root must be among the node's roots: the embedded list, or
	// for a private CA the file root names (rayctl roots file). No fallback
	// to the system store: nothing above TLS checks what ACME answers.
	hc := is.HTTPClient
	if hc == nil {
		hc = roots.Node.Client(0)
		defer hc.CloseIdleConnections()
	}
	client := &acme.Client{Key: is.AccountKey, DirectoryURL: is.Directory, HTTPClient: hc, UserAgent: "raycontrol"}
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("acme account: %w", err)
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
		if err := answer(ctx, client, z); err != nil {
			// The CA did not validate the name: a relay's port 80 closed
			// at its provider, say. The manager orders again without it
			// when it is a relay's. Not for an error of the exchange
			// itself (a limit, the network), which is no name's.
			var ae *acme.AuthorizationError
			if errors.As(err, &ae) {
				return nil, &NamesError{Names: []string{z.Identifier.Value}, Reason: "not validated by the CA", Err: err}
			}
			return nil, err
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return nil, fmt.Errorf("acme order: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		return nil, err
	}
	// With the order's own URI: a CA need not send Location on finalize.
	chain, _, err := client.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return nil, fmt.Errorf("acme certificate: %w", err)
	}
	method := "http-01"
	if solver != nil {
		method = "dns-01"
	}
	is.log().Info("certificate issued", "names", len(names), "challenge", method)
	return chain, nil
}

func challenge(z *acme.Authorization, typ string) *acme.Challenge {
	for _, c := range z.Challenges {
		if c.Type == typ {
			return c
		}
	}
	return nil
}

func accept(ctx context.Context, client *acme.Client, chal *acme.Challenge, z *acme.Authorization) error {
	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("acme accept %s: %w", z.Identifier.Value, err)
	}
	if _, err := client.WaitAuthorization(ctx, z.URI); err != nil {
		return fmt.Errorf("acme validation of %s: %w", z.Identifier.Value, err)
	}
	return nil
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
