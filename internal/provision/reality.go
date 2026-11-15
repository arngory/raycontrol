package provision

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/arngory/raycontrol/internal/perimeter"
	"github.com/arngory/raycontrol/internal/store"
)

// realityCertLen is the length of the certificate REALITY sends with its
// ML-DSA-65 signature: built like github.com/xtls/reality does it.
var realityCertLen = sync.OnceValue(func() int {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return 3600
	}
	tmpl := x509.Certificate{SerialNumber: &big.Int{}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{0, 0}, Value: make([]byte, 3309)}}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, priv.Public(), priv)
	if err != nil {
		return 3600
	}
	return len(der)
})

// RealityChainMin is the shortest certificate chain (bytes, with the
// per-certificate overhead) a REALITY target may send: REALITY pads its own
// certificate with the ML-DSA-65 signature to it.
func RealityChainMin() int { return realityCertLen() + 16 }

// realityRoots verify the target's certificate; nil is the system pool.
//
// The one outbound TLS of the node's that internal/roots does not decide
// (R4-41), on purpose: the target is a third-party site of the
// operator's choice, which may sit under a CA outside the node's list,
// and the check sends nothing secret (a handshake as a client's, no
// token, no user's data). What it decides is whether the site suits
// REALITY, as a client's browser-like view would see it; a root planted
// in the system store can at most make it pass a site that should not.
var realityRoots *x509.CertPool

// IsLocal reports whether an address is in the node's own and local
// networks (perimeter.LocalNets, R4-38).
func IsLocal(a netip.Addr) bool { return perimeter.InLocalNets(a) }

// RealityLocalTarget is the target of an enabled REALITY service when the
// operator gave it as a local address and port (127.0.0.1:8443, the host's
// own web server; an address on the private network): Xray dials it from
// the service's process, past its routing, and the egress policy's local
// part lets exactly that address, TCP and port through for that process
// (spec/egress-policy-v1.md §10). A name is never one, whatever it
// resolves to: what DNS says would decide what is opened
// (CheckRealityTarget says when a name resolves to a local address).
func RealityLocalTarget(svc store.Service) (netip.AddrPort, bool) {
	if svc.Kind != "reality" || !svc.Enabled {
		return netip.AddrPort{}, false
	}
	target, _, err := RealityTargetFromJSON(svc.Settings)
	if err != nil {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(target)
	if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" || !IsLocal(ap.Addr()) {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// CheckRealityTarget connects to a REALITY target the way a client's
// handshake reaches it and checks what REALITY needs from it: TLS 1.3,
// X25519MLKEM768 (the session must be post-quantum), HTTP/2, a certificate
// for the server name, and a certificate chain at least as long as
// REALITY's own certificate with the ML-DSA-65 signature: REALITY pads its
// messages to the target's lengths and fails on a shorter chain.
//
// It runs as rayd, not as the service's process, and rayd is not under
// the egress policy's local part (R4-38): the data plane's path to a
// target on a local address is the policy's exemption, which rayspa puts
// in from the same settings (RealityLocalTarget; rayctl egress lists it).
// A target given by a name that resolves to a local address has no
// exemption: that is refused here, as the data plane's dial would be.
func CheckRealityTarget(ctx context.Context, target, sni string) error {
	if strings.HasPrefix(target, "/") {
		return nil // the node's own site (R2b)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if host, port, err := net.SplitHostPort(target); err == nil && net.ParseIP(host) == nil {
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err == nil {
			for _, a := range addrs {
				if IsLocal(a) {
					return fmt.Errorf("reality target %s resolves to %s, a local address: the data plane reaches no local network by a name "+
						"while local networks are blocked (the default, R4-38); give the address as the target (%s) with the sni",
						target, a.Unmap(), net.JoinHostPort(a.Unmap().String(), port))
				}
			}
		}
	}
	d := tls.Dialer{Config: &tls.Config{
		RootCAs:          realityRoots,
		ServerName:       sni,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		NextProtos:       []string{"h2", "http/1.1"},
	}}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("reality target %s (sni %s): %w; it needs TLS 1.3 with X25519MLKEM768 and a valid certificate for the name", target, sni, err)
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	if st.CurveID != tls.X25519MLKEM768 {
		return fmt.Errorf("reality target %s: key exchange %v, X25519MLKEM768 is required", target, st.CurveID)
	}
	if st.NegotiatedProtocol != "h2" {
		return fmt.Errorf("reality target %s does not speak HTTP/2; pick a site that does", target)
	}
	chain := 0
	for _, c := range st.PeerCertificates {
		chain += len(c.Raw) + 5 // certificate entry: length and extensions
	}
	if need := RealityChainMin(); chain < need {
		return fmt.Errorf("reality target %s: certificate chain of %d bytes, REALITY with ML-DSA-65 needs at least %d; pick a site with a longer chain (RSA, more intermediates)", target, chain, need)
	}
	return nil
}

// RealityTargetFromJSON is RealityTarget for raw settings.
func RealityTargetFromJSON(settings string) (target, sni string, err error) {
	m := map[string]any{}
	if settings != "" {
		if err := json.Unmarshal([]byte(settings), &m); err != nil {
			return "", "", fmt.Errorf("%w settings: %w", store.ErrInvalid, err)
		}
	}
	return RealityTarget(m)
}
