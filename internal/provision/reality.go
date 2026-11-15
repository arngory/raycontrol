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
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strconv"
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

// IsLocalhost reports whether a target's host is the name localhost,
// loopback whatever DNS says (RFC 6761 §6.3; /etc/hosts gives 127.0.0.1
// and ::1).
func IsLocalhost(host string) bool { return strings.EqualFold(host, "localhost") }

// RealityLocalTarget is where an enabled REALITY service's target is when
// the operator gave it as a local address and port (127.0.0.1:8443, the
// host's own web server; an address on the private network), or as
// localhost and a port (127.0.0.1 and ::1: Xray's resolver may take
// either): Xray dials it from the service's process, past its routing,
// and the egress policy's local part lets exactly these addresses, TCP and
// port through for that process (spec/egress-policy-v1.md §10). Any other
// name is never one, whatever it resolves to: what DNS says would decide
// what is opened (CheckRealityTarget refuses a name that resolves to a
// local address, RealityTargetWarning warns of one set before). 0.0.0.0
// and :: are none either: the kernel makes them 127.0.0.1 and ::1, which
// no rule for the address would match (CheckTargetAddr refuses them).
func RealityLocalTarget(svc store.Service) []netip.AddrPort {
	if svc.Kind != "reality" || !svc.Enabled {
		return nil
	}
	target, _, err := RealityTargetFromJSON(svc.Settings)
	if err != nil {
		return nil
	}
	if host, port, err := net.SplitHostPort(target); err == nil && IsLocalhost(host) {
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil || p == 0 {
			return nil
		}
		return []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(p)), netip.AddrPortFrom(netip.IPv6Loopback(), uint16(p))}
	}
	ap, err := netip.ParseAddrPort(target)
	if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" || ap.Addr().Unmap().IsUnspecified() || !IsLocal(ap.Addr()) {
		return nil
	}
	return []netip.AddrPort{netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}
}

// ownAddrs are the host's addresses (rayd's and rayctl's on the node);
// tests replace it.
var ownAddrs = func() map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, x := range addrs {
		if p, err := netip.ParsePrefix(x.String()); err == nil {
			m[p.Addr().Unmap()] = true
		}
	}
	return m
}

// OwnAddrs are the host's addresses.
func OwnAddrs() map[netip.Addr]bool { return ownAddrs() }

// lookupNetIP resolves a target's name, as rayd's resolver does; tests
// replace it.
var lookupNetIP = net.DefaultResolver.LookupNetIP

// TargetError says why the data plane does not reach a REALITY target
// (spec/egress-policy-v1.md §10): the node's own address but loopback,
// which to_node refuses before anything else (S-2); 0.0.0.0 or ::; or a
// name that resolves to a local address, which the local part refuses
// while local networks are blocked. REALITY would answer no client and no
// prober.
type TargetError struct {
	Target string         // as given
	Addr   netip.Addr     // what it is, or what its name resolves to
	Use    netip.AddrPort // the target that works: 127.0.0.1:PORT, or the address
	Own    bool           // the node's own address, or 0.0.0.0, ::: only Use helps
	Named  bool           // the target is a name
}

func (e *TargetError) Error() string {
	switch {
	case e.Addr.IsUnspecified():
		return fmt.Sprintf("reality target %s is no address to dial: the kernel makes it loopback, which no exemption of the egress policy names; use %s", e.Target, e.Use)
	case e.Own && e.Named:
		return fmt.Sprintf("reality target %s resolves to %s, the node's own address, which the data plane does not reach (only loopback); use %s", e.Target, e.Addr, e.Use)
	case e.Own:
		return fmt.Sprintf("reality target %s is the node's own address, which the data plane does not reach (only loopback); use %s", e.Target, e.Use)
	}
	return fmt.Sprintf("reality target %s resolves to %s, a local address: the data plane reaches no local network by a name "+
		"while local networks are blocked (the default, R4-38); give the address as the target (%s) with the sni", e.Target, e.Addr, e.Use)
}

// Fix says what fixes the target of the service name, set before.
func (e *TargetError) Fix(name string) string {
	fix := fmt.Sprintf("rayctl service set %s target=%s", name, e.Use)
	if !e.Own {
		fix += " (the sni stays), or rayctl egress allow local"
	}
	return fix
}

// ForService is err, a refusal of CheckRealityTarget, with what fixes it
// for the service name that has the target already (rayd's check of the
// targets, rayctl status).
func ForService(name string, err error) error {
	var te *TargetError
	if errors.As(err, &te) {
		return fmt.Errorf("%w: %s", err, te.Fix(name))
	}
	return err
}

// CheckTargetAddr refuses a REALITY target given as an address the data
// plane does not reach (TargetError): 0.0.0.0 and ::, and the node's own
// addresses but loopback (127.0.0.0/8, ::1). Names and socket paths pass:
// CheckRealityTarget resolves the names. At creation and for rayctl
// service set NAME target=.
func CheckTargetAddr(target string) error {
	ap, err := netip.ParseAddrPort(target)
	if err != nil {
		return nil
	}
	return targetProblem(target, ap.Addr(), ap.Port(), false, false, ownAddrs())
}

// targetProblem is the TargetError of a target at a (named: given as a
// name that resolves to a), or nil; local: local networks are blocked.
func targetProblem(target string, a netip.Addr, port uint16, named, local bool, own map[netip.Addr]bool) error {
	a = a.Unmap()
	use := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	switch {
	case a.IsUnspecified() || (own[a] && !a.IsLoopback()):
		return &TargetError{Target: target, Addr: a, Use: use, Own: true, Named: named}
	case named && local && IsLocal(a):
		return &TargetError{Target: target, Addr: a, Use: netip.AddrPortFrom(a, port), Named: true}
	}
	return nil
}

// realityTargetOption checks a REALITY service's new target (rayctl
// service set NAME target=HOST:PORT) as creation does: a host and a port,
// what RealityTarget takes with the service's server name, not an address
// the data plane does not reach (CheckTargetAddr). Not for a service that
// steals from the node's own site: its server name is the site's, which a
// foreign target has no certificate for.
func realityTargetOption(svc store.Service, value string) error {
	settings := map[string]any{}
	if err := json.Unmarshal([]byte(svc.Settings), &settings); err != nil {
		return err
	}
	if site, _ := settings["site"].(string); site != "" {
		return fmt.Errorf("%w target: %s steals from the node's own site %s, whose name it has; a foreign target goes on a service of its own "+
			`(rayctl service add reality NAME -settings '{"target":"HOST:PORT","sni":"NAME"}')`, store.ErrInvalid, svc.Name, site)
	}
	host, port, err := net.SplitHostPort(value)
	if p, perr := strconv.ParseUint(port, 10, 16); err != nil || host == "" || perr != nil || p == 0 {
		return fmt.Errorf("%w target %q: HOST:PORT, an address or a name and a port", store.ErrInvalid, value)
	}
	settings["target"] = value
	if _, _, err := RealityTarget(settings); err != nil {
		return err
	}
	if err := CheckTargetAddr(value); err != nil {
		return fmt.Errorf("%w %w", store.ErrInvalid, err)
	}
	return nil
}

// RealityTargetWarning says why the data plane does not reach the target
// an enabled REALITY service has (one set before these checks, or before
// v0.27.0), and the commands that fix it: a name but localhost that
// resolves to a local address, while local networks are blocked
// (localBlocked); the node's own address but loopback, by address or by
// name; 0.0.0.0 or ::. "" when it is reached, or when the name does not
// resolve here (rayd's check of the targets says that). own are the
// node's addresses. For rayctl check and the update's first look; rayctl
// status has rayd's check of the targets (ForService), which refuses the
// same (spec/egress-policy-v1.md §10).
func RealityTargetWarning(ctx context.Context, svc store.Service, localBlocked bool, own map[netip.Addr]bool) (problem, fix string) {
	if svc.Kind != "reality" || !svc.Enabled {
		return "", ""
	}
	target, _, err := RealityTargetFromJSON(svc.Settings)
	if err != nil {
		return "", ""
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || IsLocalhost(host) {
		return "", "" // a socket path, the node's site, localhost
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", ""
	}
	addrs, named := []netip.Addr{}, false
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, a)
	} else {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if addrs, err = lookupNetIP(ctx, "ip", host); err != nil {
			return "", ""
		}
		named = true
	}
	for _, a := range addrs {
		var te *TargetError
		if err := targetProblem(target, a, uint16(p), named, localBlocked, own); errors.As(err, &te) {
			return fmt.Sprintf("REALITY %s answers no client and no prober: %v", svc.Name, err), te.Fix(svc.Name)
		}
	}
	return "", ""
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
// A target given by a name (but localhost) that resolves to a local
// address has no exemption, and the node's own addresses but loopback
// (0.0.0.0 and :: too) none that works, as to_node refuses them first:
// those are refused here (TargetError), as the data plane's dial would be.
func CheckRealityTarget(ctx context.Context, target, sni string) error {
	if strings.HasPrefix(target, "/") {
		return nil // the node's own site (R2b)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if host, port, err := net.SplitHostPort(target); err == nil && !IsLocalhost(host) {
		p, _ := strconv.ParseUint(port, 10, 16)
		own := ownAddrs()
		if a, err := netip.ParseAddr(host); err == nil {
			if err := targetProblem(target, a, uint16(p), false, true, own); err != nil {
				return err
			}
		} else if addrs, err := lookupNetIP(ctx, "ip", host); err == nil {
			for _, a := range addrs {
				if err := targetProblem(target, a, uint16(p), true, true, own); err != nil {
					return err
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
