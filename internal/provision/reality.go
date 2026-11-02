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
	"strings"
	"sync"
	"time"

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

// realityRoots verify the target's certificate; nil is the system pool.
var realityRoots *x509.CertPool

// CheckRealityTarget connects to a REALITY target the way a client's
// handshake reaches it and checks what REALITY needs from it: TLS 1.3,
// X25519MLKEM768 (the session must be post-quantum), HTTP/2, a certificate
// for the server name, and a certificate chain at least as long as
// REALITY's own certificate with the ML-DSA-65 signature: REALITY pads its
// messages to the target's lengths and fails on a shorter chain.
func CheckRealityTarget(ctx context.Context, target, sni string) error {
	if strings.HasPrefix(target, "/") {
		return nil // the node's own site (R2b)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
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
	if need := realityCertLen() + 16; chain < need {
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
