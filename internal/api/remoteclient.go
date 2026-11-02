package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1/devicev1connect"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// NewClientCertificate makes a device's client key and a self-signed
// certificate for it (ECDSA P-256): the node knows the device by the key.
func NewClientCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "raycontrol device"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0), // the node checks the key, not dates
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// EncodeClientCertificate returns the certificate and its key as PEM.
func EncodeClientCertificate(c tls.Certificate) ([]byte, error) {
	key, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})...), nil
}

// DecodeClientCertificate reads what EncodeClientCertificate wrote.
func DecodeClientCertificate(b []byte) (tls.Certificate, error) {
	c, err := tls.X509KeyPair(b, b)
	if err != nil {
		return c, err
	}
	c.Leaf, err = x509.ParseCertificate(c.Certificate[0])
	return c, err
}

// PinnedTLS is the client side of the node's TLS endpoints: TLS 1.3 with
// X25519MLKEM768 only, the node's self-signed certificate checked by its
// pin, the device's certificate if given.
func PinnedTLS(pin string, cert *tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		NextProtos:       []string{"h2"},
		// The pin replaces the chain check: the certificate is self-signed.
		InsecureSkipVerify: true, //nolint:gosec // G402: pinned in VerifyPeerCertificate
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			got := base64.RawURLEncoding.EncodeToString(sum[:])
			if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
				return fmt.Errorf("certificate pin %s, want %s", got, pin)
			}
			return nil
		},
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

func remoteHTTP(pin string, cert tls.Certificate) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: PinnedTLS(pin, &cert), ForceAttemptHTTP2: true}}
}

// NewRemoteClients returns the node and device API clients for the remote
// API at addr (host:port).
func NewRemoteClients(addr, pin string, cert tls.Certificate) (nodev1connect.NodeServiceClient, devicev1connect.DeviceServiceClient) {
	hc := remoteHTTP(pin, cert)
	base := "https://" + addr
	return nodev1connect.NewNodeServiceClient(hc, base), devicev1connect.NewDeviceServiceClient(hc, base)
}
