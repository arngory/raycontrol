package sub

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/arngory/raycontrol/internal/spa"
)

// Client fetches a subscription the way the Niko client does: TLS 1.3 with
// X25519MLKEM768 only, the certificate pinned by SPKI, RC1 auth, both
// signatures checked (spec/subscription-v1.md).
type Client struct {
	Addr      string // host:port; use an IP that already passed SPA
	Pin       string // base64url SHA-256 of the SubjectPublicKeyInfo
	DeviceID  string
	DeviceKey [spa.KeySize]byte
	NodeKeys  map[string]string
	NodeID    string // hex; the payload must carry it
}

// ErrRefused is the endpoint's 404: unknown or revoked device, bad auth
// (clock more than two minutes off) or no SPA grant on a shared address.
var ErrRefused = errors.New("subscription refused (404)")

// HTTP is a client for the endpoint: TLS 1.3 with X25519MLKEM768 only and
// the certificate pinned.
func (c Client) HTTP() *http.Client {
	pin := func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("no certificate")
		}
		cert, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		got := base64.RawURLEncoding.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(got), []byte(c.Pin)) != 1 {
			return fmt.Errorf("certificate pin %s, want %s", got, c.Pin)
		}
		return nil
	}
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
			// The pin replaces the chain check: the certificate is self-signed.
			InsecureSkipVerify:    true, //nolint:gosec // G402: pinned in VerifyPeerCertificate
			VerifyPeerCertificate: pin,
		},
		ForceAttemptHTTP2: true,
	}}
}

// Authorize names the device and adds its token for the current minute.
func (c Client) Authorize(req *http.Request) {
	req.Header.Set(DeviceHeader, c.DeviceID)
	req.Header.Set("Authorization", AuthToken(c.DeviceKey, time.Now().Unix()/60))
}

// Fetch returns the verified payload.
func (c Client) Fetch(ctx context.Context, now time.Time) (Payload, error) {
	hc := c.HTTP()
	defer hc.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+c.Addr+Path, nil)
	if err != nil {
		return Payload{}, err
	}
	req.Header.Set(DeviceHeader, c.DeviceID)
	req.Header.Set("Authorization", AuthToken(c.DeviceKey, now.Unix()/60))
	resp, err := hc.Do(req)
	if err != nil {
		return Payload{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return Payload{}, ErrRefused
	}
	if resp.StatusCode != http.StatusOK {
		return Payload{}, fmt.Errorf("subscription: HTTP %d", resp.StatusCode)
	}
	var env Envelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&env); err != nil {
		return Payload{}, err
	}
	p, err := Verify(env, c.NodeKeys)
	if err != nil {
		return p, err
	}
	if c.NodeID != "" && p.NodeID != c.NodeID {
		return p, fmt.Errorf("subscription of node %s, want %s", p.NodeID, c.NodeID)
	}
	if p.Expires <= now.Unix() {
		return p, errors.New("subscription already expired")
	}
	return p, nil
}
