package node

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// RelayBundlePrefix marks an encoded relay bundle.
const RelayBundlePrefix = "rcrelay1:"

// RelayBundle is what a relay host needs from its exit (relay-v1 §3): where
// the exit is, its API and the pin of its certificate, and the relay's own
// client certificate and key, with which the relay takes its perimeter
// (RelayService). The relay's SPA parameters and its keys of the devices
// come in that perimeter, not here. It holds a private key: root's file.
type RelayBundle struct {
	Version int        `json:"v"`
	Name    string     `json:"name"`
	Exit    netip.Addr `json:"exit"` // the DNAT target and the API's host
	API     BundleSub  `json:"api"`
	Cert    string     `json:"cert"` // PEM: the certificate, then its PKCS#8 key
	// Probe is the relay's probe-v1 endpoint (relay-v1 §9.1), which rayd
	// relay serves; bundles before v0.11 have none.
	Probe *RelayProbe `json:"probe,omitempty"`
}

// RelayProbe is a relay's probe endpoint: TCP and UDP on one port, and the
// server certificate whose pin the exit puts in the subscription.
type RelayProbe struct {
	Port uint16 `json:"port"`
	Cert string `json:"cert"` // PEM: the certificate, then its PKCS#8 key
}

// Encode returns the bundle as "rcrelay1:" + base64url(JSON).
func (b RelayBundle) Encode() (string, error) {
	j, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return RelayBundlePrefix + base64.RawURLEncoding.EncodeToString(j), nil
}

// DecodeRelayBundle parses an encoded relay bundle.
func DecodeRelayBundle(s string) (RelayBundle, error) {
	var b RelayBundle
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), RelayBundlePrefix)
	if !ok {
		return b, fmt.Errorf("must start with %q", RelayBundlePrefix)
	}
	j, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(j, &b); err != nil {
		return b, err
	}
	switch {
	case b.Version != 1:
		return b, fmt.Errorf("unsupported relay bundle version %d", b.Version)
	case !b.Exit.IsValid() || b.API.Port == 0 || b.API.Pin == "" || b.Cert == "" || b.Name == "":
		return b, errors.New("relay bundle without exit, API, certificate or name")
	case b.Probe != nil && (b.Probe.Port == 0 || b.Probe.Cert == ""):
		return b, errors.New("relay bundle with a probe endpoint without port or certificate")
	}
	return b, nil
}

// ReadRelayBundle reads a relay's bundle from a file that only its owner may
// read: it holds the relay's keys.
func ReadRelayBundle(path string) (RelayBundle, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return RelayBundle{}, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return RelayBundle{}, fmt.Errorf("relay bundle %s is mode %v: it holds a private key, make it 0600", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the configured bundle
	if err != nil {
		return RelayBundle{}, err
	}
	return DecodeRelayBundle(string(b))
}
