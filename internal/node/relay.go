package node

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
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
	}
	return b, nil
}
