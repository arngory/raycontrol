package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/node"
)

// The relay's bundle holds its private key: rayspa takes it only as root's
// file, and builds the exit's feed from it.
func TestReadRelayBundle(t *testing.T) {
	cert, err := api.NewClientCertificate()
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := api.EncodeClientCertificate(cert)
	enc, err := node.RelayBundle{Version: 1, Name: "r1", Exit: netip.MustParseAddr("203.0.113.7"),
		API: node.BundleSub{Port: 8443, Pin: "pin"}, Cert: string(pem)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "relay.bundle")
	os.WriteFile(path, []byte(enc+"\n"), 0o644)
	if _, err := readRelayBundle(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("a bundle others can read: %v", err)
	}
	os.Chmod(path, 0o600)
	b, err := readRelayBundle(path)
	if err != nil || b.Name != "r1" || b.Exit.String() != "203.0.113.7" {
		t.Fatalf("bundle %+v %v", b, err)
	}
	if _, err := relayFeed(b); err != nil {
		t.Fatal(err)
	}
	b.Cert = "garbage"
	if _, err := relayFeed(b); err == nil {
		t.Fatal("a bundle with a broken certificate")
	}
}
