package spa

import (
	"encoding/hex"
	"testing"
)

// The derived keys of relay-v1 §3 and dnsauth-v1 §2, as the specs give them:
// device key 00..1f, node ID a0..af, relay "r1", service 3. The client
// derives the same.
func TestDerivedKeyVectors(t *testing.T) {
	var dev [KeySize]byte
	var node [NodeIDSize]byte
	for i := range dev {
		dev[i] = byte(i)
	}
	for i := range node {
		node[i] = byte(0xa0 + i)
	}
	relay := RelayKey(dev, node, "r1")
	dns := DNSAuthKey(dev, node, 3)
	for name, c := range map[string]struct {
		got  []byte
		want string
	}{
		"relay":   {relay[:], "bfef0a7e5a6b933c577b794f5097f6d86bb16bd9b24d9fc0c4a06454dd926489"},
		"dnsauth": {dns[:], "0b485b425e8b19e0ec7c0362d55fdc34338147f984b87ee005455c8f5fc68b1c"},
	} {
		if hex.EncodeToString(c.got) != c.want {
			t.Errorf("%s key %x, want %s", name, c.got, c.want)
		}
	}
	if RelayKey(dev, node, "r2") == relay {
		t.Error("two relays share a key")
	}
}
