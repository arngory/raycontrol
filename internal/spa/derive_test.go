package spa

import (
	"encoding/hex"
	"testing"
)

// The derived keys of relay-v1 §3 and dnsauth-v1 §2, as the specs give them:
// device key 00..1f, node ID a0..af, the relay's node ID b0..bf and name
// "r1", service 3. The client derives the same.
func TestDerivedKeyVectors(t *testing.T) {
	var dev [KeySize]byte
	var node [NodeIDSize]byte
	for i := range dev {
		dev[i] = byte(i)
	}
	for i := range node {
		node[i] = byte(0xa0 + i)
	}
	var relayNode [NodeIDSize]byte
	for i := range relayNode {
		relayNode[i] = byte(0xb0 + i)
	}
	relay := RelayKey(dev, node, relayNode, "r1")
	dns := DNSAuthKey(dev, node, 3)
	for name, c := range map[string]struct {
		got  []byte
		want string
	}{
		"relay":   {relay[:], "6e84ab4641da09239a34c5b76756ecd3787291e57d2eb34ece0433bee3a1a504"},
		"dnsauth": {dns[:], "0b485b425e8b19e0ec7c0362d55fdc34338147f984b87ee005455c8f5fc68b1c"},
	} {
		if hex.EncodeToString(c.got) != c.want {
			t.Errorf("%s key %x, want %s", name, c.got, c.want)
		}
	}
	// The client's vector (Niko, T2): device key 11 x 32, node ID 33 x 16,
	// service 3.
	var dev11 [KeySize]byte
	var node33 [NodeIDSize]byte
	for i := range dev11 {
		dev11[i] = 0x11
	}
	for i := range node33 {
		node33[i] = 0x33
	}
	if k := DNSAuthKey(dev11, node33, 3); hex.EncodeToString(k[:]) != "2f9bd5e6fc2ef3f56206998eee87f2d4b798a66c3c846ef34eff2f2647599bd5" {
		t.Errorf("client's dnsauth vector: %x", k)
	}
	if RelayKey(dev, node, relayNode, "r2") == relay {
		t.Error("two relays share a key")
	}
	if RelayKey(dev, node, [NodeIDSize]byte{}, "r1") == relay {
		t.Error("a relay's new node ID leaves the key as it was")
	}
}
