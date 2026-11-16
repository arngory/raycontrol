package cidkey

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The spec's example (quic-cid-route-v1 §8), as niko-server derives it.
func TestLabelKey(t *testing.T) {
	secret, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	k, err := LabelKey(secret, 0x0102)
	if err != nil || hex.EncodeToString(k) != "167e64ae0e81012cf5f8667f5525e7ee" {
		t.Fatalf("%x %v", k, err)
	}
	other, _ := LabelKey(secret, 0x0103)
	if bytes.Equal(k, other) {
		t.Fatal("two labels, one key")
	}
	for _, label := range []int{0, -1, MaxLabel + 1} {
		if _, err := LabelKey(secret, label); err == nil {
			t.Errorf("label %d", label)
		}
	}
	if _, err := LabelKey(secret[:16], 1); err == nil {
		t.Error("a short secret")
	}
}
