// Package cidkey derives the keys of routable connection IDs
// (spec/quic-cid-route-v1.md §2): one per label, from the node's secret.
// It imports nothing of quic-go, so that render, which rayctl and rayspa
// link, writes each backend its own label's key; internal/quiccid makes
// the IDs with it.
package cidkey

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

const (
	// SecretLen is the node's secret: 32 bytes.
	SecretLen = 32
	// KeyLen is a label's key: 16 bytes, Speck64/128's.
	KeyLen = 16
	// MaxLabel is the largest label; 0 is none.
	MaxLabel = 1<<16 - 1

	context = "quic-cid-route-v1"
)

// LabelKey is a label's key: HMAC-SHA256(secret, "quic-cid-route-v1" ||
// BE16(label)), its first 16 bytes. The front, which has the secret, has
// every label's; a backend gets only its own.
func LabelKey(secret []byte, label int) ([]byte, error) {
	if len(secret) != SecretLen {
		return nil, fmt.Errorf("cidkey: a secret of %d bytes, want %d", len(secret), SecretLen)
	}
	if label < 1 || label > MaxLabel {
		return nil, fmt.Errorf("cidkey: label %d, want 1-%d", label, MaxLabel)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(context))
	mac.Write([]byte{byte(label >> 8), byte(label)})
	return mac.Sum(nil)[:KeyLen], nil
}
