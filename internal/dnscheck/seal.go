package dnscheck

import (
	"crypto/hmac"
	"errors"

	"golang.org/x/crypto/chacha20"
)

// dnsseal-v1 (docs/spec/dnsseal-v1.md): the framing of dnstt sealed with
// the zone's key K. From K, a cipher key and a tag key each way:
//
//	query:  N (8) || T (4) || C,  C = ChaCha20(Ku, N || 0^4)(inner),
//	        T = HMAC-SHA256(Kut, N || C)[:4]
//	answer: R (8) || T (4) || C,  C = ChaCha20(Kd, R || 0^4)(frames || 00 00 || zeros),
//	        T = HMAC-SHA256(Kdt, R || C)[:4]
//
// Everything about the seal is in this file.
const (
	sealNonceLen = 8
	sealTagLen   = 4
)

// errSealTag: the answer's tag is not the zone key's.
var errSealTag = errors.New("the seal's tag does not match")

// sealKeys are the keys derived from a zone's key.
type sealKeys struct {
	up, down, upTag, downTag []byte
}

func deriveSeal(k []byte) sealKeys {
	return sealKeys{
		up:      mac(k, []byte("dnsseal-v1 up")),
		down:    mac(k, []byte("dnsseal-v1 down")),
		upTag:   mac(k, []byte("dnsseal-v1 up tag")),
		downTag: mac(k, []byte("dnsseal-v1 down tag")),
	}
}

// sealXOR XORs p in place with ChaCha20 under key and nonce || 0^4.
func sealXOR(key, nonce, p []byte) {
	var n [chacha20.NonceSize]byte
	copy(n[:], nonce)
	c, err := chacha20.NewUnauthenticatedCipher(key, n[:])
	if err != nil {
		panic(err) // fixed sizes
	}
	c.XORKeyStream(p, p)
}

// sealQuery seals a query's inner payload with the nonce n: the bytes the
// name's labels carry.
func sealQuery(k []byte, n [sealNonceLen]byte, inner []byte) []byte {
	keys := deriveSeal(k)
	c := append([]byte(nil), inner...)
	sealXOR(keys.up, n[:], c)
	out := append(append([]byte(nil), n[:]...), mac(keys.upTag, n[:], c)[:sealTagLen]...)
	return append(out, c...)
}

// openAnswer checks the tag of a sealed answer's TXT data and returns what
// is under the seal: frames, a zero length and zeros.
func openAnswer(k, data []byte) ([]byte, error) {
	if len(data) < sealNonceLen+sealTagLen {
		return nil, errSealTag
	}
	keys := deriveSeal(k)
	r, t, c := data[:sealNonceLen], data[sealNonceLen:sealNonceLen+sealTagLen], data[sealNonceLen+sealTagLen:]
	if !hmac.Equal(t, mac(keys.downTag, r, c)[:sealTagLen]) {
		return nil, errSealTag
	}
	plain := append([]byte(nil), c...)
	sealXOR(keys.down, r, plain)
	return plain, nil
}
