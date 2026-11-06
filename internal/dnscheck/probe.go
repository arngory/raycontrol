package dnscheck

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// dnsprobe-v1 (docs/spec/dnsprobe-v1.md): a resolver check by one label
// under a dnstt zone. With the node's key in it the front answers itself,
// before the backend: a valid answer proves that the resolver brought this
// query to the node now and that TXT comes back whole. Ported from the
// supervised test's dnsProbe, without niko-server.
const (
	probeLabelBytes = 24
	probeLabelLen   = 39 // base32 of 24 bytes, no padding
	probeTokenLen   = 16
	probeSmall      = probeTokenLen + 2 + 1 + 16 // the plaintext of a small answer
	probeLarge      = 900                        // of a large one: zeros after the small part
	probeNonceLen   = 8
)

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// errProbeToken: the TXT data does not decrypt to the node's token: the
// resolver answered itself, or the key is not the node's.
var errProbeToken = errors.New("the token does not match")

// Probe is one probe query.
type Probe struct {
	Large bool // the large answer is asked for
	b     [probeLabelBytes]byte
}

// NewProbe makes a probe of zone at now with a fresh nonce.
func NewProbe(key []byte, zone string, large bool, now time.Time) (Probe, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Probe{}, err
	}
	return probeAt(key, zone, large, uint32(now.Unix()/60), nonce), nil
}

// probeAt is a probe with its minute and nonce given (the spec's example).
func probeAt(key []byte, zone string, large bool, minute uint32, nonce [8]byte) Probe {
	p := Probe{Large: large}
	p.b[0] = 1 // version
	if large {
		p.b[1] = 1
	}
	binary.BigEndian.PutUint32(p.b[2:6], minute)
	copy(p.b[6:14], nonce[:])
	copy(p.b[14:], mac(key, []byte("dnsprobe-v1 q"), []byte(canonical(zone)), p.b[:14])[:10])
	return p
}

// Label is the probe's label: 39 characters of base32, lower case.
func (p Probe) Label() string { return strings.ToLower(base32NoPad.EncodeToString(p.b[:])) }

// ProbeAnswer is what the node saw of a probe (spec §4).
type ProbeAnswer struct {
	Large  bool       // the large answer (900 bytes) came
	EDNS   int        // the UDP size the resolver advertised to the node; 0 without OPT
	Mixed  bool       // the label came with upper case letters: the resolver applies 0x20
	Egress netip.Addr // where the query came from: the resolver's egress
}

// Open checks the TXT data of an answer (its strings joined) and returns
// what the node saw. The answer may be padded (dnsseal-v1 §6): only its
// first 43 bytes count, 908 for a large answer; the rest is not looked at.
func (p Probe) Open(key, data []byte) (ProbeAnswer, error) {
	if len(data) < probeNonceLen+probeSmall {
		return ProbeAnswer{}, fmt.Errorf("TXT data of %d bytes, not a probe answer", len(data))
	}
	size := probeSmall
	if p.Large && len(data) >= probeNonceLen+probeLarge {
		size = probeLarge
	}
	nonce := data[:probeNonceLen]
	plain := append([]byte(nil), data[probeNonceLen:probeNonceLen+size]...)
	probeCrypt(mac(key, []byte("dnsprobe-v1 e")), p.b[:], nonce, plain)
	if !hmac.Equal(plain[:probeTokenLen], mac(key, []byte("dnsprobe-v1 a"), p.b[:], plain[probeTokenLen:probeSmall])[:probeTokenLen]) {
		return ProbeAnswer{}, errProbeToken
	}
	for _, c := range plain[probeSmall:] {
		if c != 0 {
			return ProbeAnswer{}, errors.New("the large answer is not zeros after its token")
		}
	}
	return ProbeAnswer{
		Large:  size == probeLarge,
		EDNS:   int(binary.BigEndian.Uint16(plain[16:18])),
		Mixed:  plain[18] == 1,
		Egress: netip.AddrFrom16([16]byte(plain[19:35])).Unmap(),
	}, nil
}

// probeCrypt XORs p with the keystream of a label's bytes b and an
// answer's nonce: blocks of HMAC-SHA256(ke, b ‖ nonce ‖ uint32 counter).
func probeCrypt(ke, b, nonce, p []byte) {
	var ctr [4]byte
	for i := 0; i < len(p); i += sha256.Size {
		binary.BigEndian.PutUint32(ctr[:], uint32(i/sha256.Size))
		block := mac(ke, b, nonce, ctr[:])
		for j := 0; j < sha256.Size && i+j < len(p); j++ {
			p[i+j] ^= block[j]
		}
	}
}

// mac is HMAC-SHA256 of the parts in turn.
func mac(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// canonical is a name in lower case without the final dot.
func canonical(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }
