package spa

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	mrand "math/rand/v2"
	"strings"
	"sync"

	"golang.org/x/crypto/cryptobyte"
)

// The TCP carrier in the shape of a TLS ClientHello (spa-v2.md §10.1,
// RAYCONTROL.md §22.2.3): 96-512 random bytes as the first data of a TCP
// connection are the class of traffic some censors drop on sight; the start
// of a TLS handshake is not. The SPA packet travels as the opaque ticket of
// the session_ticket extension, which a client resuming a session sends as
// it is.
//
// Everything else is a real Chrome's ClientHello (chrome_hello.hex, Google
// Chrome 156.0.8078.47 stable on Linux, captured by Niko's fingerprint CI,
// arngory/sing-box 427f972), made new per connection as Chrome does: random,
// session ID, key shares (a real ML-KEM-768 key), every GREASE value, the
// GREASE ECH payload, the order of the extensions; no server name, as for an
// address. Niko sends the same carrier: the two share the capture, and their
// JA4 is t13i1516h2_8daaf6152771_cb7bf5808d99.

const (
	extServerName    = 0x0000
	extSessionTicket = 0x0023
	extKeyShare      = 0x0033
	extGroups        = 0x000a
	extSigAlgs       = 0x000d
	extVersions      = 0x002b
	extECH           = 0xfe0d
	// TLSCarrierMax bounds what the node reads of a ClientHello carrier.
	TLSCarrierMax = 4096
)

//go:embed chrome_hello.hex
var chromeHelloHex string

type helloExt struct {
	typ  uint16
	data []byte
}

// chromeHello is the capture, parsed once.
var chromeHello = sync.OnceValues(func() (struct {
	ciphers []uint16
	exts    []helloExt
}, error) {
	var t struct {
		ciphers []uint16
		exts    []helloExt
	}
	raw, err := hex.DecodeString(strings.TrimSpace(chromeHelloHex))
	if err != nil {
		return t, err
	}
	s := cryptobyte.String(raw)
	var rec, msg, sid, ciphers, comp, exts cryptobyte.String
	var typ uint8
	if !s.Skip(3) || !s.ReadUint16LengthPrefixed(&rec) || !rec.ReadUint8(&typ) || typ != 1 ||
		!rec.ReadUint24LengthPrefixed(&msg) || !msg.Skip(2+32) || !msg.ReadUint8LengthPrefixed(&sid) ||
		!msg.ReadUint16LengthPrefixed(&ciphers) || !msg.ReadUint8LengthPrefixed(&comp) || !msg.ReadUint16LengthPrefixed(&exts) {
		return t, errors.New("spa: the Chrome ClientHello does not parse")
	}
	for !ciphers.Empty() {
		var c uint16
		ciphers.ReadUint16(&c)
		t.ciphers = append(t.ciphers, c)
	}
	for !exts.Empty() {
		var e helloExt
		var data cryptobyte.String
		if !exts.ReadUint16(&e.typ) || !exts.ReadUint16LengthPrefixed(&data) {
			return t, errors.New("spa: the Chrome ClientHello does not parse")
		}
		if e.typ != extServerName {
			e.data = data
			t.exts = append(t.exts, e)
		}
	}
	return t, nil
})

// isGREASE matches the GREASE values of RFC 8701: 0x?a?a, both bytes equal.
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// grease draws GREASE values as BoringSSL does, one per use; the second
// GREASE extension differs from the first.
type grease struct{ cipher, group, ext1, ext2, version uint16 }

func newGREASE() grease {
	var b [5]byte
	_, _ = rand.Read(b[:])
	v := func(x byte) uint16 { y := uint16(x&0xf0) | 0x0a; return y<<8 | y }
	g := grease{cipher: v(b[0]), group: v(b[1]), ext1: v(b[2]), ext2: v(b[3]), version: v(b[4])}
	if g.ext2 == g.ext1 {
		g.ext2 ^= 0x1010
	}
	return g
}

// TLSCarrier wraps a sealed SPA packet in a ClientHello record.
func TLSCarrier(pkt []byte) ([]byte, error) {
	if len(pkt) == 0 || len(pkt) > MaxPacketLen {
		return nil, errors.New("spa: packet length out of range")
	}
	t, err := chromeHello()
	if err != nil {
		return nil, err
	}
	g := newGREASE()
	// GREASE values inside a list of uint16 after a length prefix of n bytes.
	regrease := func(data []byte, prefix int, v uint16) []byte {
		out := bytes.Clone(data)
		for i := prefix; i+1 < len(out); i += 2 {
			if isGREASE(binary.BigEndian.Uint16(out[i:])) {
				binary.BigEndian.PutUint16(out[i:], v)
			}
		}
		return out
	}
	var exts []helloExt
	firstGREASE := true
	for _, e := range t.exts {
		var data []byte
		typ := e.typ
		switch {
		case isGREASE(typ):
			typ, data = g.ext1, bytes.Clone(e.data)
			if !firstGREASE {
				typ = g.ext2
			}
			firstGREASE = false
		case typ == extGroups:
			data = regrease(e.data, 2, g.group)
		case typ == extSigAlgs:
			data = regrease(e.data, 2, g.group)
		case typ == extVersions:
			data = regrease(e.data, 1, g.version)
		case typ == extKeyShare:
			if data, err = keyShares(e.data, g.group); err != nil {
				return nil, err
			}
		case typ == extECH:
			if data, err = greaseECH(e.data); err != nil {
				return nil, err
			}
		case typ == extSessionTicket:
			data = pkt
		default:
			data = e.data
		}
		exts = append(exts, helloExt{typ, data})
	}
	// Chrome shuffles its extensions, the GREASE ones staying first and last.
	if len(exts) > 2 && isGREASE(exts[0].typ) && isGREASE(exts[len(exts)-1].typ) {
		mid := exts[1 : len(exts)-1]
		mrand.Shuffle(len(mid), func(i, j int) { mid[i], mid[j] = mid[j], mid[i] })
	}

	var b cryptobyte.Builder
	b.AddUint8(0x16)
	b.AddUint16(0x0301)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1) // client_hello
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			var random, sessionID [32]byte
			_, _ = rand.Read(random[:])
			_, _ = rand.Read(sessionID[:])
			b.AddUint16(0x0303)
			b.AddBytes(random[:])
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sessionID[:]) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, c := range t.ciphers {
					if isGREASE(c) {
						c = g.cipher
					}
					b.AddUint16(c)
				}
			})
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) }) // compression: null
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, e := range exts {
					b.AddUint16(e.typ)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(e.data) })
				}
			})
		})
	})
	return b.Bytes()
}

// keyShares makes the capture's key shares anew: the GREASE one with its
// single zero byte, X25519MLKEM768 with a real ML-KEM-768 encapsulation key
// then an X25519 share, x25519 alone.
func keyShares(tmpl []byte, greaseGroup uint16) ([]byte, error) {
	s := cryptobyte.String(tmpl)
	var shares cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&shares) {
		return nil, errors.New("spa: key_share of the capture")
	}
	var b cryptobyte.Builder
	var err error
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for !shares.Empty() {
			var group uint16
			var key cryptobyte.String
			if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&key) {
				err = errors.New("spa: key_share of the capture")
				return
			}
			var share []byte
			switch {
			case isGREASE(group):
				group, share = greaseGroup, []byte{0}
			case group == 0x11ec: // X25519MLKEM768: ML-KEM first
				dk, kerr := mlkem.GenerateKey768()
				if kerr != nil {
					err = kerr
					return
				}
				share = append(dk.EncapsulationKey().Bytes(), x25519Share()...)
			case group == 0x001d:
				share = x25519Share()
			default:
				share = make([]byte, len(key))
				_, _ = rand.Read(share)
			}
			b.AddUint16(group)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(share) })
		}
	})
	if err != nil {
		return nil, err
	}
	return b.Bytes()
}

// x25519Share is a fresh X25519 public key.
func x25519Share() []byte {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err) // crypto/rand does not fail
	}
	return k.PublicKey().Bytes()
}

// greaseECH is a GREASE encrypted_client_hello as Chrome (BoringSSL) sends
// without an ECH config: the capture's suite, a random config ID, a fresh
// X25519 public key as enc (random bytes would set its top bit half the
// time, which a key never does), and a random payload of 144, 176, 208 or
// 240 bytes, drawn per connection.
func greaseECH(tmpl []byte) ([]byte, error) {
	s := cryptobyte.String(tmpl)
	var outer uint8
	var kdf, aead uint16
	var enc, payload cryptobyte.String
	if !s.ReadUint8(&outer) || outer != 0 || !s.ReadUint16(&kdf) || !s.ReadUint16(&aead) || !s.Skip(1) ||
		!s.ReadUint16LengthPrefixed(&enc) || !s.ReadUint16LengthPrefixed(&payload) {
		return nil, errors.New("spa: encrypted_client_hello of the capture")
	}
	fresh := func(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
	var b cryptobyte.Builder
	b.AddUint8(0)
	b.AddUint16(kdf)
	b.AddUint16(aead)
	b.AddBytes(fresh(1))
	if len(enc) != 32 {
		return nil, errors.New("spa: encrypted_client_hello of the capture: not X25519")
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(x25519Share()) })
	n := fresh(1)[0] & 3 // 144, 176, 208 or 240
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(fresh(16 + 32*(4+int(n)))) })
	return b.Bytes()
}

// IsTLSCarrier reports whether data starts like a TLS handshake record.
func IsTLSCarrier(data []byte) bool {
	return len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04
}

// FromTLSCarrier takes the SPA packet out of a ClientHello carrier: the
// data of its session_ticket extension.
func FromTLSCarrier(data []byte) ([]byte, error) {
	bad := errors.New("spa: not a ClientHello carrier")
	if !IsTLSCarrier(data) || len(data) < 5 {
		return nil, bad
	}
	rec := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+rec {
		return nil, bad
	}
	b := data[5 : 5+rec]
	if len(b) < 4 || b[0] != 0x01 {
		return nil, bad
	}
	n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if len(b) < 4+n {
		return nil, bad
	}
	b = b[4 : 4+n]
	skip := func(k int) bool {
		if len(b) < k {
			return false
		}
		b = b[k:]
		return true
	}
	vec := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		l := 0
		for i := range lenBytes {
			l = l<<8 | int(b[i])
		}
		return skip(lenBytes + l)
	}
	// version, random, session_id, cipher_suites, compression_methods
	if !skip(2+32) || !vec(1) || !vec(2) || !vec(1) || len(b) < 2 {
		return nil, bad
	}
	extLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < extLen {
		return nil, bad
	}
	b = b[:extLen]
	for len(b) >= 4 {
		typ := int(binary.BigEndian.Uint16(b))
		l := int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+l {
			return nil, bad
		}
		if typ == extSessionTicket {
			if l == 0 || l > MaxPacketLen {
				return nil, bad // empty or longer than any packet
			}
			return b[4 : 4+l], nil
		}
		b = b[4+l:]
	}
	return nil, bad
}
