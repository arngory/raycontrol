package spa

import (
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"errors"
	mrand "math/rand/v2"
)

// The TCP carrier in the shape of a TLS ClientHello (spa-v2.md §10.1,
// RAYCONTROL.md §22.2.3): 96-512 random bytes as the first data of a TCP
// connection are the class of traffic some censors drop on sight; the start
// of a TLS handshake is not. The SPA packet travels as the opaque ticket of
// the session_ticket extension, which a client resuming a session sends as
// it is; everything else is what a browser's ClientHello carries, with fresh
// random values and a real ML-KEM-768 key share.

const (
	extSessionTicket = 0x0023
	// TLSCarrierMax bounds what the node reads of a ClientHello carrier.
	TLSCarrierMax = 4096
)

// TLSCarrier wraps a sealed SPA packet in a ClientHello record.
func TLSCarrier(pkt []byte) ([]byte, error) {
	if len(pkt) == 0 || len(pkt) > MaxPacketLen {
		return nil, errors.New("spa: packet length out of range")
	}
	var random, sessionID, x25519 [32]byte
	_, _ = rand.Read(random[:])
	_, _ = rand.Read(sessionID[:])
	_, _ = rand.Read(x25519[:])
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	hybrid := append(dk.EncapsulationKey().Bytes(), x25519[:]...) // X25519MLKEM768: ML-KEM first

	u16 := func(b []byte, v int) []byte { return binary.BigEndian.AppendUint16(b, uint16(v)) }
	ext := func(typ int, body []byte) []byte { return append(u16(u16(nil, typ), len(body)), body...) }
	list16 := func(items ...int) []byte {
		var b []byte
		for _, it := range items {
			b = u16(b, it)
		}
		return u16(nil, len(b)) // the caller appends b
	}

	var exts [][]byte
	// supported_versions: TLS 1.3, 1.2.
	exts = append(exts, ext(0x002b, []byte{4, 0x03, 0x04, 0x03, 0x03}))
	// supported_groups: X25519MLKEM768, x25519, secp256r1, secp384r1.
	groups := []int{0x11ec, 0x001d, 0x0017, 0x0018}
	g := list16(groups...)
	for _, v := range groups {
		g = u16(g, v)
	}
	exts = append(exts, ext(0x000a, g))
	// key_share: X25519MLKEM768 and x25519.
	var ks []byte
	ks = u16(ks, 0x11ec)
	ks = u16(ks, len(hybrid))
	ks = append(ks, hybrid...)
	ks = u16(ks, 0x001d)
	ks = u16(ks, 32)
	ks = append(ks, x25519[:]...)
	exts = append(exts, ext(0x0033, append(u16(nil, len(ks)), ks...)))
	// signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256,
	// rsa_pkcs1_sha256, ecdsa_secp384r1_sha384, rsa_pss_rsae_sha384,
	// rsa_pkcs1_sha384, rsa_pss_rsae_sha512, rsa_pkcs1_sha512.
	algs := []int{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	sa := list16(algs...)
	for _, v := range algs {
		sa = u16(sa, v)
	}
	exts = append(exts, ext(0x000d, sa))
	exts = append(exts, ext(0x002d, []byte{1, 1}))                                                          // psk_key_exchange_modes: psk_dhe_ke
	exts = append(exts, ext(0x000b, []byte{1, 0}))                                                          // ec_point_formats: uncompressed
	exts = append(exts, ext(0x0017, nil))                                                                   // extended_master_secret
	exts = append(exts, ext(0xff01, []byte{0}))                                                             // renegotiation_info
	exts = append(exts, ext(0x0010, []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'})) // ALPN
	exts = append(exts, ext(extSessionTicket, pkt))                                                         // the SPA packet
	// Browsers shuffle their extensions; so does this.
	mrand.Shuffle(len(exts), func(i, j int) { exts[i], exts[j] = exts[j], exts[i] })

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, random[:]...)
	body = append(body, 32)
	body = append(body, sessionID[:]...)
	suites := []int{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8}
	body = u16(body, 2*len(suites))
	for _, s := range suites {
		body = u16(body, s)
	}
	body = append(body, 1, 0) // compression: null
	var all []byte
	for _, e := range exts {
		all = append(all, e...)
	}
	body = u16(body, len(all))
	body = append(body, all...)

	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...), nil
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
