package spa

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Request is the plaintext of a SPA packet.
type Request struct {
	Time  time.Time
	TTL   time.Duration // 0 asks for the server default
	Scope []uint16      // service IDs; empty asks for everything the device may use
	// Dst is the address the packet is sent to (spa-v3 §3). Set, it makes
	// a v3 packet, which a node takes only at one of its own addresses;
	// unset, a v2 packet as before.
	Dst netip.Addr
}

// MinLen is the shortest packet that holds req: a v3 one is 16 bytes
// longer than a v2 one with the same scope.
func (req Request) MinLen() int {
	n := NonceSize + headerSize + 2*len(req.Scope) + TagSize
	if req.Dst.IsValid() {
		n += DstSize
	}
	return n
}

var (
	ErrLength  = errors.New("spa: packet length out of range")
	ErrAuth    = errors.New("spa: packet does not authenticate")
	ErrVersion = errors.New("spa: unknown version")
	ErrFormat  = errors.New("spa: malformed plaintext")
	// ErrDst: a v3 packet names an address that is not the node's.
	ErrDst = errors.New("spa: packet is for another address")
)

// Seal builds a packet of exactly length bytes for the device key and the
// epoch that contains req.Time. nonce must be NonceSize bytes; pass nil to
// draw it from crypto/rand. Padding bytes are zero: they are encrypted, so
// the packet stays indistinguishable from random.
func Seal(p Params, deviceKey [KeySize]byte, req Request, nonce []byte, length int) ([]byte, error) {
	if len(req.Scope) > MaxScope {
		return nil, fmt.Errorf("spa: scope has %d services, max %d", len(req.Scope), MaxScope)
	}
	if length < p.LenMin || length > p.LenMax || length < req.MinLen() {
		return nil, ErrLength
	}
	if req.Dst.IsValid() && req.Dst.Zone() != "" {
		return nil, fmt.Errorf("spa: destination %v has a zone", req.Dst)
	}
	ttl := req.TTL / time.Second
	if ttl < 0 || ttl > 0xffff {
		return nil, fmt.Errorf("spa: ttl %v out of range", req.TTL)
	}
	if nonce == nil {
		nonce = make([]byte, NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("spa: nonce must be %d bytes", NonceSize)
	}

	pt := make([]byte, length-NonceSize-TagSize)
	pt[0] = Version
	ids := headerSize
	if req.Dst.IsValid() {
		pt[0] = Version3
		a := req.Dst.As16() // IPv4 as ::ffff:a.b.c.d
		copy(pt[headerSize:], a[:])
		ids += DstSize
	}
	binary.BigEndian.PutUint64(pt[1:9], uint64(req.Time.Unix()))
	binary.BigEndian.PutUint16(pt[9:11], uint16(ttl))
	pt[11] = 0 // flags, reserved
	pt[12] = byte(len(req.Scope))
	for i, id := range req.Scope {
		binary.BigEndian.PutUint16(pt[ids+2*i:], id)
	}

	key := EpochKey(deviceKey, p.NodeID, p.Epoch(req.Time))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, length)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, pt, p.aad()), nil
}

// SealRandom is Seal with a random nonce and a random length within the
// node's bounds, from the shortest that holds req (spa-v3 §2). Clients use
// it.
func SealRandom(p Params, deviceKey [KeySize]byte, req Request) ([]byte, error) {
	lo := max(p.LenMin, req.MinLen())
	if lo > p.LenMax {
		return nil, ErrLength
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(p.LenMax-lo+1)))
	if err != nil {
		return nil, err
	}
	return Seal(p, deviceKey, req, nil, lo+int(n.Int64()))
}

// open decrypts pkt with an epoch key and parses the plaintext.
func open(p Params, epochKey [KeySize]byte, pkt []byte) (Request, error) {
	aead, err := chacha20poly1305.NewX(epochKey[:])
	if err != nil {
		return Request{}, err
	}
	pt, err := aead.Open(nil, pkt[:NonceSize], pkt[NonceSize:], p.aad())
	if err != nil {
		return Request{}, ErrAuth
	}
	ids := headerSize
	switch pt[0] {
	case Version:
	case Version3:
		ids += DstSize
	default:
		return Request{}, ErrVersion
	}
	n := int(pt[12])
	if n > MaxScope || ids+2*n > len(pt) || pt[11] != 0 {
		return Request{}, ErrFormat
	}
	req := Request{
		Time: time.Unix(int64(binary.BigEndian.Uint64(pt[1:9])), 0),
		TTL:  time.Duration(binary.BigEndian.Uint16(pt[9:11])) * time.Second,
	}
	if pt[0] == Version3 {
		req.Dst = netip.AddrFrom16([16]byte(pt[headerSize:ids])).Unmap()
	}
	for i := range n {
		req.Scope = append(req.Scope, binary.BigEndian.Uint16(pt[ids+2*i:]))
	}
	return req, nil
}
