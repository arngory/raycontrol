package spa

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Request is the plaintext of a SPA packet.
type Request struct {
	Time  time.Time
	TTL   time.Duration // 0 asks for the server default
	Scope []uint16      // service IDs; empty asks for everything the device may use
}

var (
	ErrLength  = errors.New("spa: packet length out of range")
	ErrAuth    = errors.New("spa: packet does not authenticate")
	ErrVersion = errors.New("spa: unknown version")
	ErrFormat  = errors.New("spa: malformed plaintext")
)

// Seal builds a packet of exactly length bytes for the device key and the
// epoch that contains req.Time. nonce must be NonceSize bytes; pass nil to
// draw it from crypto/rand. Padding bytes are zero: they are encrypted, so
// the packet stays indistinguishable from random.
func Seal(p Params, deviceKey [KeySize]byte, req Request, nonce []byte, length int) ([]byte, error) {
	if length < p.LenMin || length > p.LenMax {
		return nil, ErrLength
	}
	if len(req.Scope) > MaxScope {
		return nil, fmt.Errorf("spa: scope has %d services, max %d", len(req.Scope), MaxScope)
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
	binary.BigEndian.PutUint64(pt[1:9], uint64(req.Time.Unix()))
	binary.BigEndian.PutUint16(pt[9:11], uint16(ttl))
	pt[11] = 0 // flags, reserved
	pt[12] = byte(len(req.Scope))
	for i, id := range req.Scope {
		binary.BigEndian.PutUint16(pt[headerSize+2*i:], id)
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
// node's bounds. Clients use it.
func SealRandom(p Params, deviceKey [KeySize]byte, req Request) ([]byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(p.LenMax-p.LenMin+1)))
	if err != nil {
		return nil, err
	}
	return Seal(p, deviceKey, req, nil, p.LenMin+int(n.Int64()))
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
	if pt[0] != Version {
		return Request{}, ErrVersion
	}
	n := int(pt[12])
	if n > MaxScope || headerSize+2*n > len(pt) || pt[11] != 0 {
		return Request{}, ErrFormat
	}
	req := Request{
		Time: time.Unix(int64(binary.BigEndian.Uint64(pt[1:9])), 0),
		TTL:  time.Duration(binary.BigEndian.Uint16(pt[9:11])) * time.Second,
	}
	for i := range n {
		req.Scope = append(req.Scope, binary.BigEndian.Uint16(pt[headerSize+2*i:]))
	}
	return req, nil
}
