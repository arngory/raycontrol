// Package quiccid makes the server connection IDs of naive-quic and DoH3
// routable (spec/quic-cid-route-v1.md): each carries its backend's label,
// which the niko-server front reads from a client's packet that comes from
// an address it does not know yet, so that a connection outlives the
// client's new port (NAT rebinding, a client that moves to a new socket
// at a slot change, spa-v2 §11). An ID is 8 bytes: Speck64/128 of
//
//	label (16 bits) | 0 (8 bits) | counter (40 bits)
//
// under a key derived from the node's secret, which the front and every
// QUIC backend of the node share. To anyone without it the IDs are random
// and distinct, their label included. niko-server has the same code
// (nikoserver/quiccid.go); the spec's example checks both.
package quiccid

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"strings"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

const (
	// Len is the length of a routable connection ID: what h3serve's IDs
	// have always been (h3serve.ConnIDLen).
	Len = 8
	// MaxLabel is the largest label; 0 is none.
	MaxLabel = 1<<16 - 1
	// SecretLen is the node's secret: 32 bytes.
	SecretLen = 32

	rounds      = 27 // Speck64/128
	counterBits = 40
	keyContext  = "quic-cid-route-v1"
)

// Codec is Speck64/128 under the key of a node's secret.
type Codec struct {
	rk [rounds]uint32
}

// NewCodec derives the Speck key from the node's secret:
// HMAC-SHA256(secret, "quic-cid-route-v1"), its first 16 bytes, read as
// the key words l2 l1 l0 k0 of the Speck paper (big-endian).
func NewCodec(secret []byte) (*Codec, error) {
	if len(secret) != SecretLen {
		return nil, fmt.Errorf("quiccid: a secret of %d bytes, want %d", len(secret), SecretLen)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(keyContext))
	return newSpeck(mac.Sum(nil)[:16]), nil
}

func newSpeck(key []byte) *Codec {
	c := &Codec{}
	l := [rounds + 2]uint32{binary.BigEndian.Uint32(key[8:12]), binary.BigEndian.Uint32(key[4:8]), binary.BigEndian.Uint32(key[0:4])}
	c.rk[0] = binary.BigEndian.Uint32(key[12:16])
	for i := range rounds - 1 {
		l[i+3] = (c.rk[i] + bits.RotateLeft32(l[i], -8)) ^ uint32(i) //nolint:gosec // G115: i < 26
		c.rk[i+1] = bits.RotateLeft32(c.rk[i], 3) ^ l[i+3]
	}
	return c
}

func (c *Codec) encrypt(x, y uint32) (uint32, uint32) {
	for _, k := range c.rk {
		x = (bits.RotateLeft32(x, -8) + y) ^ k
		y = bits.RotateLeft32(y, 3) ^ x
	}
	return x, y
}

func (c *Codec) decrypt(x, y uint32) (uint32, uint32) {
	for i := rounds - 1; i >= 0; i-- {
		y = bits.RotateLeft32(y^x, -3)
		x = bits.RotateLeft32((x^c.rk[i])-y, 8)
	}
	return x, y
}

// Encode is the ID of a label and a counter (its low 40 bits).
func (c *Codec) Encode(label uint16, counter uint64) [Len]byte {
	x := uint32(label)<<16 | uint32(counter>>32)&0xff //nolint:gosec // G115: 8 bits of it
	x, y := c.encrypt(x, uint32(counter))             //nolint:gosec // G115: the low 32 bits
	var id [Len]byte
	binary.BigEndian.PutUint32(id[0:4], x)
	binary.BigEndian.PutUint32(id[4:8], y)
	return id
}

// Label reads the label of an ID; false when it holds none.
func (c *Codec) Label(id []byte) (uint16, bool) {
	if len(id) < Len {
		return 0, false
	}
	x, _ := c.decrypt(binary.BigEndian.Uint32(id[0:4]), binary.BigEndian.Uint32(id[4:8]))
	label := uint16(x >> 16) //nolint:gosec // G115: the top 16 bits
	return label, x&0xff00 == 0 && label != 0
}

// Generator makes a backend's connection IDs for quic-go
// (quic.Transport.ConnectionIDGenerator): its label and a counter that
// starts at random, one step per ID. IDs of one generator do not repeat
// before 2^40 of them; those of two labels never meet.
type Generator struct {
	codec *Codec
	label uint16
	next  atomic.Uint64
}

var _ quic.ConnectionIDGenerator = (*Generator)(nil)

// NewGenerator is the generator of a backend's label, under the node's
// secret.
func NewGenerator(secret []byte, label int) (*Generator, error) {
	if label < 1 || label > MaxLabel {
		return nil, fmt.Errorf("quiccid: label %d, want 1-%d", label, MaxLabel)
	}
	codec, err := NewCodec(secret)
	if err != nil {
		return nil, err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	g := &Generator{codec: codec, label: uint16(label)} //nolint:gosec // G115: checked above
	g.next.Store(binary.BigEndian.Uint64(b[:]))
	return g, nil
}

// GenerateConnectionID is the next ID.
func (g *Generator) GenerateConnectionID() (quic.ConnectionID, error) {
	id := g.codec.Encode(g.label, g.next.Add(1)&(1<<counterBits-1))
	return quic.ConnectionIDFromBytes(id[:]), nil
}

// ConnectionIDLen is Len.
func (g *Generator) ConnectionIDLen() int { return Len }

// ParseSecret reads the node's secret from its file's text: 32 bytes in
// hex, white space around it aside.
func ParseSecret(text []byte) ([]byte, error) {
	secret, err := hex.DecodeString(strings.TrimSpace(string(text)))
	if err != nil || len(secret) != SecretLen {
		return nil, errors.New("want 32 bytes in hex")
	}
	return secret, nil
}

// ReadSecret reads the node's secret from its file. Its errors say what
// is wrong with the file, never what it holds.
func ReadSecret(file string) ([]byte, error) {
	b, err := os.ReadFile(file) //nolint:gosec // G304: the path is the caller's flag
	if err != nil {
		return nil, err
	}
	return ParseSecret(b)
}
