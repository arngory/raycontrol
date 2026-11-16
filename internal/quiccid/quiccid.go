// Package quiccid makes the server connection IDs of naive-quic and DoH3
// routable (spec/quic-cid-route-v1.md): each carries its backend's label,
// which the niko-server front reads from a client's packet that comes from
// an address it does not know yet, so that a connection outlives the
// client's new port (NAT rebinding, a client that moves to a new socket
// at a slot change, spa-v2 §11). An ID is 8 bytes: Speck64/128 of
//
//	label (16 bits) | 0 (8 bits) | counter (40 bits)
//
// under the label's key (cidkey.LabelKey, from the node's secret). The
// front has every label's key; a backend only its own. To anyone without
// it the IDs are random and distinct, their label included. niko-server
// has the same code (nikoserver/quiccid.go); the spec's example checks
// both.
package quiccid

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/arngory/raycontrol/internal/quiccid/cidkey"
)

const (
	// Len is the length of a routable connection ID: what h3serve's IDs
	// have always been (h3serve.ConnIDLen).
	Len = 8
	// MaxLabel is the largest label; 0 is none.
	MaxLabel = cidkey.MaxLabel

	rounds      = 27 // Speck64/128
	counterBits = 40
	// aheadWindow is how far past the last ID issued an ID of the
	// generator's own counts as one it will issue (Generator.Ahead).
	aheadWindow = 1 << 32
)

// Codec is Speck64/128 under a label's key.
type Codec struct {
	rk [rounds]uint32
}

// NewCodec is the codec of a label's key (cidkey.LabelKey, 16 bytes), read
// as the key words l2 l1 l0 k0 of the Speck paper (big-endian).
func NewCodec(labelKey []byte) (*Codec, error) {
	if len(labelKey) != cidkey.KeyLen {
		return nil, fmt.Errorf("quiccid: a key of %d bytes, want %d", len(labelKey), cidkey.KeyLen)
	}
	return newSpeck(labelKey), nil
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
	label, _, ok := c.Decode(id)
	return label, ok
}

// Decode reads the label and the counter of an ID; false when it holds no
// label.
func (c *Codec) Decode(id []byte) (label uint16, counter uint64, ok bool) {
	if len(id) < Len {
		return 0, 0, false
	}
	x, y := c.decrypt(binary.BigEndian.Uint32(id[0:4]), binary.BigEndian.Uint32(id[4:8]))
	label = uint16(x >> 16) //nolint:gosec // G115: the top 16 bits
	return label, uint64(x&0xff)<<32 | uint64(y), x&0xff00 == 0 && label != 0
}

// Generator makes a backend's connection IDs for quic-go
// (quic.Transport.ConnectionIDGenerator): its label and a counter that
// starts from the clock (start), one step per ID. IDs of one generator do
// not repeat before 2^40 of them; those of two labels never meet.
type Generator struct {
	codec *Codec
	label uint16
	next  atomic.Uint64
}

var _ quic.ConnectionIDGenerator = (*Generator)(nil)

// NewGenerator is the generator of a backend's label, under the label's
// key.
func NewGenerator(labelKey []byte, label int) (*Generator, error) {
	return newGeneratorAt(labelKey, label, time.Now())
}

// newGeneratorAt is NewGenerator started at now.
func newGeneratorAt(labelKey []byte, label int, now time.Time) (*Generator, error) {
	if label < 1 || label > MaxLabel {
		return nil, fmt.Errorf("quiccid: label %d, want 1-%d", label, MaxLabel)
	}
	codec, err := NewCodec(labelKey)
	if err != nil {
		return nil, err
	}
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	g := &Generator{codec: codec, label: uint16(label)} //nolint:gosec // G115: checked above
	g.next.Store(start(now, binary.BigEndian.Uint16(b[:])))
	return g, nil
}

// start is a generator's counter at its start: 4096 a second of the clock
// since 1970, and a random offset within the second, modulo 2^40 (the
// counter wraps every 2^28 s, 8.5 years). A process after another starts
// past the IDs the one before issued, as long as that one issued fewer
// than 4096 a second on average since its own start: its IDs are behind
// the new window of Ahead and still get their resets, and the new IDs are
// not the old ones. Without the label's key the counter is not seen: the
// IDs stay random. A clock set back by more than the old process lived
// puts the old IDs in the window: their clients wait out their idle time
// instead of a reset, and nothing else.
func start(now time.Time, random uint16) uint64 {
	return (uint64(now.Unix())<<12 + uint64(random&0xfff)) & (1<<counterBits - 1) //nolint:gosec // G115: the seconds since 1970
}

// GenerateConnectionID is the next ID.
func (g *Generator) GenerateConnectionID() (quic.ConnectionID, error) {
	id := g.codec.Encode(g.label, g.next.Add(1)&(1<<counterBits-1))
	return quic.ConnectionIDFromBytes(id[:]), nil
}

// ConnectionIDLen is Len.
func (g *Generator) ConnectionIDLen() int { return Len }

// Ahead reports whether id is one of the generator's own, its label under
// its key, that it has not issued yet and will within the next 2^32 IDs.
// A server must not answer a packet for such an ID with a stateless reset:
// the token is a function of the ID and the service's key, and whoever has
// the label's key could collect the tokens of the IDs to come and end
// those connections later (h3serve drops such packets). The IDs of a
// process before this one are behind the window (start): they still get
// their resets.
func (g *Generator) Ahead(id []byte) bool {
	if len(id) < Len {
		return false
	}
	x, y := g.codec.decrypt(binary.BigEndian.Uint32(id[0:4]), binary.BigEndian.Uint32(id[4:8]))
	if uint16(x>>16) != g.label || x&0xff00 != 0 { //nolint:gosec // G115: the top 16 bits
		return false
	}
	const mask = 1<<counterBits - 1
	counter := uint64(x&0xff)<<32 | uint64(y)
	d := (counter - g.next.Load()) & mask
	return d >= 1 && d <= aheadWindow
}

// ParseLabelled reads a backend's label and its key from one line:
// "<label> <16 bytes in hex>" (a naive service's file, render.NaiveQUICCID).
// Its errors say what is wrong, never what the line holds.
func ParseLabelled(text []byte) (label int, key []byte, err error) {
	fields := strings.Fields(string(text))
	if len(fields) != 2 {
		return 0, nil, errors.New("want a label and its key")
	}
	if label, err = strconv.Atoi(fields[0]); err != nil || label < 1 || label > MaxLabel {
		return 0, nil, fmt.Errorf("want a label of 1-%d", MaxLabel)
	}
	if key, err = hex.DecodeString(fields[1]); err != nil || len(key) != cidkey.KeyLen {
		return 0, nil, fmt.Errorf("want a key of %d bytes in hex", cidkey.KeyLen)
	}
	return label, key, nil
}

// ReadLabelled reads a backend's label and its key from its file
// (ParseLabelled).
func ReadLabelled(file string) (label int, key []byte, err error) {
	b, err := os.ReadFile(file) //nolint:gosec // G304: the path is the caller's flag
	if err != nil {
		return 0, nil, err
	}
	return ParseLabelled(b)
}
