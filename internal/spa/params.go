// Package spa implements raycontrol SPA v2: single packet authorization with
// per-epoch device keys and a time-rotated listening port.
//
// The wire format is specified in docs/spec/spa-v2.md. Test vectors shared
// with clients live in testdata/vectors.json.
package spa

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

const (
	// Version is the plaintext version byte of SPA v2 packets.
	Version = 0x02

	NonceSize  = 24
	TagSize    = 16
	KeySize    = 32
	NodeIDSize = 16

	// headerSize is version + time + ttl + flags + scope count.
	headerSize = 1 + 8 + 2 + 1 + 1
	// MaxScope is the largest number of service IDs a packet may request.
	MaxScope = 16

	// MinPacketLen fits a packet that requests MaxScope services.
	MinPacketLen = NonceSize + headerSize + 2*MaxScope + TagSize
	MaxPacketLen = 512

	// MaxSkew is how far the packet time may differ from the server clock.
	MaxSkew = 30 * time.Second
)

// Params are the per-node SPA parameters. Every installation picks them at
// random (see RandomParams) so that deployments share no fixed ports, packet
// lengths or timings. Clients receive them when a device is enrolled.
type Params struct {
	NodeID    [NodeIDSize]byte
	EpochLen  time.Duration // key rotation period
	SlotLen   time.Duration // port rotation period
	PortKey   [KeySize]byte
	PortBase  uint16
	PortRange uint16
	LenMin    int // packet length bounds, inclusive
	LenMax    int
}

// Bounds of the random choices made by RandomParams.
var (
	epochChoices = [2]time.Duration{6 * time.Hour, 24 * time.Hour}
	slotChoices  = [2]time.Duration{5 * time.Minute, 30 * time.Minute}
	portLow      = 20000
	portHigh     = 60999
	rangeChoices = [2]int{1024, 4096}
	lenMinChoice = [2]int{MinPacketLen, 160}
	lenSpread    = [2]int{32, 128}
)

// RandomParams draws a fresh parameter set from r (crypto/rand when nil).
func RandomParams(r io.Reader) (Params, error) {
	if r == nil {
		r = rand.Reader
	}
	var p Params
	if _, err := io.ReadFull(r, p.NodeID[:]); err != nil {
		return p, err
	}
	if _, err := io.ReadFull(r, p.PortKey[:]); err != nil {
		return p, err
	}
	pick := func(lo, hi int) (int, error) {
		n, err := rand.Int(r, big.NewInt(int64(hi-lo+1)))
		if err != nil {
			return 0, err
		}
		return lo + int(n.Int64()), nil
	}
	minutes := func(b [2]time.Duration) (time.Duration, error) {
		m, err := pick(int(b[0]/time.Minute), int(b[1]/time.Minute))
		return time.Duration(m) * time.Minute, err
	}
	var err error
	if p.EpochLen, err = minutes(epochChoices); err != nil {
		return p, err
	}
	if p.SlotLen, err = minutes(slotChoices); err != nil {
		return p, err
	}
	rng, err := pick(rangeChoices[0], rangeChoices[1])
	if err != nil {
		return p, err
	}
	base, err := pick(portLow, portHigh-rng)
	if err != nil {
		return p, err
	}
	p.PortBase, p.PortRange = uint16(base), uint16(rng)
	if p.LenMin, err = pick(lenMinChoice[0], lenMinChoice[1]); err != nil {
		return p, err
	}
	spread, err := pick(lenSpread[0], lenSpread[1])
	if err != nil {
		return p, err
	}
	p.LenMax = p.LenMin + spread
	return p, p.Validate()
}

// Validate reports whether p is usable.
func (p Params) Validate() error {
	switch {
	case p.EpochLen < time.Minute || p.EpochLen%time.Second != 0:
		return errors.New("spa: epoch length must be whole seconds, at least one minute")
	case p.SlotLen < time.Minute || p.SlotLen%time.Second != 0:
		return errors.New("spa: slot length must be whole seconds, at least one minute")
	case p.PortRange == 0:
		return errors.New("spa: empty port range")
	case int(p.PortBase)+int(p.PortRange) > 65536 || p.PortBase < 1024:
		return fmt.Errorf("spa: port range %d+%d out of bounds", p.PortBase, p.PortRange)
	case p.LenMin < MinPacketLen || p.LenMax > MaxPacketLen || p.LenMin > p.LenMax:
		return fmt.Errorf("spa: packet length bounds %d..%d out of %d..%d", p.LenMin, p.LenMax, MinPacketLen, MaxPacketLen)
	}
	return nil
}

// Epoch returns the key epoch that contains t.
func (p Params) Epoch(t time.Time) uint64 {
	return uint64(t.Unix()) / uint64(p.EpochLen/time.Second)
}

// Slot returns the port slot that contains t.
func (p Params) Slot(t time.Time) uint64 {
	return uint64(t.Unix()) / uint64(p.SlotLen/time.Second)
}

func be64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
