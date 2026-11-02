package spa

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

const (
	keyInfo  = "raycontrol-spa-v2 key"
	portInfo = "raycontrol-spa-v2 port"
	aadLabel = "raycontrol-spa-v2"
)

// EpochKey derives the packet key of a device for one epoch:
// HKDF-SHA256(ikm = device key, salt = node ID, info = label || epoch).
func EpochKey(deviceKey [KeySize]byte, nodeID [NodeIDSize]byte, epoch uint64) [KeySize]byte {
	info := append([]byte(keyInfo), be64(epoch)...)
	k, err := hkdf.Key(sha256.New, deviceKey[:], nodeID[:], string(info), KeySize)
	if err != nil {
		// Only possible for an output longer than 255 hash blocks.
		panic(err)
	}
	var out [KeySize]byte
	copy(out[:], k)
	return out
}

// Port returns the SPA listening port of a slot:
// base + first 8 bytes of HMAC-SHA256(port key, label || slot) mod range.
func (p Params) Port(slot uint64) uint16 {
	m := hmac.New(sha256.New, p.PortKey[:])
	m.Write([]byte(portInfo))
	m.Write(be64(slot))
	v := binary.BigEndian.Uint64(m.Sum(nil)[:8])
	return p.PortBase + uint16(v%uint64(p.PortRange))
}

// ActivePorts returns the ports of the previous, current and next slot at t,
// without duplicates. The server listens on all of them so that clients with a
// slightly different clock still hit an open port.
func (p Params) ActivePorts(t time.Time) []uint16 {
	s := p.Slot(t)
	out := make([]uint16, 0, 3)
	for _, slot := range []uint64{s - 1, s, s + 1} {
		port := p.Port(slot)
		dup := false
		for _, have := range out {
			dup = dup || have == port
		}
		if !dup {
			out = append(out, port)
		}
	}
	return out
}

func (p Params) aad() []byte {
	return append([]byte(aadLabel), p.NodeID[:]...)
}
