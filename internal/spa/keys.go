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

// DNSAuthKey derives a device's key for the queries of one DNS tunnel
// service (spec/dnsauth-v1.md §2): HKDF-SHA256(ikm = device key, salt =
// node ID, info = "raycontrol-dnsauth-v1" || service ID). The tunnel's
// backend gets these keys, never the device keys themselves.
func DNSAuthKey(deviceKey [KeySize]byte, nodeID [NodeIDSize]byte, serviceID uint16) [KeySize]byte {
	info := append([]byte("raycontrol-dnsauth-v1"), byte(serviceID>>8), byte(serviceID))
	k, err := hkdf.Key(sha256.New, deviceKey[:], nodeID[:], string(info), KeySize)
	if err != nil {
		panic(err)
	}
	var out [KeySize]byte
	copy(out[:], k)
	return out
}

// RelayKey derives a device's SPA key for one relay in front of the node
// (spec/relay-v1.md §3): HKDF-SHA256(ikm = device key, salt = the exit's node
// ID, info = "raycontrol-relay-v1" || the relay's own node ID (16 bytes) ||
// the relay's name, as relays[].id in the subscription). The relay gets
// these keys, never the device keys: a relay taken over cannot knock at the
// exit with them, nor at another relay. The relay's node ID is new with
// every bundle (rayctl relay bundle) and every relay added again, so the
// keys a seized relay held stop working there too.
func RelayKey(deviceKey [KeySize]byte, exitNodeID, relayNodeID [NodeIDSize]byte, relayName string) [KeySize]byte {
	info := append(append([]byte("raycontrol-relay-v1"), relayNodeID[:]...), relayName...)
	k, err := hkdf.Key(sha256.New, deviceKey[:], exitNodeID[:], string(info), KeySize)
	if err != nil {
		panic(err)
	}
	var out [KeySize]byte
	copy(out[:], k)
	return out
}
