package spa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// v3Vector is a spa-v3 test vector: a v2 one with the destination address.
type v3Vector struct {
	vectorPacket
	Dst string `json:"dst"`
}

type v3VectorFile struct {
	Comment string       `json:"comment"`
	Params  vectorParams `json:"params"`
	Packets []v3Vector   `json:"packets"`
}

var v3Inputs = []struct {
	vectorInput
	dst string
}{
	{vectorInput{key: 0x11, time: 1767225600, ttl: 600, scope: []uint16{1, 3}, nonce: 0x22, length: 96}, "203.0.113.7"},
	{vectorInput{key: 0x11, time: 1767225600, ttl: 0, scope: nil, nonce: 0x23, length: 160}, "2001:db8::7"},
	{vectorInput{key: 0x55, time: 1767225600 + 86399, ttl: 3600, scope: []uint16{7}, nonce: 0x66, length: 128}, "198.51.100.1"},
	// The shortest a v3 packet with the full scope can be.
	{vectorInput{key: 0x55, time: 1767225600, ttl: 0, scope: []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, nonce: 0x67, length: 101}, "192.0.2.1"},
}

func buildV3Vectors(t *testing.T) v3VectorFile {
	p := testParams()
	p.LenMin = MinPacketLen // the last vector is shorter than testParams' 96
	vf := v3VectorFile{
		Comment: "raycontrol SPA v3 test vectors, see docs/spec/spa-v3.md",
		Params: vectorParams{
			NodeID:    hex.EncodeToString(p.NodeID[:]),
			EpochLenS: int64(p.EpochLen / time.Second),
			SlotLenS:  int64(p.SlotLen / time.Second),
			PortKey:   hex.EncodeToString(p.PortKey[:]),
			PortBase:  p.PortBase,
			PortRange: p.PortRange,
			LenMin:    p.LenMin,
			LenMax:    p.LenMax,
		},
	}
	for _, in := range v3Inputs {
		key := fill32(in.key)
		nonce := bytes.Repeat([]byte{in.nonce}, NonceSize)
		req := Request{Time: time.Unix(in.time, 0), TTL: time.Duration(in.ttl) * time.Second, Scope: in.scope,
			Dst: netip.MustParseAddr(in.dst)}
		pkt, err := Seal(p, key, req, nonce, in.length)
		if err != nil {
			t.Fatal(err)
		}
		e := p.Epoch(req.Time)
		ek := EpochKey(key, p.NodeID, e)
		vf.Packets = append(vf.Packets, v3Vector{vectorPacket: vectorPacket{
			DeviceKey: hex.EncodeToString(key[:]),
			Time:      in.time,
			TTLS:      in.ttl,
			Scope:     in.scope,
			Nonce:     hex.EncodeToString(nonce),
			Length:    in.length,
			Epoch:     e,
			EpochKey:  hex.EncodeToString(ek[:]),
			Packet:    hex.EncodeToString(pkt),
		}, Dst: in.dst})
	}
	return vf
}

func TestV3Vectors(t *testing.T) {
	got, err := json.MarshalIndent(buildV3Vectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	const path = "testdata/vectors-v3.json"
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("vectors changed; the wire format is frozen. Run with -update only for an intended format change.")
	}
}

func TestV3VerifyVectors(t *testing.T) {
	vf := buildV3Vectors(t)
	p := testParams()
	p.LenMin = vf.Params.LenMin
	for _, vp := range vf.Packets {
		pkt, _ := hex.DecodeString(vp.Packet)
		key, _ := hex.DecodeString(vp.DeviceKey)
		v := NewVerifier(p, 10*time.Minute, time.Hour, 1000)
		v.now = func() time.Time { return time.Unix(vp.Time, 0) }
		v.SetDevices([]Device{device("d", key[0], 1, 2, 3, 7)})
		g, err := v.Verify(pkt)
		if err != nil {
			t.Fatalf("vector %s: %v", vp.Nonce[:4], err)
		}
		if g.Dst != netip.MustParseAddr(vp.Dst) {
			t.Fatalf("dst = %v, want %s", g.Dst, vp.Dst)
		}
		// The plaintext layout, independently: version, then the address
		// after the 13-byte header, IPv4 as ::ffff:a.b.c.d.
		pt := openPlain(t, p, [KeySize]byte(key), pkt, vp.Time)
		want := netip.MustParseAddr(vp.Dst).As16()
		if pt[0] != 0x03 || !bytes.Equal(pt[13:29], want[:]) || int(pt[12]) != len(vp.Scope) {
			t.Fatalf("plaintext header %x", pt[:31])
		}
		for i, id := range vp.Scope {
			if pt[29+2*i] != byte(id>>8) || pt[30+2*i] != byte(id) {
				t.Fatalf("scope at %d: %x", i, pt[29+2*i:31+2*i])
			}
		}
		if !allZero(pt[29+2*len(vp.Scope):]) {
			t.Fatal("padding not zero")
		}
	}
}

func openPlain(t *testing.T, p Params, key [KeySize]byte, pkt []byte, ts int64) []byte {
	t.Helper()
	ek := EpochKey(key, p.NodeID, p.Epoch(time.Unix(ts, 0)))
	aead, err := chacha20poly1305.NewX(ek[:])
	if err != nil {
		t.Fatal(err)
	}
	pt, err := aead.Open(nil, pkt[:NonceSize], pkt[NonceSize:], p.aad())
	if err != nil {
		t.Fatal(err)
	}
	return pt
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestV3Lengths(t *testing.T) {
	p := testParams()
	p.LenMin = MinPacketLen
	key := fill32(0x11)
	now := time.Unix(1767225600, 0)
	dst := netip.MustParseAddr("203.0.113.7")
	full := Request{Time: now, Scope: make([]uint16, MaxScope), Dst: dst}
	if full.MinLen() != 101 {
		t.Fatalf("min len %d", full.MinLen())
	}
	if _, err := Seal(p, key, full, nil, 100); !errors.Is(err, ErrLength) {
		t.Fatalf("100 bytes: %v", err)
	}
	// SealRandom never goes below what the request needs.
	for range 200 {
		pkt, err := SealRandom(p, key, full)
		if err != nil || len(pkt) < 101 || len(pkt) > p.LenMax {
			t.Fatalf("len %d, err %v", len(pkt), err)
		}
	}
	tight := p
	tight.LenMax = 100
	if _, err := SealRandom(tight, key, full); !errors.Is(err, ErrLength) {
		t.Fatalf("no room: %v", err)
	}
	if _, err := Seal(p, key, Request{Time: now, Dst: netip.MustParseAddr("fe80::1%eth0")}, nil, 120); err == nil {
		t.Fatal("zone accepted")
	}
}

func TestV3SameKeyAsV2(t *testing.T) {
	// One trial decryption a device and epoch: the version is inside.
	now := time.Unix(1767225600, 0)
	v := newTestVerifier(now, device("a", 0x11, 1, 2))
	g2, err := v.Verify(seal(t, 0x11, Request{Time: now}))
	if err != nil || g2.Dst.IsValid() {
		t.Fatalf("v2: %+v %v", g2, err)
	}
	dst := netip.MustParseAddr("2001:db8::1")
	g3, err := v.Verify(seal(t, 0x11, Request{Time: now, Scope: []uint16{2}, Dst: dst}))
	if err != nil || g3.Dst != dst || !slices.Equal(g3.Scope, []uint16{2}) {
		t.Fatalf("v3: %+v %v", g3, err)
	}
	// A v4 address comes back unmapped.
	g3, err = v.Verify(seal(t, 0x11, Request{Time: now, Dst: netip.MustParseAddr("::ffff:203.0.113.7")}))
	if err != nil || g3.Dst != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("mapped: %+v %v", g3, err)
	}
}

func TestOwnDst(t *testing.T) {
	a := netip.MustParseAddr
	own := []netip.Addr{a("203.0.113.7"), a("2001:db8::7")}
	tests := []struct {
		dst, wire string
		want      bool
	}{
		{"203.0.113.7", "", true},         // a public address
		{"2001:db8::7", "10.0.0.5", true}, // behind 1:1 NAT
		{"10.0.0.5", "10.0.0.5", true},    // where it came to
		{"::ffff:10.0.0.5", "10.0.0.5", true},
		{"198.51.100.9", "10.0.0.5", false}, // somebody else's
		{"198.51.100.9", "", false},
		{"64:ff9b::cb00:7107", "", true},      // 203.0.113.7 through the well-known NAT64 prefix
		{"64:ff9b::a00:5", "10.0.0.5", true},  // the wire address the same way
		{"64:ff9b::c633:6409", "", false},     // somebody else's there
		{"2001:db8:64::cb00:7107", "", false}, // a network's own NAT64 prefix: anyone can have these low bits
		{"64:ff9b:1::cb00:7107", "", false},
	}
	for _, tt := range tests {
		var wire netip.Addr
		if tt.wire != "" {
			wire = a(tt.wire)
		}
		if got := OwnDst(a(tt.dst), wire, own); got != tt.want {
			t.Errorf("OwnDst(%s, %s) = %v", tt.dst, tt.wire, got)
		}
	}
	if OwnDst(netip.Addr{}, a("10.0.0.5"), own) {
		t.Error("unset destination taken")
	}
}
