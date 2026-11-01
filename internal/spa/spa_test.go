package spa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"slices"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

func fill32(b byte) (out [KeySize]byte) {
	for i := range out {
		out[i] = b
	}
	return out
}

func fill16(b byte) (out [NodeIDSize]byte) {
	for i := range out {
		out[i] = b
	}
	return out
}

func testParams() Params {
	return Params{
		NodeID:    fill16(0x33),
		EpochLen:  24 * time.Hour,
		SlotLen:   10 * time.Minute,
		PortKey:   fill32(0x44),
		PortBase:  40000,
		PortRange: 4096,
		LenMin:    96,
		LenMax:    160,
	}
}

type vectorFile struct {
	Comment string         `json:"comment"`
	Params  vectorParams   `json:"params"`
	Ports   []vectorPort   `json:"ports"`
	Packets []vectorPacket `json:"packets"`
}

type vectorParams struct {
	NodeID    string `json:"node_id"`
	EpochLenS int64  `json:"epoch_len_s"`
	SlotLenS  int64  `json:"slot_len_s"`
	PortKey   string `json:"port_key"`
	PortBase  uint16 `json:"port_base"`
	PortRange uint16 `json:"port_range"`
	LenMin    int    `json:"len_min"`
	LenMax    int    `json:"len_max"`
}

type vectorPort struct {
	Time int64  `json:"time"`
	Slot uint64 `json:"slot"`
	Port uint16 `json:"port"`
}

type vectorPacket struct {
	DeviceKey string   `json:"device_key"`
	Time      int64    `json:"time"`
	TTLS      int      `json:"ttl_s"`
	Scope     []uint16 `json:"scope"`
	Nonce     string   `json:"nonce"`
	Length    int      `json:"length"`
	Epoch     uint64   `json:"epoch"`
	EpochKey  string   `json:"epoch_key"`
	Packet    string   `json:"packet"`
}

type vectorInput struct {
	key    byte
	time   int64
	ttl    int
	scope  []uint16
	nonce  byte
	length int
}

var vectorInputs = []vectorInput{
	{key: 0x11, time: 1767225600, ttl: 600, scope: []uint16{1, 3}, nonce: 0x22, length: 96},
	{key: 0x11, time: 1767225600, ttl: 0, scope: nil, nonce: 0x23, length: 160},
	{key: 0x55, time: 1767225600 + 86399, ttl: 3600, scope: []uint16{7}, nonce: 0x66, length: 128},
}

func buildVectors(t *testing.T) vectorFile {
	p := testParams()
	vf := vectorFile{
		Comment: "raycontrol SPA v2 test vectors, see docs/spec/spa-v2.md",
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
	for _, ts := range []int64{1767225600, 1767225600 + 599, 1767225600 + 600, 1767312000} {
		s := p.Slot(time.Unix(ts, 0))
		vf.Ports = append(vf.Ports, vectorPort{Time: ts, Slot: s, Port: p.Port(s)})
	}
	for _, in := range vectorInputs {
		key := fill32(in.key)
		nonce := bytes.Repeat([]byte{in.nonce}, NonceSize)
		req := Request{Time: time.Unix(in.time, 0), TTL: time.Duration(in.ttl) * time.Second, Scope: in.scope}
		pkt, err := Seal(p, key, req, nonce, in.length)
		if err != nil {
			t.Fatal(err)
		}
		e := p.Epoch(req.Time)
		ek := EpochKey(key, p.NodeID, e)
		vf.Packets = append(vf.Packets, vectorPacket{
			DeviceKey: hex.EncodeToString(key[:]),
			Time:      in.time,
			TTLS:      in.ttl,
			Scope:     in.scope,
			Nonce:     hex.EncodeToString(nonce),
			Length:    in.length,
			Epoch:     e,
			EpochKey:  hex.EncodeToString(ek[:]),
			Packet:    hex.EncodeToString(pkt),
		})
	}
	return vf
}

func TestVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	const path = "testdata/vectors.json"
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

func newTestVerifier(now time.Time, devices ...Device) *Verifier {
	v := NewVerifier(testParams(), 10*time.Minute, time.Hour, 1000)
	v.now = func() time.Time { return now }
	v.SetDevices(devices)
	return v
}

func device(id string, key byte, allowed ...uint16) Device {
	return Device{ID: id, Key: fill32(key), Allowed: allowed}
}

func seal(t *testing.T, key byte, req Request) []byte {
	t.Helper()
	pkt, err := SealRandom(testParams(), fill32(key), req)
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func TestVerifyVectors(t *testing.T) {
	vf := buildVectors(t)
	for _, vp := range vf.Packets {
		pkt, _ := hex.DecodeString(vp.Packet)
		key, _ := hex.DecodeString(vp.DeviceKey)
		v := newTestVerifier(time.Unix(vp.Time, 0), device("d", key[0], 1, 2, 3, 7))
		g, err := v.Verify(pkt)
		if err != nil {
			t.Fatalf("vector %s: %v", vp.Nonce[:4], err)
		}
		if g.DeviceID != "d" {
			t.Fatalf("device = %q", g.DeviceID)
		}
	}
}

func TestScopeAndTTL(t *testing.T) {
	now := time.Unix(1767225600, 0)
	tests := []struct {
		name    string
		req     Request
		scope   []uint16
		ttl     time.Duration
		wantErr error
	}{
		{"default scope and ttl", Request{}, []uint16{1, 2}, 10 * time.Minute, nil},
		{"intersection", Request{Scope: []uint16{2, 9, 2}}, []uint16{2}, 10 * time.Minute, nil},
		{"nothing allowed", Request{Scope: []uint16{9}}, nil, 0, ErrScope},
		{"ttl clamped", Request{TTL: 5 * time.Hour}, []uint16{1, 2}, time.Hour, nil},
		{"ttl requested", Request{TTL: 2 * time.Minute}, []uint16{1, 2}, 2 * time.Minute, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newTestVerifier(now, device("a", 0x11, 1, 2))
			tt.req.Time = now
			g, err := v.Verify(seal(t, 0x11, tt.req))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err == nil && (!slices.Equal(g.Scope, tt.scope) || g.TTL != tt.ttl) {
				t.Fatalf("grant = %+v", g)
			}
		})
	}
}

func TestRejects(t *testing.T) {
	now := time.Unix(1767225600, 0)
	good := seal(t, 0x11, Request{Time: now})

	t.Run("replay", func(t *testing.T) {
		v := newTestVerifier(now, device("a", 0x11, 1))
		if _, err := v.Verify(good); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(good); !errors.Is(err, ErrReplay) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("replay after skew window is stale", func(t *testing.T) {
		v := newTestVerifier(now, device("a", 0x11, 1))
		if _, err := v.Verify(good); err != nil {
			t.Fatal(err)
		}
		v.now = func() time.Time { return now.Add(2*MaxSkew + time.Second) }
		if _, err := v.Verify(good); !errors.Is(err, ErrStale) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("stale", func(t *testing.T) {
		v := newTestVerifier(now.Add(MaxSkew+time.Second), device("a", 0x11, 1))
		if _, err := v.Verify(good); !errors.Is(err, ErrStale) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("future", func(t *testing.T) {
		v := newTestVerifier(now.Add(-MaxSkew-time.Second), device("a", 0x11, 1))
		if _, err := v.Verify(good); !errors.Is(err, ErrStale) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unknown device", func(t *testing.T) {
		v := newTestVerifier(now, device("b", 0x12, 1))
		if _, err := v.Verify(good); !errors.Is(err, ErrAuth) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("revoked device", func(t *testing.T) {
		v := newTestVerifier(now, device("a", 0x11, 1))
		v.SetDevices(nil)
		if _, err := v.Verify(good); !errors.Is(err, ErrAuth) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		v := newTestVerifier(now, device("a", 0x11, 1))
		for _, i := range []int{0, NonceSize, len(good) - 1} {
			bad := slices.Clone(good)
			bad[i] ^= 1
			if _, err := v.Verify(bad); !errors.Is(err, ErrAuth) {
				t.Fatalf("byte %d: err = %v", i, err)
			}
		}
	})
	t.Run("other node", func(t *testing.T) {
		p := testParams()
		p.NodeID[0] ^= 1
		pkt, err := SealRandom(p, fill32(0x11), Request{Time: now})
		if err != nil {
			t.Fatal(err)
		}
		v := newTestVerifier(now, device("a", 0x11, 1))
		if _, err := v.Verify(pkt); !errors.Is(err, ErrAuth) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("length", func(t *testing.T) {
		v := newTestVerifier(now, device("a", 0x11, 1))
		for _, n := range []int{testParams().LenMin - 1, testParams().LenMax + 1} {
			if _, err := v.Verify(make([]byte, n)); !errors.Is(err, ErrLength) {
				t.Fatalf("len %d: err = %v", n, err)
			}
		}
	})
	t.Run("cache full fails closed", func(t *testing.T) {
		v := NewVerifier(testParams(), time.Minute, time.Hour, 1)
		v.now = func() time.Time { return now }
		v.SetDevices([]Device{device("a", 0x11, 1)})
		if _, err := v.Verify(good); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(seal(t, 0x11, Request{Time: now})); !errors.Is(err, ErrBusy) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestEpochBoundary(t *testing.T) {
	p := testParams()
	last := time.Unix(int64(p.Epoch(time.Unix(1767225600, 0))+1)*int64(p.EpochLen/time.Second)-1, 0)
	pkt := seal(t, 0x11, Request{Time: last})
	// The server clock is already in the next epoch.
	v := newTestVerifier(last.Add(2*time.Second), device("a", 0x11, 1))
	if _, err := v.Verify(pkt); err != nil {
		t.Fatal(err)
	}
	if p.Epoch(last) == p.Epoch(last.Add(2*time.Second)) {
		t.Fatal("test does not cross an epoch boundary")
	}
}

func TestSealLimits(t *testing.T) {
	p := testParams()
	key := fill32(0x11)
	now := time.Unix(1767225600, 0)
	if _, err := Seal(p, key, Request{Time: now}, nil, p.LenMin-1); !errors.Is(err, ErrLength) {
		t.Fatalf("short: %v", err)
	}
	if _, err := Seal(p, key, Request{Time: now, Scope: make([]uint16, MaxScope+1)}, nil, p.LenMax); err == nil {
		t.Fatal("scope over limit accepted")
	}
	pkt, err := Seal(p, key, Request{Time: now, Scope: make([]uint16, MaxScope)}, nil, MinPacketLen+11)
	if err != nil || len(pkt) != MinPacketLen+11 {
		t.Fatalf("len %d, err %v", len(pkt), err)
	}
}

func TestRandomParams(t *testing.T) {
	seen := map[uint16]bool{}
	for range 20 {
		p, err := RandomParams(nil)
		if err != nil {
			t.Fatal(err)
		}
		seen[p.PortBase] = true
		for _, port := range p.ActivePorts(time.Now()) {
			if port < p.PortBase || int(port) >= int(p.PortBase)+int(p.PortRange) {
				t.Fatalf("port %d outside %d+%d", port, p.PortBase, p.PortRange)
			}
		}
	}
	if len(seen) < 10 {
		t.Fatalf("only %d distinct port bases in 20 installs", len(seen))
	}
}

func TestActivePorts(t *testing.T) {
	p := testParams()
	now := time.Unix(1767225600, 0)
	ports := p.ActivePorts(now)
	s := p.Slot(now)
	if !slices.Contains(ports, p.Port(s-1)) || !slices.Contains(ports, p.Port(s)) || !slices.Contains(ports, p.Port(s+1)) {
		t.Fatalf("ports %v miss a neighbour slot", ports)
	}
}
