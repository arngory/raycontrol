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
		// Both clocks a minute on: the nonce is forgotten, its packet stale.
		v.now = func() time.Time { return now.Add(2*MaxSkew + time.Second) }
		v.since = func() time.Duration { return knockWindow + time.Second }
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

// One device's knocks count against its quota for a minute: past it that
// device is refused, others pass, and its quota frees as its knocks age.
// Knocks refused for their scope count as well.
func TestDeviceQuota(t *testing.T) {
	now := time.Unix(1767225600, 0)
	clock, mono := now, time.Duration(0)
	v := NewVerifier(testParams(), 10*time.Minute, time.Hour, 100000)
	v.now = func() time.Time { return clock }
	v.since = func() time.Duration { return mono }
	v.SetDevices([]Device{device("a", 0x11, 1), device("b", 0x22, 1)})
	for i := range DeviceNonces {
		// Half of them for a service the device may not open.
		req := Request{Time: clock}
		if i%2 == 1 {
			req.Scope = []uint16{9}
		}
		if _, err := v.Verify(seal(t, 0x11, req)); err != nil && !errors.Is(err, ErrScope) {
			t.Fatalf("knock %d: %v", i, err)
		}
	}
	if g, err := v.Verify(seal(t, 0x11, Request{Time: clock})); !errors.Is(err, ErrQuota) || g.DeviceID != "a" || g.Scope != nil {
		t.Fatalf("over the quota: %+v, err = %v", g, err)
	}
	if _, err := v.Verify(seal(t, 0x22, Request{Time: clock})); err != nil {
		t.Fatalf("another device: %v", err)
	}
	clock, mono = now.Add(knockWindow), knockWindow
	if _, err := v.Verify(seal(t, 0x11, Request{Time: clock})); err != nil {
		t.Fatalf("after its knocks aged: %v", err)
	}
	// b's knock came at the same time: gone with a's, nonces and counts.
	if _, ok := v.perDevice["b"]; len(v.seen) != 1 || v.perDevice["a"] != 1 || ok {
		t.Fatalf("cache: %d nonces, a %d, b %d", len(v.seen), v.perDevice["a"], v.perDevice["b"])
	}
}

// The cache forgets each nonce when its packet can no longer pass the skew
// check, and refuses a replay before then.
func TestReplayCacheOrder(t *testing.T) {
	now := time.Unix(1767225600, 0)
	clock := now
	mono := time.Duration(0)
	v := NewVerifier(testParams(), 10*time.Minute, time.Hour, 3)
	v.now = func() time.Time { return clock }
	v.since = func() time.Duration { return mono }
	v.SetDevices([]Device{device("a", 0x11, 1)})
	first := seal(t, 0x11, Request{Time: clock})
	if _, err := v.Verify(first); err != nil {
		t.Fatal(err)
	}
	clock, mono = now.Add(MaxSkew), MaxSkew
	for range 2 {
		if _, err := v.Verify(seal(t, 0x11, Request{Time: clock})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := v.Verify(first); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: err = %v", err)
	}
	if _, err := v.Verify(seal(t, 0x11, Request{Time: clock})); !errors.Is(err, ErrBusy) {
		t.Fatalf("cache full: err = %v", err)
	}
	// The first one's time passes on both clocks: one place frees, the
	// others stay.
	clock, mono = now.Add(knockWindow), knockWindow
	if _, err := v.Verify(seal(t, 0x11, Request{Time: clock})); err != nil {
		t.Fatalf("after the first expired: %v", err)
	}
	if len(v.seen) != 3 {
		t.Fatalf("cache: %d nonces", len(v.seen))
	}
}

// The wall clock steps back an hour: a packet taken before is still a
// replay when the clock comes back to its time, and the devices' quotas,
// on the monotonic clock, go on as ever (protocol review 2026-11).
func TestReplayCacheClockBack(t *testing.T) {
	now := time.Unix(1767225600, 0)
	clock, mono := now, time.Duration(0)
	v := NewVerifier(testParams(), 10*time.Minute, time.Hour, 100000)
	v.now = func() time.Time { return clock }
	v.since = func() time.Duration { return mono }
	v.SetDevices([]Device{device("a", 0x11, 1)})
	first := seal(t, 0x11, Request{Time: clock})
	if _, err := v.Verify(first); err != nil {
		t.Fatal(err)
	}
	for range DeviceNonces - 1 {
		if _, err := v.Verify(seal(t, 0x11, Request{Time: clock})); err != nil {
			t.Fatal(err)
		}
	}
	clock = now.Add(-time.Hour)
	for i := range 2 * DeviceNonces {
		if i%DeviceNonces == 0 {
			clock, mono = clock.Add(knockWindow), mono+knockWindow // a minute later, a quota again
		}
		if _, err := v.Verify(seal(t, 0x11, Request{Time: clock})); err != nil {
			t.Fatalf("knock %d after the step back: %v", i, err)
		}
	}
	// Back near the first packet's time: within the skew, and a replay.
	clock, mono = now.Add(-20*time.Second), mono+time.Hour
	if _, err := v.Verify(first); !errors.Is(err, ErrReplay) {
		t.Fatalf("the first packet again: err = %v", err)
	}
}

// The wall clock steps forward and back again: a nonce is kept until both
// clocks have passed it, so its packet is a replay throughout (second
// review of the protocol review's change).
func TestReplayCacheClockForwardBack(t *testing.T) {
	now := time.Unix(1767225600, 0)
	clock, mono := now, time.Duration(0)
	v := NewVerifier(testParams(), 10*time.Minute, time.Hour, 100000)
	v.now = func() time.Time { return clock }
	v.since = func() time.Duration { return mono }
	v.SetDevices([]Device{device("a", 0x11, 1), device("b", 0x22, 1)})
	first := seal(t, 0x11, Request{Time: clock})
	if _, err := v.Verify(first); err != nil {
		t.Fatal(err)
	}
	// Two minutes ahead, a second later: another device's knock forgets
	// what has passed.
	clock, mono = now.Add(2*time.Minute), time.Second
	if _, err := v.Verify(seal(t, 0x22, Request{Time: clock})); err != nil {
		t.Fatal(err)
	}
	clock, mono = now.Add(5*time.Second), 2*time.Second
	if _, err := v.Verify(first); !errors.Is(err, ErrReplay) {
		t.Fatalf("back again, within the minute: err = %v", err)
	}
	// Past the minute, the wall clock still before the packet's time is
	// out: kept.
	clock, mono = now.Add(10*time.Second), knockWindow+time.Second
	if _, err := v.Verify(seal(t, 0x22, Request{Time: clock})); err != nil {
		t.Fatal(err)
	}
	if err := v.Precheck(first); !errors.Is(err, ErrReplay) {
		t.Fatalf("past the minute, before its time: err = %v", err)
	}
	// Both passed: forgotten, and its packet is stale.
	clock, mono = now.Add(knockWindow), 2*knockWindow
	if err := v.Precheck(first); err != nil {
		t.Fatalf("both passed: precheck %v", err)
	}
	if _, err := v.Verify(first); !errors.Is(err, ErrStale) {
		t.Fatalf("both passed: err = %v", err)
	}
}

// The wall clock steps back after a nonce is forgotten (third review of
// the protocol review's change): its packet is within the skew again, and
// refused as a replay all the same, as is any as old.
func TestReplayAfterForgottenStepBack(t *testing.T) {
	truth := time.Unix(1767225600, 0)
	clock, mono := truth.Add(2*time.Minute), time.Duration(0) // the node's clock fast
	v := NewVerifier(testParams(), 10*time.Minute, time.Hour, 100000)
	v.now = func() time.Time { return clock }
	v.since = func() time.Duration { return mono }
	v.SetDevices([]Device{device("a", 0x11, 1), device("b", 0x22, 1)})
	first := seal(t, 0x11, Request{Time: clock}) // a client as fast
	if _, err := v.Verify(first); err != nil {
		t.Fatal(err)
	}
	// Both clocks past it: another knock forgets it.
	clock, mono = clock.Add(62*time.Second), 62*time.Second
	if _, err := v.Verify(seal(t, 0x22, Request{Time: clock})); err != nil {
		t.Fatal(err)
	}
	if err := v.Precheck(first); err != nil {
		t.Fatalf("not forgotten: %v", err)
	}
	// NTP steps the clock back to the truth; the packet's time is within
	// the skew again.
	clock, mono = truth.Add(2*time.Minute+10*time.Second), 70*time.Second
	if _, err := v.Verify(first); !errors.Is(err, ErrReplay) || !errors.Is(err, ErrClockBack) {
		t.Fatalf("its packet after the step back: err = %v", err)
	}
	// A new packet of a time after every one forgotten passes.
	if _, err := v.Verify(seal(t, 0x22, Request{Time: clock.Add(20 * time.Second)})); err != nil {
		t.Fatalf("a new packet: %v", err)
	}
}

// VerifyDevices tries only the devices named: another's packet is no
// one's, a name not enrolled is skipped, and a packet of one named passes.
func TestVerifyDevices(t *testing.T) {
	now := time.Unix(1767225600, 0)
	v := newTestVerifier(now, device("a", 0x11, 1), device("b", 0x22, 1))
	pa := seal(t, 0x11, Request{Time: now})
	if _, err := v.VerifyDevices(pa, []string{"b"}); !errors.Is(err, ErrAuth) {
		t.Fatalf("a's packet, b tried: %v", err)
	}
	if _, err := v.VerifyDevices(pa, []string{"gone"}); !errors.Is(err, ErrAuth) {
		t.Fatalf("a's packet, no one enrolled tried: %v", err)
	}
	if _, err := v.VerifyDevices(pa, nil); !errors.Is(err, ErrAuth) {
		t.Fatalf("a's packet, no one tried: %v", err)
	}
	g, err := v.VerifyDevices(pa, []string{"gone", "a"})
	if err != nil || g.DeviceID != "a" {
		t.Fatalf("a's packet, a tried: %+v %v", g, err)
	}
	if _, err := v.VerifyDevices(pa, []string{"a"}); !errors.Is(err, ErrReplay) {
		t.Fatalf("again: %v", err)
	}
}

// TestTTLFloorAndSetTTL: a grant lasts a second at least, whatever the
// node's TTLs (nft takes 0 for no timeout at all: fourth review), and new
// TTLs keep the replay cache.
func TestTTLFloorAndSetTTL(t *testing.T) {
	clock := time.Unix(1767225600, 0)
	v := NewVerifier(testParams(), 0, 0, 1000)
	v.SetClock(func() time.Time { return clock })
	v.SetDevices([]Device{{ID: "a", Key: fill32(0x11), Allowed: []uint16{1}}})
	pkt := seal(t, 0x11, Request{Time: clock})
	g, err := v.Verify(pkt)
	if err != nil || g.TTL != time.Second {
		t.Fatalf("TTLs of 0: %v %v", g.TTL, err)
	}
	v.SetTTL(10*time.Minute, time.Hour)
	if _, err := v.Verify(pkt); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed after new TTLs: %v", err)
	}
	if g, err := v.Verify(seal(t, 0x11, Request{Time: clock})); err != nil || g.TTL != 10*time.Minute {
		t.Fatalf("the new default: %v %v", g.TTL, err)
	}
}
