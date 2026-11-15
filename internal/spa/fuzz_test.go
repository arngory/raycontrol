package spa

import (
	"encoding/binary"
	"errors"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// FuzzVerify: a packet from anyone (the slot ports are open to all) is
// refused unless a device's key made it, and what one made, whatever its
// plaintext holds, opens no more than the rules say: that device's
// services only, each once, for at most the longest TTL, at a time within
// the skew, in the epoch of its key, once. sealed: the fuzzer's plaintext
// is sealed with a device's key for an epoch about now, so that it gets
// past the AEAD to the parser; else its packet goes as it is.
func FuzzVerify(f *testing.F) {
	now := time.Unix(1767225600, 0)
	p := testParams()
	plain := func(at time.Time, ttl uint16, flags byte, scope ...uint16) []byte {
		pt := make([]byte, 96-NonceSize-TagSize)
		pt[0] = Version
		binary.BigEndian.PutUint64(pt[1:9], uint64(at.Unix()))
		binary.BigEndian.PutUint16(pt[9:11], ttl)
		pt[11], pt[12] = flags, byte(len(scope))
		for i, id := range scope {
			binary.BigEndian.PutUint16(pt[headerSize+2*i:], id)
		}
		return pt
	}
	nonce := make([]byte, NonceSize)
	for _, s := range []struct {
		pt    []byte
		shift int8
	}{
		{plain(now, 0, 0), 0},
		{plain(now, 600, 0, 1, 2, 2, 9), 0},
		{plain(now, 0xffff, 0, 3), 0},
		{plain(now.Add(MaxSkew+time.Second), 0, 0), 0},
		{plain(now, 0, 1), 0},
		{plain(now, 0, 0, slices.Repeat([]uint16{1}, MaxScope)...), 0},
		{plain(now.Add(-24*time.Hour), 0, 0), -1},
		{append([]byte{1}, plain(now, 0, 0)[1:]...), 0},
		{func() []byte { b := plain(now, 0, 0); b[12] = MaxScope + 1; return b }(), 1},
		{plain(now, 0, 0)[:headerSize], 0},
	} {
		f.Add([]byte(nil), s.pt, nonce, s.shift, true)
	}
	pkt, err := Seal(p, fill32(0x11), Request{Time: now, Scope: []uint16{1}}, nonce, 120)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pkt, []byte(nil), []byte(nil), int8(0), false)
	f.Add(pkt[:95], []byte(nil), []byte(nil), int8(0), false)
	f.Add(make([]byte, 160), []byte(nil), []byte(nil), int8(0), false)

	devices := map[string]Device{"a": device("a", 0x11, 1, 2), "b": device("b", 0x12, 3)}
	f.Fuzz(func(t *testing.T, raw, pt, n []byte, shift int8, sealed bool) {
		v := newTestVerifier(now, devices["a"], devices["b"])
		var epoch uint64
		if sealed {
			// Within the packet's bounds: 96 to 160 bytes, 56 to 120 of
			// plaintext.
			if len(pt) < p.LenMin-NonceSize-TagSize {
				pt = append(pt, make([]byte, p.LenMin-NonceSize-TagSize-len(pt))...)
			}
			pt = pt[:min(len(pt), p.LenMax-NonceSize-TagSize)]
			epoch = p.Epoch(now) + uint64(int64(shift%2)) //nolint:gosec // G115: -1, 0 or 1 around now
			key := EpochKey(fill32(0x11), p.NodeID, epoch)
			aead, err := chacha20poly1305.NewX(key[:])
			if err != nil {
				t.Fatal(err)
			}
			var nn [NonceSize]byte
			copy(nn[:], n)
			raw = aead.Seal(nn[:], nn[:], pt, p.aad())
		}
		g, err := v.Verify(raw)
		if err != nil {
			if sealed && errors.Is(err, ErrAuth) {
				t.Fatalf("a packet of a device's key refused as not authentic")
			}
			return
		}
		d, ok := devices[g.DeviceID]
		switch {
		case !ok:
			t.Fatalf("grant to %q", g.DeviceID)
		case len(g.Scope) == 0:
			t.Fatal("a grant of nothing")
		case g.TTL <= 0 || g.TTL > time.Hour:
			t.Fatalf("a grant for %v", g.TTL)
		}
		for i, id := range g.Scope {
			if !slices.Contains(d.Allowed, id) || slices.Contains(g.Scope[:i], id) {
				t.Fatalf("%s granted %v, allowed %v", g.DeviceID, g.Scope, d.Allowed)
			}
		}
		if sealed {
			at := time.Unix(int64(binary.BigEndian.Uint64(pt[1:9])), 0) //nolint:gosec // G115: as the verifier reads it
			if g.DeviceID != "a" || pt[0] != Version || pt[11] != 0 || p.Epoch(at) != epoch || at.Sub(now).Abs() > MaxSkew {
				t.Fatalf("plaintext %x of epoch %d taken: %+v", pt, epoch, g)
			}
			if n := int(pt[12]); n > MaxScope || headerSize+2*n > len(pt) {
				t.Fatalf("plaintext %x of %d services taken", pt, n)
			}
		}
		if _, err := v.Verify(raw); !errors.Is(err, ErrReplay) {
			t.Fatalf("a packet taken twice: %v", err)
		}
	})
}
