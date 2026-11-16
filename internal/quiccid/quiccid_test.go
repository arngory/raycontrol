package quiccid

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/arngory/raycontrol/internal/quiccid/cidkey"
)

// Speck64/128's vector from the paper (Beaulieu et al., "The SIMON and
// SPECK Families of Lightweight Block Ciphers", appendix C), words as
// printed there.
func TestSpeckVector(t *testing.T) {
	key, _ := hex.DecodeString("1b1a1918131211100b0a090803020100")
	c := newSpeck(key)
	x, y := c.encrypt(0x3b726574, 0x7475432d)
	if x != 0x8c6fa548 || y != 0x454e028b {
		t.Fatalf("Speck64/128: %08x %08x, want 8c6fa548 454e028b", x, y)
	}
	if x, y = c.decrypt(x, y); x != 0x3b726574 || y != 0x7475432d {
		t.Fatalf("decrypt: %08x %08x", x, y)
	}
}

// labelKey is a label's key under a secret of one byte repeated.
func labelKey(t testing.TB, b byte, label int) []byte {
	t.Helper()
	k, err := cidkey.LabelKey(bytes.Repeat([]byte{b}, cidkey.SecretLen), label)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The spec's example (quic-cid-route-v1 §8), which niko-server's front
// checks too: the same secret, label and counter give the same ID.
func TestExample(t *testing.T) {
	secret, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	key, err := cidkey.LabelKey(secret, 0x0102)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	id := c.Encode(0x0102, 0x030405060708)
	if got := hex.EncodeToString(id[:]); got != "0243e188ccdc1084" {
		t.Fatalf("ID %s, want 0243e188ccdc1084", got)
	}
	if label, ok := c.Label(id[:]); !ok || label != 0x0102 {
		t.Fatalf("label %#x %v", label, ok)
	}
	if _, err := NewCodec(secret); err == nil {
		t.Fatal("the node's secret taken for a label's key")
	}
}

// Each label has its own key: its IDs read as its label under that key
// only, not under another label's of the node, nor another node's.
func TestGenerator(t *testing.T) {
	for _, label := range []int{1, 2, 300, MaxLabel} {
		key := labelKey(t, 7, label)
		g, err := NewGenerator(key, label)
		if err != nil {
			t.Fatal(err)
		}
		if g.ConnectionIDLen() != Len {
			t.Fatal(g.ConnectionIDLen())
		}
		c, _ := NewCodec(key)
		neighbour, _ := NewCodec(labelKey(t, 7, label%MaxLabel+1))
		other, _ := NewCodec(labelKey(t, 8, label))
		seen := map[string]bool{}
		for range 1000 {
			id, err := g.GenerateConnectionID()
			if err != nil || id.Len() != Len {
				t.Fatalf("%v %v", id, err)
			}
			if seen[string(id.Bytes())] {
				t.Fatalf("label %d: %v twice", label, id)
			}
			seen[string(id.Bytes())] = true
			if got, ok := c.Label(id.Bytes()); !ok || int(got) != label {
				t.Fatalf("label %d read as %d %v", label, got, ok)
			}
			for _, k := range []*Codec{neighbour, other} {
				if got, ok := k.Label(id.Bytes()); ok && (int(got) == label || int(got) == label%MaxLabel+1) {
					t.Fatalf("another key reads label %d", got)
				}
			}
		}
	}
	key := labelKey(t, 7, 9)
	for _, label := range []int{0, -1, MaxLabel + 1} {
		if _, err := NewGenerator(key, label); err == nil {
			t.Errorf("label %d", label)
		}
	}
	if _, err := NewGenerator(key[:8], 1); err == nil {
		t.Error("a short key")
	}
	// The counter wraps within its 40 bits.
	g, _ := NewGenerator(key, 9)
	c, _ := NewCodec(key)
	g.next.Store(1<<counterBits - 2)
	a, _ := g.GenerateConnectionID()
	b, _ := g.GenerateConnectionID()
	if wa, wb := c.Encode(9, 1<<counterBits-1), c.Encode(9, 0); !bytes.Equal(a.Bytes(), wa[:]) || !bytes.Equal(b.Bytes(), wb[:]) {
		t.Fatal("the counter past 2^40")
	}
}

// An ID the generator will issue, within its window, is ahead; one it
// issued, one of another label or key, and garbage are not.
func TestAhead(t *testing.T) {
	key := labelKey(t, 6, 5)
	g, _ := NewGenerator(key, 5)
	c, _ := NewCodec(key)
	g.next.Store(1<<counterBits - 3) // the window wraps past 2^40
	var issued [][]byte
	for range 3 {
		id, _ := g.GenerateConnectionID()
		issued = append(issued, id.Bytes())
	}
	for _, id := range issued {
		if g.Ahead(id) {
			t.Fatalf("%x issued, read as ahead", id)
		}
	}
	last := g.next.Load()
	const mask = 1<<counterBits - 1
	for _, d := range []uint64{1, 2, 64, aheadWindow} {
		if id := c.Encode(5, (last+d)&mask); !g.Ahead(id[:]) {
			t.Fatalf("counter +%d not ahead", d)
		}
	}
	for _, d := range []uint64{0, aheadWindow + 1, 1 << 39} {
		if id := c.Encode(5, (last+d)&mask); g.Ahead(id[:]) {
			t.Fatalf("counter +%d ahead", d)
		}
	}
	next := c.Encode(5, (last+1)&mask)
	if id, _ := g.GenerateConnectionID(); !bytes.Equal(id.Bytes(), next[:]) || g.Ahead(next[:]) {
		t.Fatal("the next ID, once issued, is still ahead")
	}
	c6, _ := NewCodec(labelKey(t, 6, 6))
	other, _ := NewCodec(labelKey(t, 1, 5))
	for _, id := range [][Len]byte{c6.Encode(6, last+2), other.Encode(5, last+2), {1, 2, 3}} {
		if g.Ahead(id[:]) {
			t.Fatalf("%x: ahead", id)
		}
	}
	if g.Ahead([]byte{1, 2, 3}) {
		t.Fatal("3 bytes")
	}
}

// Random IDs read as a given label about 2^-24 of the time.
func TestRandomMiss(t *testing.T) {
	c, _ := NewCodec(labelKey(t, 1, 5))
	r := rand.New(rand.NewPCG(1, 2))
	var id [Len]byte
	hits := 0
	for range 1 << 20 {
		binary.BigEndian.PutUint64(id[:], r.Uint64())
		if label, ok := c.Label(id[:]); ok && label == 5 {
			hits++
		}
	}
	if hits > 2 {
		t.Fatalf("%d random IDs of 2^20 read as label 5", hits)
	}
	if _, ok := c.Label(id[:7]); ok {
		t.Fatal("7 bytes")
	}
}

func FuzzCodec(f *testing.F) {
	f.Add(uint16(1), uint64(0), uint32(0), uint32(0))
	c, _ := NewCodec(labelKey(f, 5, 1))
	f.Fuzz(func(t *testing.T, label uint16, counter uint64, x, y uint32) {
		id := c.Encode(label, counter)
		if got, ok := c.Label(id[:]); got != label || ok != (label != 0) {
			t.Fatalf("label %d read as %d %v", label, got, ok)
		}
		if a, b := c.decrypt(c.encrypt(x, y)); a != x || b != y {
			t.Fatal("decrypt(encrypt)")
		}
	})
}

func TestReadLabelled(t *testing.T) {
	dir := t.TempDir()
	key := labelKey(t, 6, 4242)
	h := hex.EncodeToString(key)
	good := filepath.Join(dir, "good")
	_ = os.WriteFile(good, []byte("4242 "+h+"\n"), 0o600)
	if label, got, err := ReadLabelled(good); err != nil || label != 4242 || !bytes.Equal(got, key) {
		t.Fatalf("%d %x %v", label, got, err)
	}
	secret := hex.EncodeToString(bytes.Repeat([]byte{6}, cidkey.SecretLen))
	for name, content := range map[string]string{"no label": h, "label 0": "0 " + h, "label 65536": "65536 " + h,
		"not a number": "x " + h, "short key": "1 0102", "the secret": "1 " + secret, "three fields": "1 " + h + " 2", "empty": ""} {
		p := filepath.Join(dir, "bad")
		_ = os.WriteFile(p, []byte(content), 0o600)
		if _, _, err := ReadLabelled(p); err == nil {
			t.Errorf("%s: read", name)
		} else if bytes.Contains([]byte(err.Error()), []byte(h[:16])) || bytes.Contains([]byte(err.Error()), []byte(secret[:16])) {
			t.Errorf("%s: the error tells the key: %v", name, err)
		}
	}
	if _, _, err := ReadLabelled(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing")
	}
}
