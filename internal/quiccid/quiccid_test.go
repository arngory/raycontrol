package quiccid

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
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

// The spec's example (quic-cid-route-v1 §8), which niko-server's front
// checks too: the same secret, label and counter give the same ID.
func TestExample(t *testing.T) {
	secret, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	c, err := NewCodec(secret)
	if err != nil {
		t.Fatal(err)
	}
	id := c.Encode(0x0102, 0x030405060708)
	if got := hex.EncodeToString(id[:]); got != "61224892a4254ad8" {
		t.Fatalf("ID %s, want 61224892a4254ad8", got)
	}
	if label, ok := c.Label(id[:]); !ok || label != 0x0102 {
		t.Fatalf("label %#x %v", label, ok)
	}
}

func TestGenerator(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, SecretLen)
	c, _ := NewCodec(secret)
	other, _ := NewCodec(bytes.Repeat([]byte{8}, SecretLen))
	for _, label := range []int{1, 2, 300, MaxLabel} {
		g, err := NewGenerator(secret, label)
		if err != nil {
			t.Fatal(err)
		}
		if g.ConnectionIDLen() != Len {
			t.Fatal(g.ConnectionIDLen())
		}
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
			if got, ok := other.Label(id.Bytes()); ok && int(got) == label {
				t.Fatalf("another node's key reads label %d", got)
			}
		}
	}
	for _, label := range []int{0, -1, MaxLabel + 1} {
		if _, err := NewGenerator(secret, label); err == nil {
			t.Errorf("label %d", label)
		}
	}
	if _, err := NewGenerator(secret[:16], 1); err == nil {
		t.Error("a short secret")
	}
	// The counter wraps within its 40 bits.
	g, _ := NewGenerator(secret, 9)
	g.next.Store(1<<counterBits - 2)
	a, _ := g.GenerateConnectionID()
	b, _ := g.GenerateConnectionID()
	if wa, wb := c.Encode(9, 1<<counterBits-1), c.Encode(9, 0); !bytes.Equal(a.Bytes(), wa[:]) || !bytes.Equal(b.Bytes(), wb[:]) {
		t.Fatal("the counter past 2^40")
	}
}

// Random IDs read as a given label about 2^-24 of the time.
func TestRandomMiss(t *testing.T) {
	c, _ := NewCodec(bytes.Repeat([]byte{1}, SecretLen))
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

func TestReadSecret(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	want := bytes.Repeat([]byte{3}, SecretLen)
	_ = os.WriteFile(good, []byte(" "+hex.EncodeToString(want)+"\n"), 0o600)
	if got, err := ReadSecret(good); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%x %v", got, err)
	}
	for name, content := range map[string]string{"short": "0102", "not hex": "zz", "empty": "", "long": hex.EncodeToString(bytes.Repeat(want, 2))} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(content), 0o600)
		if _, err := ReadSecret(p); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if _, err := ReadSecret(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing")
	}
}

func FuzzCodec(f *testing.F) {
	f.Add(uint16(1), uint64(0), uint32(0), uint32(0))
	c, _ := NewCodec(bytes.Repeat([]byte{5}, SecretLen))
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
	secret := bytes.Repeat([]byte{6}, SecretLen)
	h := hex.EncodeToString(secret)
	good := filepath.Join(dir, "good")
	_ = os.WriteFile(good, []byte("4242 "+h+"\n"), 0o600)
	if label, got, err := ReadLabelled(good); err != nil || label != 4242 || !bytes.Equal(got, secret) {
		t.Fatalf("%d %x %v", label, got, err)
	}
	for name, content := range map[string]string{"no label": h, "label 0": "0 " + h, "label 65536": "65536 " + h,
		"not a number": "x " + h, "short secret": "1 0102", "three fields": "1 " + h + " 2", "empty": ""} {
		p := filepath.Join(dir, "bad")
		_ = os.WriteFile(p, []byte(content), 0o600)
		if _, _, err := ReadLabelled(p); err == nil {
			t.Errorf("%s: read", name)
		} else if bytes.Contains([]byte(err.Error()), []byte(h[:16])) {
			t.Errorf("%s: the error tells the secret: %v", name, err)
		}
	}
	if _, _, err := ReadLabelled(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing")
	}
}
