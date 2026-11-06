package dnscheck

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// The spec's example (docs/spec/dnsseal-v1.md §9).
func TestSealVectors(t *testing.T) {
	k := seq(0, 32)
	inner := append(seq(0xc0, 8), 0x01, 0xff)
	query := sealQuery(k, [8]byte(seq(0xa0, 8)), inner)
	if got := hex.EncodeToString(query); got != "a0a1a2a3a4a5a6a70c56c1a39145fd1ffc3688be16c2" {
		t.Fatalf("query %s", got)
	}
	// The tests' node opens it.
	if got, ok := specOpenQuery(k, query); !ok || !bytes.Equal(got, inner) {
		t.Fatalf("the node opens %x %v", got, ok)
	}
	answer, _ := hex.DecodeString("b0b1b2b3b4b5b6b7d119c872f77002e5cc82e741ca69b3f568b5facff046fa764c1646d7395735e3f34ca5e0f2082aeae570f04304a4571256c325042f0d9dd5")
	plain, err := openAnswer(k, answer)
	if err != nil || !bytes.Equal(plain, append([]byte{0, 2, 0xaa, 0xbb}, make([]byte, 48)...)) {
		t.Fatalf("answer %x %v", plain, err)
	}
	// And the tests' node seals the same.
	if got := specSealAnswer(k, []byte{0, 2, 0xaa, 0xbb}, 1000, seq(0xb0, 8)); !bytes.Equal(got, answer) {
		t.Fatalf("the node seals %x", got)
	}
	// A poll that opens to this answer reads its one packet.
	if n, err := (Poll{Sealed: true, key: k}).Open(answer); err != nil || n != 1 {
		t.Fatalf("frames %d %v", n, err)
	}
	// The tag covers every byte: R, T and C.
	for _, i := range []int{0, 8, 12, 63} {
		bad := append([]byte(nil), answer...)
		bad[i] ^= 0x20
		if _, err := openAnswer(k, bad); !errors.Is(err, errSealTag) {
			t.Fatalf("byte %d changed: %v", i, err)
		}
	}
	if _, err := openAnswer(seq(1, 32), answer); !errors.Is(err, errSealTag) {
		t.Fatalf("another key: %v", err)
	}
}

// Polls as dnstt and dnsseal-v1 build them, opened by the tests' node,
// and their answers back.
func TestPoll(t *testing.T) {
	zone := "t3x.example.com"
	labels := func(p Poll) []string {
		rest, ok := strings.CutSuffix(p.Name, "."+zone)
		if !ok {
			t.Fatalf("name %s", p.Name)
		}
		return strings.Split(rest, ".")
	}
	payload := func(p Poll) []byte {
		b, err := base32NoPad.DecodeString(strings.ToUpper(strings.Join(labels(p), "")))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	now := time.Unix(1_800_000_000, 0)

	// Open: ClientID, then 8 bytes of padding: 17 bytes, 28 characters.
	p, err := NewPoll(zone, nil, nil, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if l := labels(p); len(l) != 1 || len(l[0]) != 28 || strings.ToLower(l[0]) != l[0] {
		t.Fatalf("open poll %s", p.Name)
	}
	if b := payload(p); b[8] != 0xe8 {
		t.Fatalf("open poll's padding %x", b)
	}
	if n, err := p.Open(nil); err != nil || n != 0 {
		t.Fatalf("an empty answer: %d %v", n, err)
	}
	if n, err := p.Open([]byte{0, 2, 1, 2, 0, 1, 9}); err != nil || n != 2 {
		t.Fatalf("two packets: %d %v", n, err)
	}
	if _, err := p.Open([]byte{0, 9, 1}); err == nil {
		t.Fatal("a cut packet parsed")
	}

	// With a device's tag (dnsauth-v1 §3): 25 bytes, 40 characters.
	authKey := seq(0x60, 32)
	p, err = NewPoll(zone, nil, authKey, false, now)
	if err != nil {
		t.Fatal(err)
	}
	b := payload(p)
	if len(b) != 25 || len(labels(p)[0]) != 40 {
		t.Fatalf("tagged poll %s", p.Name)
	}
	epoch := binary.BigEndian.AppendUint32(nil, uint32(now.Unix()/600))
	if want := mac(authKey, []byte("dnsauth1"), epoch, b[8:])[:8]; !bytes.Equal(b[:8], want) {
		t.Fatalf("tag %x, want %x", b[:8], want)
	}

	// dnsauth-v2 (spec/dnsauth-v2.md §6): the vectors, then a poll with
	// the field: hint and tag over the rest.
	vk, _ := hex.DecodeString("0b485b425e8b19e0ec7c0362d55fdc34338147f984b87ee005455c8f5fc68b1c")
	vmsg := seq(0, 24)
	for _, c := range []struct {
		epoch uint32
		field string
	}{{2945448, "2d82b1220002a927"}} {
		if got := hex.EncodeToString(authTag2(vk, c.epoch, vmsg)); got != c.field {
			t.Fatalf("dnsauth-v2 field %s, want %s", got, c.field)
		}
	}
	for e, hint := range map[uint32]string{2945447: "a5f9", 2945449: "e97f"} {
		if got := hex.EncodeToString(authTag2(vk, e, vmsg)[:2]); got != hint {
			t.Fatalf("hint at %d: %s, want %s", e, got, hint)
		}
	}
	p, err = NewPoll(zone, nil, authKey, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if b := payload(p); len(b) != 25 || !bytes.Equal(b[:8], authTag2(authKey, uint32(now.Unix()/600), b[8:])) {
		t.Fatalf("a v2 tagged poll %x", b)
	}

	// Sealed: N, T and C, labels of 32 to 63 characters; the node opens
	// it and answers sealed.
	sealKey := seq(0x40, 32)
	for range 20 {
		p, err = NewPoll(zone, sealKey, authKey, false, now)
		if err != nil {
			t.Fatal(err)
		}
		ls := labels(p)
		for i, l := range ls {
			if len(l) > 63 || (i < len(ls)-1 && len(l) < 32) {
				t.Fatalf("label of %d characters in %s", len(l), p.Name)
			}
		}
		inner, ok := specOpenQuery(sealKey, payload(p))
		if !ok || len(inner) < 8+8+1 || inner[16] < 0xe0 || len(inner) != 17+int(inner[16]-0xe0) {
			t.Fatalf("sealed poll opens to %x %v", inner, ok)
		}
		data := specSealAnswer(sealKey, nil, 934, nil)
		if len(data) != 64 {
			t.Fatalf("sealed answer of %d bytes", len(data))
		}
		if n, err := p.Open(data); err != nil || n != 0 {
			t.Fatalf("sealed answer: %d %v", n, err)
		}
		if _, err := p.Open(specSealAnswer(seq(1, 32), nil, 934, nil)); !errors.Is(err, errSealTag) {
			t.Fatalf("answer under another key: %v", err)
		}
	}
	if _, ok := specOpenQuery(seq(1, 32), payload(p)); ok {
		t.Fatal("another key opened the poll")
	}
}
