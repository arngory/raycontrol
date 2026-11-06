package dnscheck

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// The spec's example (docs/spec/dnsprobe-v1.md §7).
func TestProbeVectors(t *testing.T) {
	key := seq(0, 32)
	p := probeAt(key, "t.example.com", false, 29000000, [8]byte(seq(0xa0, 8)))
	if got := p.Label(); got != "aeaadoubicqkdivduss2nj2inuqqx7vwla4ifvi" {
		t.Fatalf("label %s", got)
	}
	// The zone's case and final dot do not change the MAC.
	if q := probeAt(key, "T.Example.com.", false, 29000000, [8]byte(seq(0xa0, 8))); q.Label() != p.Label() {
		t.Fatalf("label of the zone as typed: %s", q.Label())
	}
	data, _ := hex.DecodeString("b0b1b2b3b4b5b6b708ef7fc6424b785eb4b2e7c0d6b7839339c69f34cd0f9e0484c8f8e7ff8479a7990d11")
	want := ProbeAnswer{EDNS: 1232, Mixed: true, Egress: netip.MustParseAddr("198.51.100.7")}
	if a, err := p.Open(key, data); err != nil || a != want {
		t.Fatalf("answer %+v %v", a, err)
	}
	// Padded as a sealed zone pads it (dnsseal-v1 §6): 64 bytes, the rest
	// not looked at.
	padded := append(append([]byte(nil), data...), bytes.Repeat([]byte{0x5a}, 64-len(data))...)
	if a, err := p.Open(key, padded); err != nil || a != want {
		t.Fatalf("padded answer %+v %v", a, err)
	}
	// Another key, a changed byte, a short answer: no.
	if _, err := p.Open(seq(1, 32), data); !errors.Is(err, errProbeToken) {
		t.Fatalf("another key: %v", err)
	}
	bad := append([]byte(nil), data...)
	bad[30] ^= 1
	if _, err := p.Open(key, bad); err == nil {
		t.Fatal("a changed byte opened")
	}
	if _, err := p.Open(key, data[:42]); err == nil {
		t.Fatal("42 bytes opened")
	}
	// The emulated front makes the same answer: the tests' node agrees
	// with the spec.
	plain := make([]byte, 35)
	plain[16], plain[17], plain[18] = 0x04, 0xd0, 1
	a16 := netip.MustParseAddr("198.51.100.7").As16() // ::ffff:198.51.100.7
	copy(plain[19:], a16[:])
	tok := mac(key, []byte("dnsprobe-v1 a"), p.b[:], plain[16:35])
	copy(plain, tok[:16])
	specProbeCrypt(mac(key, []byte("dnsprobe-v1 e")), p.b[:], seq(0xb0, 8), plain)
	if got := append(seq(0xb0, 8), plain...); !bytes.Equal(got, data) {
		t.Fatalf("the front's answer %x", got)
	}
}

// A large probe: the 900-byte answer, padded or not; a small answer to it
// when the resolver advertised too little; zeros required after the token.
func TestProbeLarge(t *testing.T) {
	key := seq(0, 32)
	f := &front{key: key, now: time.Now, zones: map[string]*frontZone{"t.example.com": {kind: "dnstt", probe: true, sealPad: true}}}
	answer := func(p Probe, edns int) []byte {
		t.Helper()
		q, err := newQuery(p.Label()+".t.example.com", 16, true)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := readQuery(q)
		info.edns = edns
		r, ok := f.probe(q, info, "t.example.com", f.zones["t.example.com"], netip.MustParseAddr("192.0.2.7"))
		if !ok {
			t.Fatal("not a probe")
		}
		x, err := parseReply(q, r)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := x.txt(p.Label() + ".t.example.com")
		return data
	}
	p, err := NewProbe(key, "t.example.com", true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data := answer(p, 1232)
	if len(data) != 934 { // padded to the room at 1232
		t.Fatalf("large answer of %d bytes", len(data))
	}
	if a, err := p.Open(key, data); err != nil || !a.Large || a.EDNS != 1232 || a.Egress != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("large %+v %v", a, err)
	}
	small := answer(p, 1024)
	if len(small) != 64 {
		t.Fatalf("small answer of %d bytes", len(small))
	}
	if a, err := p.Open(key, small); err != nil || a.Large || a.EDNS != 1024 {
		t.Fatalf("small answer to a large probe %+v %v", a, err)
	}
	// A large answer must be zeros after the token, which covers 16-34 only.
	plain := make([]byte, 900)
	plain[35] = 1
	copy(plain, mac(key, []byte("dnsprobe-v1 a"), p.b[:], plain[16:35])[:16])
	probeCrypt(mac(key, []byte("dnsprobe-v1 e")), p.b[:], seq(0xb0, 8), plain)
	if _, err := p.Open(key, append(seq(0xb0, 8), plain...)); err == nil {
		t.Fatal("a large answer with a byte set after the token opened")
	}
}
