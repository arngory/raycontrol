package redact

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"
)

// fuzzRedactor is a Redactor with a fixed salt: a fuzz target's runs are
// the same each time.
func fuzzRedactor(names ...string) *Redactor {
	r := New(names...)
	r.salt = []byte("raycontrol-fuzz!")
	return r
}

// seps are what stands between an address and the text around it in the
// node's lines: the address is a word of its own.
var seps = []string{" ", "\n", "\t", "=", ",", ";", "(", ")", "[", "]", "<", ">", "\"", "'", "/", "@", "|", "!", "?", "*", "#", "{", "}", "→"}

// written is address a as text puts it, by form: IPv4 plain, with leading
// zeros, embedded in IPv6, mapped, with a port, mapped in hex; IPv6
// compressed, written out, ending in "::", with a zone, bracketed with a
// port, glued to a word by a colon, in capitals, a prefix, before a colon
// and a word, with a port and no brackets. It also says which address the
// text holds, as a reader takes it (the IPv4 one of an embedded or mapped
// form), whose token the text gets but in the embedded form (the NAT64
// address's).
func written(a4 [4]byte, a16 [16]byte, form uint8) (text string, addr netip.Addr) {
	v4 := netip.AddrFrom4(a4)
	v6 := netip.AddrFrom16(a16)
	switch form % 16 {
	case 0:
		return v4.String(), v4
	case 1:
		return fmt.Sprintf("%03d.%d.%02d.%03d", a4[0], a4[1], a4[2], a4[3]), v4
	case 2:
		return "64:ff9b::" + v4.String(), v4
	case 3:
		return "::ffff:" + v4.String(), v4
	case 4:
		return v4.String() + ":443", v4
	case 5:
		return netip.AddrFrom16(netip.AddrFrom4(a4).As16()).StringExpanded(), v4
	case 6:
		return v6.String(), v6
	case 7:
		return v6.StringExpanded(), v6
	case 8:
		// Its last groups zero: "2001:db8::".
		for i := 8 + int(a16[15]%8); i < 16; i++ {
			a16[i] = 0
		}
		v6 = netip.AddrFrom16(a16)
		return v6.String(), v6
	case 9:
		a16[0], a16[1] = 0xfe, 0x80
		v6 = netip.AddrFrom16(a16)
		return v6.String() + "%eth0", v6
	case 10:
		return "[" + v6.String() + "]:443", v6
	case 11:
		return "ipv6:" + v6.String(), v6
	case 12:
		return strings.ToUpper(v6.String()), v6
	case 13:
		return netip.PrefixFrom(v6, 48).Masked().String(), netip.PrefixFrom(v6, 48).Masked().Addr()
	case 14:
		return v6.String() + ": refused", v6
	default:
		return v6.StringExpanded() + ":443", v6
	}
}

// addrsIn are the addresses s holds in any substring that parses as one,
// as parseAddr reads it (leading zeros too), unmapped and without zone.
func addrsIn(s string) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	isAddrByte := func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == ':' || c == '.'
	}
	for i := 0; i < len(s); {
		if !isAddrByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isAddrByte(s[j]) {
			j++
		}
		run := s[i:j]
		for a := 0; a < len(run); a++ {
			for b := a + 1; b <= len(run) && b-a <= 45; b++ {
				if ad, ok := parseAddr(run[a:b]); ok {
					out[ad.WithZone("").Unmap()] = true
				}
			}
		}
		i = j
	}
	return out
}

// glue glues text t of written's form to a word or a number, as the form's
// high bits say: on its left (16), on its right (32), with a letter, a
// digit, an underscore or a hex digit (64, 128). On the left only of an
// IPv4 address, or of an IPv6 one that starts with a whole group and has
// two at least (at): "Cafe::new" and "io::Error" are none.
func glue(t string, form uint8) (string, bool) {
	c := string("q7_C"[form>>6])
	glued := false
	left := false
	switch form % 16 {
	case 0, 1, 4, 5, 7, 15:
		left = true
	case 6, 12:
		left = len(t) > 4 && t[4] == ':' && isHex(t[0]) && isHex(t[1]) && isHex(t[2]) && isHex(t[3]) && groups(t) >= 2
	}
	if form&16 != 0 && left {
		t, glued = c+t, true
	}
	if form&32 != 0 {
		t, glued = t+c, true
	}
	return t, glued
}

// FuzzRedact: a report's text with two addresses in it, each in one of
// the forms of written, a word of its own between the fuzzer's text
// (without what an address is made of) or glued to a word or a number on
// either side (glue), keeps neither in any form a reader parses back to
// the same address (loopback and unspecified ones, which say nothing,
// aside), and has the token of each not glued, the same whatever its form.
// Any text: a second redaction changes nothing (what the first left is not
// one), none makes it panic, and text that is UTF-8 stays so.
func FuzzRedact(f *testing.F) {
	for _, s := range []struct {
		pre, mid, post string
		a4             [4]byte
		a16            string
		f1, f2, s1, s2 uint8
	}{
		{"spa granted src", " device ", " ok", [4]byte{198, 51, 100, 23}, "2001:db8::42", 0, 6, 1, 0},
		{"dial tcp", "refused; via", "", [4]byte{203, 0, 113, 5}, "2001:db8:1:2:3:4:5:6", 1, 15, 0, 0},
		{"nat64", "and", "up", [4]byte{198, 51, 100, 9}, "fe80::a9fe:a9fe", 2, 9, 0, 0},
		{"from", "", "", [4]byte{10, 1, 2, 3}, "2001:db8::5", 3, 14, 0, 24},
		{"admin addresses", "sshd at", "", [4]byte{198, 51, 100, 7}, "2001:db8:1::", 4, 13, 9, 0},
		{"peer", "src", "x", [4]byte{192, 0, 2, 1}, "2001:db8::9", 5, 10, 1, 1},
		{"lo", "any", "", [4]byte{127, 0, 0, 1}, "::1", 0, 11, 0, 0},
		{"", "", "", [4]byte{0, 0, 0, 0}, "::", 1, 12, 0, 0},
		{"\xff\xfe", "\x00", "é", [4]byte{100, 64, 0, 1}, "64:ff9b::c633:6409", 8, 7, 2, 3},
		{"host", "via", "up", [4]byte{203, 0, 113, 5}, "2001:db8::1", 0 | 16 | 32, 6 | 16 | 32 | 64, 0, 0},
		{"addr", "and", "x", [4]byte{198, 51, 100, 25}, "2001:db8:1:2:3:4:5:6", 1 | 16 | 32 | 128, 7 | 16 | 32 | 192, 1, 1},
		{"src", "dst", "", [4]byte{192, 0, 2, 1}, "2001:db8::", 4 | 16 | 64, 8 | 32 | 128, 0, 0},
	} {
		a := netip.MustParseAddr(s.a16).As16()
		f.Add(s.pre, s.mid, s.post, s.a4[:], a[:], s.f1, s.f2, s.s1, s.s2, "")
	}
	f.Add("", "", "", []byte{1, 2, 3, 4}, make([]byte, 16), uint8(0), uint8(0), uint8(0), uint8(0),
		"from 2001:db8::5: refused; 2001:db8:1:2:3:4:5:6: no; dial 203.0.113.05:443; via 198.051.100.007 and 64:ff9b::198.51.100.09; "+
			"vless://6f1c2a3b-0000-4000-8000-000000000007@203.0.113.7:443?security=reality#r rcdev1:eyJ2IjoxfQ k3f.node.example.org")
	f.Add("", "", "", []byte{1, 2, 3, 4}, make([]byte, 16), uint8(0), uint8(0), uint8(0), uint8(0),
		"1.2.3.4.5.6.7.8 999.1.2.3.4 a1.2.3.4 1:2:3:4:5:6:7:8:9 std::io::Error ::ffff:1.2.3.4:5 [::1]:80 aa:bb:cc:dd:ee:ff 12:30:45:")
	f.Add("", "", "", []byte{1, 2, 3, 4}, make([]byte, 16), uint8(0), uint8(0), uint8(0), uint8(0),
		"host203.0.113.5 203.0.113.5203.0.113.6 eth0fe80::1 2001:db8::1x 2001:db8::1203.0.113.5 v1.2.3.4 Cafe::new g::2x 0203.0.113.0005")
	f.Fuzz(func(t *testing.T, pre, mid, post string, a4, a16 []byte, f1, f2, s1, s2 uint8, free string) {
		r := fuzzRedactor("node.example.org")
		// Any text: no panic, the same after a second pass, UTF-8 kept.
		once := r.String(free)
		if twice := r.String(once); twice != once {
			t.Fatalf("not idempotent:\n in %q\nonce %q\ntwice %q", free, once, twice)
		}
		if utf8.ValidString(free) && !utf8.ValidString(once) {
			t.Fatalf("%q redacted to %q", free, once)
		}

		// Addresses in text around them: none is left.
		if len(a4) < 4 || len(a16) < 16 {
			return
		}
		plain := func(s string) string {
			return strings.Map(func(c rune) rune {
				if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == ':' || c == '.' || c == '%' {
					return -1
				}
				return c
			}, s)
		}
		t1, x1 := written([4]byte(a4), [16]byte(a16), f1)
		t2, x2 := written([4]byte(a4), [16]byte(a16), f2)
		t1, g1 := glue(t1, f1)
		t2, g2 := glue(t2, f2)
		in := plain(pre) + seps[int(s1)%len(seps)] + t1 + seps[int(s1/32+1)%len(seps)] + plain(mid) + seps[int(s2)%len(seps)] + t2 +
			seps[int(s2/32+1)%len(seps)] + plain(post)
		out := r.String(in)
		left := addrsIn(out)
		for i, x := range []netip.Addr{x1, x2} {
			x = x.WithZone("").Unmap()
			if x.IsLoopback() || x.IsUnspecified() {
				continue
			}
			if left[x] {
				t.Fatalf("%v left:\n in %q\nout %q", x, in, out)
			}
			// The same address, the same token, whatever its form; glued,
			// the glue may be read as part of it (203.0.113.5 and 7).
			if form := []uint8{f1, f2}[i] % 16; form != 2 && ![]bool{g1, g2}[i] && !strings.Contains(out, r.token(x, "")) {
				t.Fatalf("%v (form %d) without its token %s:\n in %q\nout %q", x, form, r.token(x, ""), in, out)
			}
		}
		if twice := r.String(out); twice != out {
			t.Fatalf("not idempotent:\n in %q\nonce %q\ntwice %q", in, out, twice)
		}
	})
}
