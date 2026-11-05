package spa

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// parsedHello is a ClientHello as its parts.
type parsedHello struct {
	ciphers []uint16
	exts    []uint16
	data    map[uint16][]byte
}

func parseHello(t *testing.T, raw []byte) parsedHello {
	t.Helper()
	s := cryptobyte.String(raw)
	var rec, msg, sid, ciphers, comp, exts cryptobyte.String
	var typ uint8
	if !s.Skip(3) || !s.ReadUint16LengthPrefixed(&rec) || !rec.ReadUint8(&typ) || typ != 1 ||
		!rec.ReadUint24LengthPrefixed(&msg) || !msg.Skip(2+32) || !msg.ReadUint8LengthPrefixed(&sid) ||
		!msg.ReadUint16LengthPrefixed(&ciphers) || !msg.ReadUint8LengthPrefixed(&comp) || !msg.ReadUint16LengthPrefixed(&exts) ||
		!rec.Empty() || !msg.Empty() || len(sid) != 32 {
		t.Fatal("not a well-formed ClientHello record")
	}
	h := parsedHello{data: map[uint16][]byte{}}
	for !ciphers.Empty() {
		var c uint16
		ciphers.ReadUint16(&c)
		h.ciphers = append(h.ciphers, c)
	}
	for !exts.Empty() {
		var id uint16
		var d cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&d) {
			t.Fatal("bad extension")
		}
		if _, dup := h.data[id]; dup {
			t.Fatalf("extension %04x twice", id)
		}
		h.exts = append(h.exts, id)
		h.data[id] = d
	}
	return h
}

func g16(v uint16) string {
	if isGREASE(v) {
		return "GREASE"
	}
	return fmt.Sprintf("%04x", v)
}

func list16(b []byte, prefix int) []string {
	var out []string
	for i := prefix; i+1 < len(b); i += 2 {
		out = append(out, g16(binary.BigEndian.Uint16(b[i:])))
	}
	return out
}

// shape is what two ClientHellos of one browser share: per-connection
// values (random, session ID, keys, GREASE values, the order of the
// extensions, the ECH payload) left out; the server name and the ticket,
// which the carrier changes on purpose, too.
func (h parsedHello) shape() string {
	var ciphers []string
	for _, c := range h.ciphers {
		ciphers = append(ciphers, g16(c))
	}
	var lines, ids []string
	for _, id := range h.exts {
		if id == extServerName {
			continue
		}
		ids = append(ids, g16(id))
		d := h.data[id]
		var v string
		switch {
		case isGREASE(id):
			v = hex.EncodeToString(d)
		case id == extGroups, id == extSigAlgs:
			v = strings.Join(list16(d, 2), ",")
		case id == extVersions:
			v = strings.Join(list16(d, 1), ",")
		case id == extKeyShare:
			s := cryptobyte.String(d)
			var shares cryptobyte.String
			s.ReadUint16LengthPrefixed(&shares)
			var ks []string
			for !shares.Empty() {
				var g uint16
				var k cryptobyte.String
				shares.ReadUint16(&g)
				shares.ReadUint16LengthPrefixed(&k)
				ks = append(ks, fmt.Sprintf("%s/%d", g16(g), len(k)))
			}
			v = strings.Join(ks, ",")
		case id == extECH:
			v = fmt.Sprintf("GREASE ECH %x", d[:5]) // its length is drawn per connection
		case id == extSessionTicket:
			v = "ticket"
		default:
			v = hex.EncodeToString(d)
		}
		lines = append(lines, g16(id)+" "+v)
	}
	sort.Strings(ids)
	sort.Strings(lines)
	return "ciphers " + strings.Join(ciphers, ",") + "\nextensions " + strings.Join(ids, ",") + "\n" + strings.Join(lines, "\n")
}

// ja4 is the FoxIO JA4 of the hello (TCP; GREASE left out everywhere).
func (h parsedHello) ja4() string {
	var ciphers, exts, sigs []string
	for _, c := range h.ciphers {
		if !isGREASE(c) {
			ciphers = append(ciphers, fmt.Sprintf("%04x", c))
		}
	}
	sni, alpn, n := "i", "00", 0
	for _, id := range h.exts {
		if isGREASE(id) {
			continue
		}
		n++
		switch id {
		case extServerName:
			sni = "d"
		case 0x0010:
			d := h.data[id]
			if len(d) > 3 {
				p := d[3 : 3+int(d[2])]
				alpn = string(p[0]) + string(p[len(p)-1])
			}
		default:
			exts = append(exts, fmt.Sprintf("%04x", id))
		}
	}
	for _, a := range list16(h.data[extSigAlgs], 2) {
		if a != "GREASE" {
			sigs = append(sigs, a)
		}
	}
	sort.Strings(ciphers)
	sort.Strings(exts)
	part := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:])[:12] }
	return fmt.Sprintf("t13%s%02d%02d%s_%s_%s", sni, len(ciphers), n, alpn,
		part(strings.Join(ciphers, ",")), part(strings.Join(exts, ",")+"_"+strings.Join(sigs, ",")))
}

// The carrier is Chrome 156's ClientHello without the server name: the same
// shape as the capture, the JA4 Niko's carrier has, every per-connection
// value new each time, and the packet back out of it.
func TestTLSCarrierLikeChrome(t *testing.T) {
	raw, err := hex.DecodeString(strings.TrimSpace(chromeHelloHex))
	if err != nil {
		t.Fatal(err)
	}
	chrome := parseHello(t, raw)
	if got := chrome.ja4(); got != "t13d1517h2_8daaf6152771_cb7bf5808d99" {
		t.Fatalf("the capture's JA4 %s, Chrome 156's is t13d1517h2_8daaf6152771_cb7bf5808d99", got)
	}
	pkt := make([]byte, 200)
	orders, echLens := map[string]bool{}, map[int]bool{}
	var first parsedHello
	for i := range 40 {
		c, err := TLSCarrier(pkt)
		if err != nil {
			t.Fatal(err)
		}
		h := parseHello(t, c)
		if h.shape() != chrome.shape() {
			t.Fatalf("carrier shape:\n%s\n\nChrome:\n%s", h.shape(), chrome.shape())
		}
		if got := h.ja4(); got != "t13i1516h2_8daaf6152771_cb7bf5808d99" {
			t.Fatalf("carrier JA4 %s", got)
		}
		if out, err := FromTLSCarrier(c); err != nil || len(out) != len(pkt) {
			t.Fatalf("packet back: %d bytes, %v", len(out), err)
		}
		if !isGREASE(h.exts[0]) || !isGREASE(h.exts[len(h.exts)-1]) || h.exts[0] == h.exts[len(h.exts)-1] {
			t.Fatalf("GREASE extensions %04x %04x", h.exts[0], h.exts[len(h.exts)-1])
		}
		orders[fmt.Sprint(h.exts[1:len(h.exts)-1])] = true
		// GREASE ECH as BoringSSL makes it: enc an X25519 key (its top bit
		// clear), the payload 144, 176, 208 or 240 bytes.
		ech := h.data[extECH]
		enc, payload := ech[8:8+32], ech[8+32+2:]
		if binary.BigEndian.Uint16(ech[6:]) != 32 || enc[31]&0x80 != 0 {
			t.Fatalf("GREASE ECH enc %x", enc)
		}
		if n := len(payload); n < 144 || n > 240 || (n-16)%32 != 0 {
			t.Fatalf("GREASE ECH payload of %d bytes", n)
		}
		echLens[len(payload)] = true
		if i == 0 {
			first = h
			continue
		}
		for _, id := range []uint16{extKeyShare, extECH} {
			if slices.Equal(first.data[id], h.data[id]) {
				t.Errorf("extension %04x the same in two carriers", id)
			}
		}
	}
	if len(orders) < 2 {
		t.Error("the extensions come in one order only")
	}
	if len(echLens) < 2 {
		t.Error("the GREASE ECH payload has one length only")
	}
}
