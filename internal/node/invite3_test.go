package node

import (
	"reflect"
	"strings"
	"testing"

	"rsc.io/qr"
)

// The layout of api-v1 §3b, worked out apart from this code (Python, the
// layout alone): rcinv2's fields, the node's name after the host, a flag
// for SPA v3.
func TestInvite3Vectors(t *testing.T) {
	for _, c := range []struct {
		host, name string
		pin, v3    bool
		want       string
	}{
		{"203.0.113.7", "k3f.example.com", true, true, "RCINV3:AMM4WADRA4HWWM3GFZSXQYLNOBWGKLTDN5WQAAICAMCAKBQHBAEQUCYMBUHA6AAAQZGAAAAGKQQCCIRDEQSSMJZIFEVCWLBNFYXTAMJSGM2DKNRXHA4TUOZ4HU7D6VMTBOFQBCAAZ2QKDIVDUSS2NJ2AIFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2UKVLFOWCZLJNVYXK6L4AAPPCVMBQWEY3EMVTGO2DJNJVWY3LON5YHC4TTOR2XM53YPF5HW7D5PZ7WSVYKQA"},
		{"2001:db8::7", "k3f.example.com", false, true, "RCINV3:AMNCAAINXAAAAAAAAAAAAAAAAAAAOD3LGNTC4ZLYMFWXA3DFFZRW63IAAEBAGBAFAYDQQCIKBMGA2DQPAAAIMTAAAADFIIBBEIRSIJJGE4UCSKRLFQWS4LZQGEZDGNBVGY3TQOJ2HM6D2PR7KWJQXCYARAAM5IFBUKR2JJNGU5AECQSDIRCUMR2IJFFEWTCNJZHVAUKSKNKFKVSXLBMVUW24LVPF6AAHXRKWAYLCMNSGKZTHNBUWU23MNVXG64DROJZXI5LWO54HS6T3PR6X473JK4FIA"},
		{"node.example.com", "", false, true, "RCINV3:AMKBA3TPMRSS4ZLYMFWXA3DFFZRW63IAAEBAGBAFAYDQQCIKBMGA2DQPAAAIMTAAAADFIIBBEIRSIJJGE4UCSKRLFQWS4LZQGEZDGNBVGY3TQOJ2HM6D2PR7KWJQXCYARAAM5IFBUKR2JJNGU5AECQSDIRCUMR2IJFFEWTCNJZHVAUKSKNKFKVSXLBMVUW24LVPF6AAHXRKWAYLCMNSGKZTHNBUWU23MNVXG64DROJZXI5LWO54HS6T3PR6X473JK4FIA"},
		{"203.0.113.7", "", false, false, "RCINV3:AMAMWADRA4AACAQDAQCQMBYIBEFAWDANBYHQAAEGJQAAABSUEAQSEIZEEUTCOKBJFIVSYLJOF4YDCMRTGQ2TMNZYHE5DWPB5HY7VLEYLRMAIQAGOUCQ2FI5EUWTKOQCBIJBUIRKGI5EESSSLJRGU4T2QKFJFGVCVKZLVQWK2LNOF2XS7AAD3YVLAMFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPJ5XY7L6P5UVOCUA"},
	} {
		b := invite2Bundle(c.host, c.pin)
		if c.name != "" {
			b.DNSName, b.Addrs = c.name, Addrs(c.host)
		}
		if c.v3 {
			b.SPA.Versions = []int{2, 3}
		}
		got, err := b.EncodeInvite3()
		if err != nil || got != c.want {
			t.Errorf("%s %s: %v\n%s\nwant\n%s", c.host, c.name, err, got, c.want)
			continue
		}
		back, err := DecodeInvite(got)
		if err != nil || !reflect.DeepEqual(back, b) {
			t.Errorf("%s: back %+v %v", c.host, back, err)
		}
		if low, err := DecodeInvite(strings.ToLower(got)); err != nil || !reflect.DeepEqual(low, b) {
			t.Errorf("%s: lower case %v", c.host, err)
		}
		// rcinv2 of the same bundle leaves the name and versions out.
		if s2, err := b.EncodeInvite2(); err != nil {
			t.Errorf("%s: rcinv2 %v", c.host, err)
		} else if b2, err := DecodeInvite(s2); err != nil || b2.DNSName != "" || b2.SPA.Versions != nil {
			t.Errorf("%s: rcinv2 carries %q %v (%v)", c.host, b2.DNSName, b2.SPA.Versions, err)
		}
	}
}

func TestInvite3Refused(t *testing.T) {
	b := invite2Bundle("node.example.com", false)
	b.DNSName = "k3f.example.com"
	if s, err := b.EncodeInvite3(); err == nil || s != "" {
		t.Fatalf("a name with a host that is a name encoded: %q (%v)", s, err)
	}
	b = invite2Bundle("203.0.113.7", false)
	// A name that is no name, or one a client would take for an address.
	for _, name := range []string{"bad name", "198.51.100.99", "k3f.example.123", "1234"} {
		b.DNSName = name
		if s, err := b.EncodeInvite3(); err == nil || s != "" {
			t.Errorf("name %q encoded: %q (%v)", name, s, err)
		}
	}
	b.DNSName = "k3f.example.com"
	good, err := b.EncodeInvite3()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := invite2Base32.DecodeString(good[len(InvitePrefix3):])
	enc := func(r []byte) string { return InvitePrefix3 + invite2Base32.EncodeToString(r) }
	bad := map[string][]byte{}
	b1 := append([]byte(nil), raw...)
	b1[1] |= 1 << 5 // a flag rcinv3 does not know
	bad["unknown flag"] = b1
	b2 := append([]byte(nil), raw...)
	b2[0] = 2
	bad["version 2 under RCINV3"] = b2
	bad["byte left over"] = append(append([]byte(nil), raw...), 0)
	bad["cut short"] = raw[:len(raw)-1]
	// the name k3f.example.com (after the version, the flags, the 4 bytes of
	// the host and the name's length) as a name of the same length that
	// looks like an address
	b3 := append([]byte(nil), raw...)
	if string(raw[2+4+1:2+4+1+15]) != "k3f.example.com" {
		t.Fatalf("the name is not where the layout puts it: %q", raw[2+4+1:2+4+1+15])
	}
	copy(b3[2+4+1:], "198.51.100.9999")
	bad["a name like an address"] = b3
	for what, r := range bad {
		if _, err := DecodeInvite(enc(r)); err == nil {
			t.Errorf("%s: taken", what)
		}
	}
	// rcinv2 does not take rcinv3's flags.
	r2 := append([]byte(nil), raw...)
	r2[0] = 2
	if _, err := DecodeInvite(InvitePrefix2 + invite2Base32.EncodeToString(r2)); err == nil {
		t.Error("rcinv2 took the name flag")
	}
}

// The QR of an invite by name: version 10 at most with level M.
func TestInvite3QR(t *testing.T) {
	b := invite2Bundle("203.0.113.7", true)
	b.DNSName, b.Addrs, b.SPA.Versions = "k3f.example.com", []string{"203.0.113.7"}, []int{2, 3}
	s, err := b.EncodeInvite3()
	if err != nil {
		t.Fatal(err)
	}
	code, err := qr.Encode(s, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	v := (code.Size - 17) / 4
	t.Logf("QR version %d for %d characters", v, len(s))
	if v > 10 {
		t.Fatalf("QR version %d for %d characters", v, len(s))
	}
}
