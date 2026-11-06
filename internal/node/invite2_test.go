package node

import (
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"rsc.io/qr"
)

func seqHex(from byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = from + byte(i)
	}
	return hex.EncodeToString(b)
}

func invite2Bundle(host string, pin bool) Bundle {
	apiPin, _ := hex.DecodeString(seqHex(0x60, 32))
	return Bundle{Version: 1, Host: host, PIN: pin,
		SPA: SPAParams{NodeID: seqHex(0, 16), EpochLenS: 34380, SlotLenS: 1620, PortKey: seqHex(0x20, 32),
			PortBase: 21907, PortRange: 2955, LenMin: 136, LenMax: 206},
		DeviceID: seqHex(0xa0, 8), DeviceKey: seqHex(0x40, 32),
		Services: []BundleService{{ID: 7, Kind: "api", Name: "api"}},
		API:      &BundleSub{Port: 48213, Pin: base64.RawURLEncoding.EncodeToString(apiPin)},
		Expires:  1767312000}
}

// The layout of api-v1 §3a, worked out apart from this code (Python, the
// layout alone): IPv4 with a PIN, IPv6, a name.
func TestInvite2Vectors(t *testing.T) {
	for _, c := range []struct {
		host string
		pin  bool
		want string
	}{
		{"203.0.113.7", true, "RCINV2:AIA4WADRA4AACAQDAQCQMBYIBEFAWDANBYHQAAEGJQAAABSUEAQSEIZEEUTCOKBJFIVSYLJOF4YDCMRTGQ2TMNZYHE5DWPB5HY7VLEYLRMAIQAGOUCQ2FI5EUWTKOQCBIJBUIRKGI5EESSSLJRGU4T2QKFJFGVCVKZLVQWK2LNOF2XS7AAD3YVLAMFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPJ5XY7L6P5UVOCUA"},
		{"2001:db8::7", false, "RCINV2:AIBCAAINXAAAAAAAAAAAAAAAAAAAOAABAIBQIBIGA4EASCQLBQGQ4DYAACDEYAAAAZKCAIJCEMSCKJRHFAUSUKZMFUXC6MBRGIZTINJWG44DSOR3HQ6T4P2VSMFYWAEIADHKBINCUOSKLJVHIBAUEQ2EIVDEOSCJJJFUYTKOJ5IFCUSTKRKVMV2YLFNFWXC5LZPQAB54KVQGCYTDMRSWMZ3INFVGW3DNNZXXA4LSON2HK5TXPB4XU634PV7H62KXBKAA"},
		{"node.example.com", false, "RCINV2:AICBA3TPMRSS4ZLYMFWXA3DFFZRW63IAAEBAGBAFAYDQQCIKBMGA2DQPAAAIMTAAAADFIIBBEIRSIJJGE4UCSKRLFQWS4LZQGEZDGNBVGY3TQOJ2HM6D2PR7KWJQXCYARAAM5IFBUKR2JJNGU5AECQSDIRCUMR2IJFFEWTCNJZHVAUKSKNKFKVSXLBMVUW24LVPF6AAHXRKWAYLCMNSGKZTHNBUWU23MNVXG64DROJZXI5LWO54HS6T3PR6X473JK4FIA"},
	} {
		b := invite2Bundle(c.host, c.pin)
		got, err := b.EncodeInvite2()
		if err != nil || got != c.want {
			t.Errorf("%s: %v\n%s\nwant\n%s", c.host, err, got, c.want)
			continue
		}
		back, err := DecodeInvite(got)
		if err != nil || !reflect.DeepEqual(back, b) {
			t.Errorf("%s: back %+v %v", c.host, back, err)
		}
		// Pasted in lower case, it reads the same.
		if low, err := DecodeInvite(strings.ToLower(got)); err != nil || !reflect.DeepEqual(low, b) {
			t.Errorf("%s: lower case %v", c.host, err)
		}
	}
}

// The QR of a short invite: version 9 at most with level M (61 terminal
// columns with the quiet zone), where rcinv1's was 17.
func TestInvite2QR(t *testing.T) {
	b := invite2Bundle("203.0.113.7", true)
	s, err := b.EncodeInvite2()
	if err != nil {
		t.Fatal(err)
	}
	code, err := qr.Encode(s, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	if v := (code.Size - 17) / 4; v > 9 {
		t.Fatalf("QR version %d for %d characters", v, len(s))
	}
	long, _ := b.EncodeInvite()
	if len(s) >= len(long)/2 {
		t.Fatalf("rcinv2 %d characters, rcinv1 %d", len(s), len(long))
	}
}

// What a reader refuses: another version, flags it does not know, a kind
// of host there is not, a field cut short, a byte left over, a bad name.
func TestInvite2Refused(t *testing.T) {
	good, _ := invite2Bundle("203.0.113.7", false).EncodeInvite2()
	raw, err := invite2Base32.DecodeString(strings.TrimPrefix(good, InvitePrefix2))
	if err != nil {
		t.Fatal(err)
	}
	encode := func(b []byte) string { return InvitePrefix2 + invite2Base32.EncodeToString(b) }
	with := func(i int, v byte) string {
		b := append([]byte(nil), raw...)
		b[i] = v
		return encode(b)
	}
	name, _ := invite2Bundle("node.example.com", false).EncodeInvite2()
	nameRaw, _ := invite2Base32.DecodeString(strings.TrimPrefix(name, InvitePrefix2))
	nameRaw[3] = '_' // node -> n_de
	for what, s := range map[string]string{
		"version 3":      with(0, 3),
		"version 1":      with(0, 1),
		"unknown flag":   with(1, 1<<3),
		"host kind 3":    with(1, 3<<1),
		"cut short":      encode(raw[:len(raw)-1]),
		"a byte over":    encode(append(append([]byte(nil), raw...), 0)),
		"no expiry":      encode(append(append([]byte(nil), raw[:len(raw)-4]...), 0, 0, 0, 0)),
		"bad name":       encode(nameRaw),
		"not base32":     InvitePrefix2 + "AIA!",
		"rcinv1 version": "rcinv1:" + base64.RawURLEncoding.EncodeToString([]byte(`{"v":2}`)),
	} {
		if _, err := DecodeInvite(s); err == nil {
			t.Errorf("%s: taken", what)
		}
	}
	// And what a node does not encode.
	for what, b := range map[string]Bundle{
		"IDN host": invite2Bundle("узел.example.com", false),
		"no API":   func() Bundle { b := invite2Bundle("203.0.113.7", false); b.API = nil; return b }(),
		"two services": func() Bundle {
			b := invite2Bundle("203.0.113.7", false)
			b.Services = append(b.Services, BundleService{ID: 8, Kind: "api", Name: "x"})
			return b
		}(),
		"short key": func() Bundle { b := invite2Bundle("203.0.113.7", false); b.DeviceKey = "abcd"; return b }(),
		"zone":      invite2Bundle("fe80::1%eth0", false),
	} {
		if s, err := b.EncodeInvite2(); err == nil {
			t.Errorf("%s: encoded %s", what, s)
		}
	}
}
