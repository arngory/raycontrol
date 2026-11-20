package node

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
)

// InvitePrefix2 marks an invite in the short form (api-v1 §3a): base32 of a
// fixed binary layout, about 250 characters for an IPv4 host, all in the
// alphanumeric set of QR codes, so the QR is version 8 or 9, not 17. The
// fields and what they mean are rcinv1's.
const InvitePrefix2 = "RCINV2:"

// InvitePrefix3 marks an invite by name (api-v1 §3b): rcinv2's layout with
// the node's own name after the host and a flag for SPA v3.
const InvitePrefix3 = "RCINV3:"

const (
	invite2Version = 2
	invite3Version = 3
	invite2PIN     = 1 << 0 // the invite also needs a PIN
	invite2HostV4  = 0 << 1 // the host: 4 bytes
	invite2HostV6  = 1 << 1 // 16 bytes
	invite2HostDNS = 2 << 1 // a length byte, then the name (ASCII, punycode for IDN)
	invite2Host    = 3 << 1
	invite3Name    = 1 << 3 // rcinv3: the node's name (dns_name) follows the host, which is an address
	invite3SPA3    = 1 << 4 // rcinv3: the node takes SPA v3 (spa.versions [2, 3])
)

var invite2Base32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeInvite2 returns the bundle of an invite in the short form, without
// the node's name and SPA versions: those go in rcinv3.
func (b Bundle) EncodeInvite2() (string, error) {
	s, err := b.encodeShort(invite2Version)
	if err != nil {
		return "", err
	}
	return InvitePrefix2 + s, nil
}

// EncodeInvite3 returns the bundle of an invite by name (api-v1 §3b): the
// node's name when it has one, and whether it takes SPA v3.
func (b Bundle) EncodeInvite3() (string, error) {
	s, err := b.encodeShort(invite3Version)
	if err != nil {
		return "", err
	}
	return InvitePrefix3 + s, nil
}

func (b Bundle) encodeShort(version byte) (string, error) {
	tag := fmt.Sprintf("rcinv%d", version)
	if b.API == nil || b.Expires <= 0 || b.Expires > math.MaxUint32 || len(b.Services) != 1 || b.Services[0].Kind != "api" {
		return "", fmt.Errorf("%s: an invite has the API as its one service, an API endpoint and an expiry", tag)
	}
	out := []byte{version, 0}
	if b.PIN {
		out[1] |= invite2PIN
	}
	name := version == invite3Version && b.DNSName != ""
	if name {
		// names-v1 §2: a node has a name only when its host is an address,
		// and that address is the name's fallback (addrs).
		if a, err := netip.ParseAddr(b.Host); err != nil || a.Zone() != "" {
			return "", fmt.Errorf("%s: the node's name %q with a host %q that is no address", tag, b.DNSName, b.Host)
		}
		if !nodeName(b.DNSName) {
			return "", fmt.Errorf("%s: name %q is no ASCII name, or looks like an address", tag, b.DNSName)
		}
		out[1] |= invite3Name
	}
	if version == invite3Version && slices.Contains(b.SPA.Versions, 3) {
		out[1] |= invite3SPA3
	}
	if a, err := netip.ParseAddr(b.Host); err == nil && a.Zone() == "" {
		if a = a.Unmap(); a.Is4() {
			v4 := a.As4()
			out = append(out, v4[:]...)
		} else {
			v6 := a.As16()
			out[1] |= invite2HostV6
			out = append(out, v6[:]...)
		}
	} else {
		if !hostName(b.Host) {
			return "", fmt.Errorf("%s: host %q is no address and no ASCII name (an IDN goes as punycode)", tag, b.Host)
		}
		out[1] |= invite2HostDNS
		out = append(out, byte(len(b.Host)))
		out = append(out, b.Host...)
	}
	if name {
		out = append(out, byte(len(b.DNSName)))
		out = append(out, b.DNSName...)
	}
	var err error
	field := func(name, h string, n int) {
		if err != nil {
			return
		}
		v, e := hex.DecodeString(h)
		if e != nil || len(v) != n {
			err = fmt.Errorf("%s: %s is not %d bytes of hex", tag, name, n)
			return
		}
		out = append(out, v...)
	}
	u16 := func(name string, v int64) {
		if err == nil && (v < 0 || v > math.MaxUint16) {
			err = fmt.Errorf("%s: %s %d out of range", tag, name, v)
		}
		out = binary.BigEndian.AppendUint16(out, uint16(v))
	}
	u32 := func(name string, v int64) {
		if err == nil && (v <= 0 || v > math.MaxUint32) {
			err = fmt.Errorf("%s: %s %d out of range", tag, name, v)
		}
		out = binary.BigEndian.AppendUint32(out, uint32(v))
	}
	field("spa.node_id", b.SPA.NodeID, 16)
	u32("spa.epoch_len_s", b.SPA.EpochLenS)
	u32("spa.slot_len_s", b.SPA.SlotLenS)
	field("spa.port_key", b.SPA.PortKey, 32)
	u16("spa.port_base", int64(b.SPA.PortBase))
	u16("spa.port_range", int64(b.SPA.PortRange))
	u16("spa.len_min", int64(b.SPA.LenMin))
	u16("spa.len_max", int64(b.SPA.LenMax))
	field("device_id", b.DeviceID, 8)
	field("device_key", b.DeviceKey, 32)
	u16("services[0].id", int64(b.Services[0].ID))
	u16("api.port", int64(b.API.Port))
	pin, e := base64.RawURLEncoding.DecodeString(b.API.Pin)
	if err == nil && (e != nil || len(pin) != 32) {
		err = fmt.Errorf("%s: api.pin is not 32 bytes of base64url", tag)
	}
	out = append(out, pin...)
	u32("expires", b.Expires)
	if err != nil {
		return "", err
	}
	return invite2Base32.EncodeToString(out), nil
}

// decodeShort parses the base32 of a short invite of a version (rcinv2,
// rcinv3), after its prefix. Another version, flags this one does not know,
// a field cut short or a byte left over: refused.
func decodeShort(text string, version byte) (Bundle, error) {
	tag := fmt.Sprintf("rcinv%d", version)
	raw, err := invite2Base32.DecodeString(strings.ToUpper(text))
	if err != nil {
		return Bundle{}, fmt.Errorf("%s: %w", tag, err)
	}
	r := invite2Reader{b: raw, tag: tag}
	if v := r.byte(); v != version {
		return Bundle{}, fmt.Errorf("%s: version %d", tag, v)
	}
	flags := r.byte()
	known := byte(invite2PIN | invite2Host)
	if version == invite3Version {
		known |= invite3Name | invite3SPA3
	}
	if flags&^known != 0 {
		return Bundle{}, fmt.Errorf("%s: unknown flags %#02x", tag, flags)
	}
	b := Bundle{Version: 1, PIN: flags&invite2PIN != 0}
	switch flags & invite2Host {
	case invite2HostV4:
		b.Host = netip.AddrFrom4([4]byte(r.bytes(4))).String()
	case invite2HostV6:
		b.Host = netip.AddrFrom16([16]byte(r.bytes(16))).String()
	case invite2HostDNS:
		b.Host = string(r.bytes(int(r.byte())))
		if r.err == nil && !hostName(b.Host) {
			return Bundle{}, fmt.Errorf("%s: host %q", tag, b.Host)
		}
	default:
		return Bundle{}, fmt.Errorf("%s: unknown kind of host", tag)
	}
	if flags&invite3Name != 0 {
		if flags&invite2Host == invite2HostDNS {
			return Bundle{}, fmt.Errorf("%s: the node's name with a host that is a name", tag)
		}
		b.DNSName = string(r.bytes(int(r.byte())))
		if r.err == nil && !nodeName(b.DNSName) {
			return Bundle{}, fmt.Errorf("%s: name %q", tag, b.DNSName)
		}
		b.Addrs = Addrs(b.Host)
	}
	if flags&invite3SPA3 != 0 {
		b.SPA.Versions = slices.Clone(SPAVersions)
	}
	b.SPA.NodeID = hex.EncodeToString(r.bytes(16))
	b.SPA.EpochLenS = int64(r.u32())
	b.SPA.SlotLenS = int64(r.u32())
	b.SPA.PortKey = hex.EncodeToString(r.bytes(32))
	b.SPA.PortBase = r.u16()
	b.SPA.PortRange = r.u16()
	b.SPA.LenMin = int(r.u16())
	b.SPA.LenMax = int(r.u16())
	b.DeviceID = hex.EncodeToString(r.bytes(8))
	b.DeviceKey = hex.EncodeToString(r.bytes(32))
	b.Services = []BundleService{{ID: r.u16(), Kind: "api", Name: "api"}}
	b.API = &BundleSub{Port: r.u16()}
	b.API.Pin = base64.RawURLEncoding.EncodeToString(r.bytes(32))
	b.Expires = int64(r.u32())
	switch {
	case r.err != nil:
		return Bundle{}, r.err
	case len(r.b) != 0:
		return Bundle{}, fmt.Errorf("%s: %d bytes left over", tag, len(r.b))
	case b.Expires == 0 || b.API.Port == 0:
		return Bundle{}, fmt.Errorf("%s: no expiry or no API port", tag)
	}
	return b, nil
}

type invite2Reader struct {
	b   []byte
	tag string
	err error
}

func (r *invite2Reader) bytes(n int) []byte {
	if r.err != nil || len(r.b) < n {
		if r.err == nil {
			r.err = fmt.Errorf("%s: cut short", r.tag)
		}
		return make([]byte, n)
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *invite2Reader) byte() byte  { return r.bytes(1)[0] }
func (r *invite2Reader) u16() uint16 { return binary.BigEndian.Uint16(r.bytes(2)) }
func (r *invite2Reader) u32() uint32 { return binary.BigEndian.Uint32(r.bytes(4)) }

// nodeName reports whether s is a name rcinv3 carries as the node's: a
// host name whose last label is not all digits, so that no client takes
// it for an address (198.51.100.99).
func nodeName(s string) bool {
	if !hostName(s) {
		return false
	}
	last := s[strings.LastIndexByte(s, '.')+1:]
	return strings.Trim(last, "0123456789") != ""
}

// hostName reports whether s is a host name an invite carries: ASCII
// letters, digits, hyphens and dots, labels of 1 to 63, 253 at most.
func hostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for l := range strings.SplitSeq(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range []byte(l) {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
