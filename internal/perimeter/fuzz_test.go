package perimeter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/spa"
)

// scriptFW is a firewall that writes down the nft transactions NFT would
// run for the gate's calls, as NFT renders them, and the ports, prefixes
// and addresses it was handed.
type scriptFW struct {
	n       *NFT
	scripts []string
	ports   []Port
	nets    []netip.Prefix
	addrs   []netip.Addr
	rot     map[uint16]uint16
	udp     []uint16
}

func (f *scriptFW) run(s string) error { f.scripts = append(f.scripts, s); return nil }
func (f *scriptFW) Setup() error       { return f.SetupWith(TableContents{}) }
func (f *scriptFW) SetupWith(c TableContents) error {
	f.ports = append(f.ports, c.Public...)
	f.ports = append(f.ports, c.AdminPorts...)
	f.ports = append(f.ports, c.Forward...)
	f.ports = append(f.ports, c.RelayPorts...)
	f.ports = append(f.ports, c.IntegPorts...)
	f.nets = append(f.nets, c.Admin...)
	f.nets = append(f.nets, c.Relays...)
	f.nets = append(f.nets, c.Integ...)
	for _, g := range c.Grants {
		f.ports, f.addrs = append(f.ports, g.Port), append(f.addrs, g.Addr)
	}
	f.rot, f.udp = c.Rotation, c.SPAUDP
	return f.run(f.n.SetupScript(c))
}
func (f *scriptFW) Present() (bool, error) { return true, nil }
func (f *scriptFW) SetSPAPorts(udp, tcp []uint16) error {
	f.udp = udp
	return f.run(spaPortsScript(udp, tcp))
}
func (f *scriptFW) SetPublic(ports []Port) error {
	f.ports = append(f.ports, ports...)
	return f.run(publicScript(ports))
}
func (f *scriptFW) SetAdmin(prefixes []netip.Prefix, ports []Port) error {
	f.nets, f.ports = append(f.nets, prefixes...), append(f.ports, ports...)
	return f.run(adminScript(prefixes, ports))
}
func (f *scriptFW) SetInteg(prefixes []netip.Prefix, ports []Port) error {
	f.nets, f.ports = append(f.nets, prefixes...), append(f.ports, ports...)
	return f.run(integScript(prefixes, ports))
}
func (f *scriptFW) SetForward(ports []Port) error {
	f.ports = append(f.ports, ports...)
	if !f.n.RelayTo.IsValid() {
		return nil
	}
	return f.run(forwardScript(ports))
}
func (f *scriptFW) SetRelays(addrs []netip.Prefix, ports []Port) error {
	f.nets, f.ports = append(f.nets, addrs...), append(f.ports, ports...)
	return f.run(relaysScript(addrs, ports))
}
func (f *scriptFW) SetRotation(udp map[uint16]uint16) error {
	f.rot = udp
	return f.run(rotationScript(udp))
}
func (f *scriptFW) SetACME(port uint16, ttl time.Duration) error { return f.run(acmeScript(port, ttl)) }
func (f *scriptFW) SetEgress(e Egress) error {
	if f.n.RelayTo.IsValid() {
		return nil
	}
	f.ports = append(f.ports, e.Loopback...)
	for _, x := range e.Exempt {
		f.ports, f.addrs = append(f.ports, x.Port), append(f.addrs, x.Addr)
	}
	return errors.Join(f.run(EgressLocalScript(e)), f.run(EgressOptionalScript(e, false)), f.run(EgressOptionalScript(e, true)))
}
func (f *scriptFW) SetInLimit(on bool) error {
	return f.run(inLimitScript(on, f.n.RelayTo.IsValid(), 1))
}
func (f *scriptFW) SetGuard(on bool) error { return f.run(GuardScript(on)) }
func (f *scriptFW) Allow(addr netip.Addr, ports []Port, ttl time.Duration) error {
	f.ports, f.addrs = append(f.ports, ports...), append(f.addrs, addr)
	set, elems := elements(addr, ports, ttl)
	return f.run(f.n.forget(addr, ports) + "add element inet " + Table + " " + set + " { " + elems + " }\n")
}
func (f *scriptFW) Deny(addr netip.Addr, ports []Port) error {
	f.ports, f.addrs = append(f.ports, ports...), append(f.addrs, addr)
	return f.run(f.n.forget(addr, ports))
}
func (f *scriptFW) Teardown() error { return nil }

var (
	// The lines of a transaction the gate's calls make, but those of the
	// table's rules (Ruleset) and the fixed rules (fixedLines).
	flushLine   = regexp.MustCompile(`^flush (set|map|chain) inet raycontrol [a-z0-9_]+$`)
	elementLine = regexp.MustCompile(`^(add|delete|destroy) element inet raycontrol [a-z0-9_]+ \{ (.+) \}$`)
	exemptLine  = regexp.MustCompile(`^add rule inet raycontrol egress_local meta skuid ([0-9]+) ip6? daddr ([0-9a-f:.]+) meta l4proto (tcp|udp) th dport ([0-9]+) return$`)
	loopLine    = regexp.MustCompile(`^add rule inet raycontrol egress_local ip daddr 127\.0\.0\.1 meta l4proto \. th dport \{ (.+) \} return$`)
	// The elements of a set or map.
	portElem  = regexp.MustCompile(`^(tcp|udp) \. ([0-9]{1,5})$`)
	grantElem = regexp.MustCompile(`^([0-9a-f:.]+) \. (tcp|udp) \. ([0-9]{1,5})( timeout [0-9]+s)?$`)
	numElem   = regexp.MustCompile(`^([0-9]{1,5})( timeout [0-9]+s)?$`)
	rotElem   = regexp.MustCompile(`^([0-9]{1,5}) : ([0-9]{1,5})$`)
	acmeElem  = regexp.MustCompile(`^80 timeout [0-9]+s : ([0-9]{1,5})$`)
)

// fixedLines are the rules the gate's calls add whatever the snapshot
// says: each exactly as it is.
var fixedLines = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range []string{relaysScript(nil, nil), inLimitScript(true, true, 1), GuardScript(true),
		EgressOptionalScript(Egress{SMTP: true, BitTorrent: true}, false), EgressOptionalScript(Egress{SMTP: true, BitTorrent: true}, true),
		EgressLocalScript(Egress{Local: true})} {
		for _, l := range strings.Split(s, "\n") {
			if strings.HasPrefix(l, "add rule ") && !strings.Contains(l, "meta skuid") && !strings.Contains(l, "127.0.0.1 meta l4proto .") {
				m[l] = true
			}
		}
	}
	return m
}()

// port reports whether s is a port number.
func port(s string) bool { n, err := strconv.Atoi(s); return err == nil && n >= 0 && n <= 65535 }

// checkScript fails t unless every line of script is one the gate's calls
// make, every element a port, an address or a prefix nftables reads as
// such: nothing a snapshot carries, whatever it is, reads as nft syntax.
func checkScript(t *testing.T, n *NFT, script string) {
	t.Helper()
	script = strings.TrimPrefix(script, n.Ruleset())
	for _, l := range strings.Split(strings.TrimSuffix(script, "\n"), "\n") {
		switch m := elementLine.FindStringSubmatch(l); {
		case l == "", fixedLines[l], flushLine.MatchString(l):
		case m != nil:
			for _, e := range strings.Split(m[2], ", ") {
				if !element(e) {
					t.Fatalf("element %q in %q", e, l)
				}
			}
		case exemptLine.MatchString(l):
			x := exemptLine.FindStringSubmatch(l)
			if _, err := netip.ParseAddr(x[2]); err != nil || !port(x[4]) {
				t.Fatalf("rule %q", l)
			}
		case loopLine.MatchString(l):
			for _, e := range strings.Split(loopLine.FindStringSubmatch(l)[1], ", ") {
				if m := portElem.FindStringSubmatch(e); m == nil || !port(m[2]) {
					t.Fatalf("element %q in %q", e, l)
				}
			}
		default:
			t.Fatalf("line %q in:\n%s", l, script)
		}
	}
}

func element(e string) bool {
	if m := portElem.FindStringSubmatch(e); m != nil {
		return port(m[2])
	}
	if m := grantElem.FindStringSubmatch(e); m != nil {
		_, err := netip.ParseAddr(m[1])
		return err == nil && port(m[3])
	}
	if m := numElem.FindStringSubmatch(e); m != nil {
		return port(m[1])
	}
	if m := rotElem.FindStringSubmatch(e); m != nil {
		return port(m[1]) && port(m[2])
	}
	if m := acmeElem.FindStringSubmatch(e); m != nil {
		return port(m[1])
	}
	if p, err := netip.ParsePrefix(e); err == nil {
		return p.String() == e
	}
	a, err := netip.ParseAddr(e)
	return err == nil && a.Zone() == "" && a.String() == e
}

// fuzzSnapshot is a snapshot with everything in it: devices, services
// with a rotation and a relay's own, public, admin and relay ports and
// addresses, the ACME window and the egress policy.
func fuzzSnapshot(now time.Time) *perimeterv1.Snapshot {
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1, 2, 3}},
		&perimeterv1.Device{Id: "bob", Key: key(0x12), Allowed: []uint32{1}})
	snap.Services[1].Rotation = &perimeterv1.Rotation{PortKey: key(0x55), PortBase: 20000, PortRange: 1000, TargetPort: 443}
	snap.Services = append(snap.Services, &perimeterv1.Service{Id: 4, Local: true, Ports: []*perimeterv1.Port{{Proto: "tcp", Port: 2222}}})
	snap.AdminPrefixes = []string{"198.51.100.0/24", "2001:db8::/48", "::ffff:203.0.113.7/128"}
	snap.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 22}}
	snap.RelayPrefixes = []string{"192.0.2.44/32", "2001:db8::44/128"}
	snap.RelayPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 443}, {Proto: "udp", Port: 443}}
	snap.IntegPrefixes = []string{"198.51.100.7/32", "2001:db8:7::/64", "::ffff:203.0.113.8/128"}
	snap.IntegPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 8443}}
	snap.Acme = &perimeterv1.AcmeWindow{Port: 9180, Until: now.Add(10 * time.Minute).Unix()}
	snap.Egress = &perimeterv1.Egress{Smtp: true, Bittorrent: true, Uids: []uint32{4242}, Local: &perimeterv1.Local{
		Loopback: []*perimeterv1.Port{{Proto: "tcp", Port: 8443}},
		Exempt:   []*perimeterv1.LocalExempt{{Addr: "10.0.0.7", Port: &perimeterv1.Port{Proto: "tcp", Port: 443}, Uid: 9121}}}}
	return snap
}

// FuzzGateUpdate: whatever snapshot the feed brings (rayd's on a node, the
// exit's on a relay, both apart from rayspa's root), what the gate takes
// gives nft transactions of the gate's own lines only, with ports in
// range, protocols tcp or udp, addresses and prefixes that parse; the
// slot ports lie in their ranges, rotated ones too. A snapshot whose
// field is out of its bounds is refused, not cut to fit.
func FuzzGateUpdate(f *testing.F) {
	now := time.Unix(1767225600, 0)
	good, err := proto.Marshal(fuzzSnapshot(now))
	if err != nil {
		f.Fatal(err)
	}
	plain, _ := proto.Marshal(testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}}))
	for _, s := range []struct {
		snap       []byte
		at         uint8
		proto      string
		n, b, r, x uint32
	}{
		{good, 0, "tcp", 443, 20000, 1000, 443},
		{plain, 0, "udp", 53, 0, 0, 0},
		{good, 1, "tcp . 22 }\nflush ruleset\nadd element inet raycontrol public { tcp", 22, 0, 0, 0},
		{good, 2, "udp", 70000, 0, 0, 0},
		{good, 5, "", 0, 0xffff0000 + 60000, 10000, 70443},
		{good, 6, "sctp", 9180, 1, 1, 1},
		{nil, 0, "", 0, 0, 0, 0},
	} {
		for _, relay := range []bool{false, true} {
			f.Add(s.snap, s.at, s.proto, s.n, s.b, s.r, s.x, relay, relay)
		}
	}
	exit := netip.MustParseAddr("203.0.113.1")
	f.Fuzz(func(t *testing.T, raw []byte, at uint8, pr string, num, base, rng, target uint32, relay, first bool) {
		snap := &perimeterv1.Snapshot{}
		if proto.Unmarshal(raw, snap) != nil {
			return
		}
		// One field set as the fuzzer says, so that it reaches each.
		set := func(ps []*perimeterv1.Port) {
			if len(ps) > 0 {
				ps[int(num)%len(ps)].Proto, ps[int(num)%len(ps)].Port = pr, num
			}
		}
		switch at % 8 {
		case 1:
			set(snap.PublicPorts)
		case 2:
			if len(snap.Services) > 0 {
				set(snap.Services[int(base)%len(snap.Services)].Ports)
			}
		case 3:
			set(snap.AdminPorts)
		case 4:
			set(snap.RelayPorts)
		case 5:
			for _, s := range snap.Services {
				if s.Rotation != nil {
					s.Rotation.PortBase, s.Rotation.PortRange, s.Rotation.TargetPort = base, rng, target
				}
			}
		case 6:
			if snap.Acme != nil {
				snap.Acme.Port = num
			}
		case 7:
			if l := snap.GetEgress().GetLocal(); l != nil {
				set(l.Loopback)
			}
		}

		n := &NFT{}
		if relay {
			n.RelayTo = exit
		}
		fw := &scriptFW{n: n}
		g := NewGate(fw, quiet)
		g.now = func() time.Time { return now }
		if first {
			g.SetupAtFirstSnapshot()
		}
		err := g.Update(snap)
		if err != nil && !errors.Is(err, ErrPending) {
			if len(fw.scripts) != 0 {
				t.Fatalf("refused (%v), and %d transactions run", err, len(fw.scripts))
			}
			return
		}
		checkTaken(t, snap)

		// A device's knock, then its revocation: the grant's elements go
		// in and out.
		if d := snap.GetDevices(); len(d) > 0 && len(d[0].Key) == spa.KeySize {
			p, _ := paramsOf(snap.Spa)
			var scope []uint16
			for _, id := range d[0].Allowed {
				if len(scope) < spa.MaxScope {
					scope = append(scope, uint16(id)) //nolint:gosec // G115: a test's
				}
			}
			pkt, err := spa.Seal(p, [spa.KeySize]byte(d[0].Key), spa.Request{Time: now, Scope: scope}, bytes.Repeat([]byte{7}, spa.NonceSize), p.LenMin)
			if err == nil {
				_, _ = g.Handle(netip.MustParseAddr("192.0.2.9"), pkt)
				_, _ = g.Handle(netip.MustParseAddr("2001:db8::9"), pkt) // a replay
			}
			snap.Devices = snap.Devices[1:]
			_ = g.Update(snap)
		}
		later := now.Add(time.Hour)
		g.now = func() time.Time { return later }
		_, _ = g.Tick()

		for _, s := range fw.scripts {
			checkScript(t, n, s)
		}
		for _, p := range fw.ports {
			if p.Proto != "tcp" && p.Proto != "udp" {
				t.Fatalf("port %q handed to the firewall", p.Proto)
			}
		}
		for _, p := range fw.nets {
			if !p.IsValid() || p != p.Masked() && !p.IsSingleIP() {
				t.Fatalf("prefix %v handed to the firewall", p)
			}
		}
		for _, a := range fw.addrs {
			if !a.IsValid() || a.Zone() != "" {
				t.Fatalf("address %v handed to the firewall", a)
			}
		}
		// The slot ports in their range, rotated ones in theirs.
		sp := snap.GetSpa()
		for _, p := range fw.udp {
			if int(p) < int(sp.PortBase) || int(p) >= int(sp.PortBase)+int(sp.PortRange) {
				t.Fatalf("slot port %d outside %d+%d", p, sp.PortBase, sp.PortRange)
			}
		}
		for p, to := range fw.rot {
			if !slices.ContainsFunc(snap.Services, func(s *perimeterv1.Service) bool {
				r := s.Rotation
				return r != nil && uint64(p) >= uint64(r.PortBase) && uint64(p) < uint64(r.PortBase)+uint64(r.PortRange) && uint32(to) == r.TargetPort
			}) {
				t.Fatalf("rotated port %d to %d: no rotation of the snapshot has it", p, to)
			}
		}
	})
}

// checkTaken fails t unless a snapshot the gate took is within its
// bounds: ports and protocols, rotations, the ACME port, the prefixes.
func checkTaken(t *testing.T, snap *perimeterv1.Snapshot) {
	t.Helper()
	ports := slices.Concat(snap.PublicPorts, snap.AdminPorts, snap.RelayPorts, snap.IntegPorts)
	for _, s := range snap.Services {
		ports = append(ports, s.Ports...)
		if r := s.Rotation; r != nil && (uint64(r.PortBase)+uint64(r.PortRange) > 65536 || r.TargetPort > 65535) {
			t.Fatalf("rotation %d+%d to %d taken", r.PortBase, r.PortRange, r.TargetPort)
		}
		if s.Id > 65535 {
			t.Fatalf("service %d taken", s.Id)
		}
	}
	for _, d := range snap.Devices {
		if slices.ContainsFunc(d.Allowed, func(id uint32) bool { return id > 65535 }) {
			t.Fatalf("scope %v taken", d.Allowed)
		}
	}
	if sp := snap.GetSpa(); uint64(sp.PortBase)+uint64(sp.PortRange) > 65536 || sp.PortBase < 1024 || sp.PortRange == 0 {
		t.Fatalf("SPA ports %d+%d taken", sp.PortBase, sp.PortRange)
	}
	for _, p := range ports {
		if p.Proto != "tcp" && p.Proto != "udp" || p.Port > 65535 {
			t.Fatalf("port %q %d taken", p.Proto, p.Port)
		}
	}
	if w := snap.GetAcme(); w != nil && w.Port > 65535 {
		t.Fatalf("ACME port %d taken", w.Port)
	}
	for _, s := range append(slices.Clone(snap.AdminPrefixes), snap.IntegPrefixes...) {
		if _, err := netip.ParsePrefix(s); err != nil {
			t.Fatalf("admin or integration prefix %q taken", s)
		}
	}
	for _, s := range snap.RelayPrefixes {
		if p, err := netip.ParsePrefix(s); err != nil || !p.IsSingleIP() {
			t.Fatalf("relay prefix %q taken", s)
		}
	}
}

// FuzzParseUDP: what NFLOG hands over (a packet from anyone, as the
// kernel logged it) gives an address of the packet's header and a payload
// that is the UDP datagram's, inside the packet, or nothing; never a
// panic.
func FuzzParseUDP(f *testing.F) {
	v4 := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0, 203, 0, 113, 9, 192, 0, 2, 1, 0x30, 0x39, 0x9c, 0x40, 0, 20, 0, 0}
	v4 = append(v4, bytes.Repeat([]byte{0xaa}, 12)...)
	v6 := append([]byte{0x60, 0, 0, 0, 0, 20, 17, 64}, make([]byte, 32)...)
	v6[8], v6[23] = 0x20, 0x09
	v6 = append(v6, 0x30, 0x39, 0x9c, 0x40, 0, 20, 0, 0)
	v6 = append(v6, bytes.Repeat([]byte{0xbb}, 12)...)
	for _, s := range [][]byte{v4, v6, v4[:27], {0x4f}, {0x46, 0, 0, 0, 0, 0, 0, 0, 0, 17}, nil} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, pkt []byte) {
		src, payload, ok := parseUDP(pkt)
		if !ok {
			return
		}
		var hdr int
		switch pkt[0] >> 4 {
		case 4:
			hdr = int(pkt[0]&0x0f) * 4
			if src != netip.AddrFrom4([4]byte(pkt[12:16])) || pkt[9] != 17 {
				t.Fatalf("v4 source %v", src)
			}
		case 6:
			hdr = 40
			if src != netip.AddrFrom16([16]byte(pkt[8:24])) || pkt[6] != 17 {
				t.Fatalf("v6 source %v", src)
			}
		default:
			t.Fatalf("version %d parsed", pkt[0]>>4)
		}
		ulen := int(binary.BigEndian.Uint16(pkt[hdr+4:]))
		if ulen < 8 || hdr+ulen > len(pkt) || !bytes.Equal(payload, pkt[hdr+8:hdr+ulen]) {
			t.Fatalf("payload of %d bytes from a datagram of %d", len(payload), ulen)
		}
	})
}
