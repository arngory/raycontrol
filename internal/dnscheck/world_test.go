package dnscheck

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/net/dns/dnsmessage"
)

// An internet in memory for the checks: the node's front (dnsprobe-v1,
// the apex, the dnstt backend with dnsseal-v1 and dnsauth-v1, masterdns),
// the parent's servers, the host's resolver and public resolvers with
// their habits. The servers here are written from the specs, apart from
// the code they test.

var (
	nodeAddr   = netip.MustParseAddr("203.0.113.7")
	nodeFront  = netip.AddrPortFrom(nodeAddr, 53)
	systemAddr = netip.MustParseAddrPort("192.0.2.53:53")
	parentIPs  = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")}
	elsewhere  = netip.MustParseAddr("198.51.100.9")
)

const (
	testParent = "example.com"
	testNS     = "n7q.example.com"
	dnsttZone  = "t3x.example.com"
	mdnsZone   = "k2p.example.com"
)

// handler answers a query from src; nil: the answer is lost.
type handler func(network string, src netip.Addr, q []byte) []byte

// memNet is the network: servers by address. It records every query the
// checker sends, and two different queries to one server at once.
type memNet struct {
	mu       sync.Mutex
	servers  map[netip.AddrPort]handler
	unreach  map[netip.Addr]bool
	queries  []sentQuery
	inflight map[netip.AddrPort]map[string]int
	overlaps []overlap
}

// overlap is two different queries to one server at once.
type overlap struct {
	to   netip.AddrPort
	what string
}

type sentQuery struct {
	to      netip.AddrPort
	network string
	info    queryInfo
}

func newMemNet() *memNet {
	return &memNet{servers: map[netip.AddrPort]handler{}, unreach: map[netip.Addr]bool{}, inflight: map[netip.AddrPort]map[string]int{}}
}

func (n *memNet) handle(a netip.AddrPort, h handler) {
	n.mu.Lock()
	n.servers[a] = h
	n.mu.Unlock()
}

func (n *memNet) Exchange(ctx context.Context, network string, srv netip.AddrPort, q []byte) ([]byte, error) {
	info, err := readQuery(q)
	if err != nil {
		return nil, err
	}
	key := info.name + "/" + info.q.Type.String()
	n.mu.Lock()
	n.queries = append(n.queries, sentQuery{to: srv, network: network, info: info})
	if n.inflight[srv] == nil {
		n.inflight[srv] = map[string]int{}
	}
	for other, c := range n.inflight[srv] {
		if c > 0 && other != key {
			n.overlaps = append(n.overlaps, overlap{srv, other + " and " + key})
		}
	}
	n.inflight[srv][key]++
	h, unreachable := n.servers[srv], n.unreach[srv.Addr()]
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		n.inflight[srv][key]--
		n.mu.Unlock()
	}()
	if unreachable {
		return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
	}
	if h != nil {
		if r := h(network, nodeAddr, q); r != nil {
			return r, nil
		}
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// sent returns the queries sent to an address.
func (n *memNet) sent(a netip.Addr) []sentQuery {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []sentQuery
	for _, q := range n.queries {
		if q.to.Addr() == a {
			out = append(out, q)
		}
	}
	return out
}

// queryInfo is what a test server reads of a query.
type queryInfo struct {
	h    dnsmessage.Header
	q    dnsmessage.Question
	name string // lower case, no final dot
	raw  string // as it came
	edns int    // 0: no OPT
	opt  bool
	do   bool
}

func readQuery(b []byte) (queryInfo, error) {
	var p dnsmessage.Parser
	var info queryInfo
	var err error
	if info.h, err = p.Start(b); err != nil {
		return info, err
	}
	if info.q, err = p.Question(); err != nil {
		return info, err
	}
	info.raw = strings.TrimSuffix(info.q.Name.String(), ".")
	info.name = strings.ToLower(info.raw)
	if err := p.SkipAllQuestions(); err != nil {
		return info, err
	}
	_ = p.SkipAllAnswers()
	_ = p.SkipAllAuthorities()
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if h.Type == dnsmessage.TypeOPT {
			info.opt, info.edns, info.do = true, int(h.Class), h.DNSSECAllowed()
		}
		_ = p.SkipAdditional()
	}
	return info, nil
}

func dnsName(s string) dnsmessage.Name {
	return dnsmessage.MustNewName(strings.TrimSuffix(s, ".") + ".")
}

func rrHeader(name string, t dnsmessage.Type, ttl uint32) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: dnsName(name), Type: t, Class: dnsmessage.ClassINET, TTL: ttl}
}

func rrSOA(owner, mname string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: rrHeader(owner, dnsmessage.TypeSOA, ttl), Body: &dnsmessage.SOAResource{NS: dnsName(mname),
		MBox: dnsName("hostmaster." + owner), Serial: 1, Refresh: 7200, Retry: 3600, Expire: 1209600, MinTTL: 60}}
}

func rrNS(owner, ns string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: rrHeader(owner, dnsmessage.TypeNS, ttl), Body: &dnsmessage.NSResource{NS: dnsName(ns)}}
}

func rrA(name string, a netip.Addr) dnsmessage.Resource {
	if a.Is4() {
		return dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeA, 300), Body: &dnsmessage.AResource{A: a.As4()}}
	}
	return dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeAAAA, 300), Body: &dnsmessage.AAAAResource{AAAA: a.As16()}}
}

// rrTXT carries data as dnstt does: strings of 255 bytes and the rest.
func rrTXT(name string, data []byte, ttl uint32) dnsmessage.Resource {
	strs := []string{""}
	if len(data) > 0 {
		strs = nil
		for len(data) > 0 {
			n := min(255, len(data))
			strs, data = append(strs, string(data[:n])), data[n:]
		}
	}
	return dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeTXT, ttl), Body: &dnsmessage.TXTResource{TXT: strs}}
}

func rrOPT(size int) dnsmessage.Resource {
	var h dnsmessage.ResourceHeader
	if err := h.SetEDNS0(size, dnsmessage.RCodeSuccess, false); err != nil {
		panic(err)
	}
	return dnsmessage.Resource{Header: h, Body: &dnsmessage.OPTResource{}}
}

// respond answers q: its ID, RD and question as they came.
func respond(q []byte, rcode dnsmessage.RCode, aa bool, an, ns, ar []dnsmessage.Resource) []byte {
	info, err := readQuery(q)
	if err != nil {
		panic(err)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: info.h.ID, Response: true, Authoritative: aa,
		RecursionDesired: info.h.RecursionDesired, RCode: rcode}, Questions: []dnsmessage.Question{info.q},
		Answers: an, Authorities: ns, Additionals: ar}
	b, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return b
}

// The host's resolver: the parent and its servers (the third without glue).
func systemResolver(_ string, _ netip.Addr, q []byte) []byte {
	info, _ := readQuery(q)
	switch {
	case info.name == testParent && info.q.Type == dnsmessage.TypeSOA:
		return respond(q, dnsmessage.RCodeSuccess, false, []dnsmessage.Resource{rrSOA(testParent, "ns1.example.net", 3600)}, nil, nil)
	case info.name == testParent && info.q.Type == dnsmessage.TypeNS:
		return respond(q, dnsmessage.RCodeSuccess, false,
			[]dnsmessage.Resource{rrNS(testParent, "ns1.example.net", 3600), rrNS(testParent, "ns2.example.net", 3600), rrNS(testParent, "ns3.example.net", 3600)},
			nil, []dnsmessage.Resource{rrA("ns1.example.net", parentIPs[0]), rrA("ns2.example.net", parentIPs[1])})
	case info.name == "ns3.example.net" && info.q.Type == dnsmessage.TypeA:
		return respond(q, dnsmessage.RCodeSuccess, false, []dnsmessage.Resource{rrA("ns3.example.net", parentIPs[2])}, nil, nil)
	}
	return respond(q, dnsmessage.RCodeNameError, false, nil, nil, nil)
}

// parentSim is a server of example.com: how it delegates each zone.
type parentSim struct {
	mu   sync.Mutex
	mode map[string]string // right, nons, wrongns, wrongglue, noglue, nxdomain
	rd   []string          // queries that came with RD set
}

func (p *parentSim) set(zone, mode string) {
	p.mu.Lock()
	p.mode[zone] = mode
	p.mu.Unlock()
}

func (p *parentSim) handle(_ string, _ netip.Addr, q []byte) []byte {
	info, _ := readQuery(q)
	p.mu.Lock()
	if info.h.RecursionDesired {
		p.rd = append(p.rd, info.name)
	}
	mode, delegated := p.mode[info.name]
	p.mu.Unlock()
	nodata := func() []byte {
		// The wildcard *.example.com has an A record only.
		return respond(q, dnsmessage.RCodeSuccess, true, nil, []dnsmessage.Resource{rrSOA(testParent, "ns1.example.net", 3600)}, nil)
	}
	switch {
	case delegated && info.q.Type == dnsmessage.TypeNS:
		ns := []dnsmessage.Resource{rrNS(info.name, testNS, 300)}
		glue := []dnsmessage.Resource{rrA(testNS, nodeAddr)}
		switch mode {
		case "nons":
			return nodata()
		case "nxdomain":
			return respond(q, dnsmessage.RCodeNameError, true, nil, []dnsmessage.Resource{rrSOA(testParent, "ns1.example.net", 3600)}, nil)
		case "wrongns":
			ns, glue = []dnsmessage.Resource{rrNS(info.name, "other.example.com", 300)}, []dnsmessage.Resource{rrA("other.example.com", nodeAddr)}
		case "wrongglue":
			glue = []dnsmessage.Resource{rrA(testNS, elsewhere)}
		case "noglue":
			glue = nil
		}
		return respond(q, dnsmessage.RCodeSuccess, false, nil, ns, glue)
	case info.name == testNS && info.q.Type == dnsmessage.TypeA:
		return respond(q, dnsmessage.RCodeSuccess, true, []dnsmessage.Resource{rrA(testNS, nodeAddr)}, nil, nil)
	}
	return nodata()
}

// frontZone is a zone of the front and its backend.
type frontZone struct {
	kind    string // dnstt | masterdns
	ns      string // the apex's NS; "" none
	probe   bool
	sealPad bool   // probe answers padded (seal=required)
	seal    string // the backend's seal mode
	sealKey []byte
	auth    string // the backend's auth mode
	authKey []byte // a device's key it takes
	down    bool   // the backend does not answer
}

// front is niko-server's DNS front with its backends.
type front struct {
	mu    sync.Mutex
	key   []byte // the probe key
	zones map[string]*frontZone
	now   func() time.Time
}

func (f *front) zone(name string) (string, *frontZone) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for z, fz := range f.zones {
		if name == z || strings.HasSuffix(name, "."+z) {
			c := *fz
			return z, &c
		}
	}
	return "", nil
}

func (f *front) handle(_ string, src netip.Addr, q []byte) []byte {
	info, err := readQuery(q)
	if err != nil {
		return nil
	}
	zone, z := f.zone(info.name)
	if z == nil {
		return respond(q, dnsmessage.RCodeRefused, false, nil, nil, nil)
	}
	var opt []dnsmessage.Resource
	if info.opt {
		opt = []dnsmessage.Resource{rrOPT(4096)}
	}
	if z.ns != "" && info.name == zone {
		switch info.q.Type {
		case dnsmessage.TypeSOA:
			return respond(q, dnsmessage.RCodeSuccess, true, []dnsmessage.Resource{rrSOA(info.raw, z.ns, 300)}, nil, opt)
		case dnsmessage.TypeNS:
			return respond(q, dnsmessage.RCodeSuccess, true, []dnsmessage.Resource{rrNS(info.raw, z.ns, 300)}, nil, opt)
		}
		return respond(q, dnsmessage.RCodeSuccess, true, nil, []dnsmessage.Resource{rrSOA(info.raw, z.ns, 60)}, opt)
	}
	if z.probe && f.key != nil {
		if r, ok := f.probe(q, info, zone, z, src); ok {
			return r
		}
	}
	if z.down {
		return nil
	}
	nodata := respond(q, dnsmessage.RCodeSuccess, true, nil, nil, opt)
	if z.kind != "dnstt" || info.q.Type != dnsmessage.TypeTXT {
		return nodata
	}
	payload, err := base32NoPad.DecodeString(strings.ToUpper(strings.ReplaceAll(strings.TrimSuffix(info.name, "."+zone), ".", "")))
	if err != nil {
		return nodata
	}
	var sealedWith []byte
	if z.seal != "off" && z.seal != "" {
		if inner, ok := specOpenQuery(z.sealKey, payload); ok {
			payload, sealedWith = inner, z.sealKey
		} else if z.seal == "required" {
			return nodata
		}
	}
	if z.auth != "off" && z.auth != "" {
		tagged := false
		if len(payload) >= 16 {
			e := uint32(time.Now().Unix() / 600)
			for _, epoch := range []uint32{e, e - 1, e + 1} {
				var eb [4]byte
				binary.BigEndian.PutUint32(eb[:], epoch)
				m := hmac.New(sha256.New, z.authKey)
				m.Write([]byte("dnsauth1"))
				m.Write(eb[:])
				m.Write(payload[8:])
				if hmac.Equal(m.Sum(nil)[:8], payload[:8]) {
					tagged = true
				}
			}
		}
		switch {
		case tagged:
			payload = payload[8:]
		case z.auth == "required":
			return nodata
		}
	}
	if len(payload) < 8 {
		return nodata
	}
	var data []byte // an answer without packets
	if sealedWith != nil {
		data = specSealAnswer(sealedWith, nil, room(info.edns), nil)
	}
	return respond(q, dnsmessage.RCodeSuccess, true, []dnsmessage.Resource{rrTXT(info.raw, data, 60)}, nil, opt)
}

// room is the TXT data an answer to a requester of this EDNS size may
// carry, as dnstt reckons it for the longest name (934 at 1232).
func room(edns int) int { return max(edns, 512) - 298 }

// probe answers dnsprobe-v1 (spec §3, §4) as the front does.
func (f *front) probe(q []byte, info queryInfo, zone string, z *frontZone, src netip.Addr) ([]byte, bool) {
	rawLabel, _, _ := strings.Cut(info.raw, ".")
	label := strings.ToLower(rawLabel)
	if info.name != label+"."+zone || len(label) != 39 || info.q.Type != dnsmessage.TypeTXT {
		return nil, false
	}
	b, err := base32NoPad.DecodeString(strings.ToUpper(label))
	if err != nil || len(b) != 24 || b[0] != 1 || b[1] > 1 {
		return nil, false
	}
	m := hmac.New(sha256.New, f.key)
	m.Write([]byte("dnsprobe-v1 q"))
	m.Write([]byte(zone))
	m.Write(b[:14])
	if !hmac.Equal(m.Sum(nil)[:10], b[14:]) {
		return nil, false
	}
	minute := uint32(f.now().Unix() / 60)
	if sent := binary.BigEndian.Uint32(b[2:6]); sent+2 < minute || sent > minute+2 {
		return nil, false
	}
	size := 35
	if b[1] == 1 && 8+900 <= room(info.edns) {
		size = 900
	}
	plain := make([]byte, size)
	binary.BigEndian.PutUint16(plain[16:], uint16(info.edns))
	if rawLabel != label {
		plain[18] = 1
	}
	a16 := src.As16()
	copy(plain[19:], a16[:])
	tm := hmac.New(sha256.New, f.key)
	tm.Write([]byte("dnsprobe-v1 a"))
	tm.Write(b)
	tm.Write(plain[16:35])
	copy(plain, tm.Sum(nil)[:16])
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	em := hmac.New(sha256.New, f.key)
	em.Write([]byte("dnsprobe-v1 e"))
	specProbeCrypt(em.Sum(nil), b, nonce, plain)
	data := append(nonce, plain...)
	if z.sealPad {
		if target := min((len(data)+63)/64*64, room(info.edns)); target > len(data) {
			fill := make([]byte, target-len(data))
			_, _ = rand.Read(fill)
			data = append(data, fill...)
		}
	}
	var opt []dnsmessage.Resource
	if info.opt {
		opt = []dnsmessage.Resource{rrOPT(4096)}
	}
	return respond(q, dnsmessage.RCodeSuccess, true, []dnsmessage.Resource{rrTXT(info.raw, data, 60)}, nil, opt), true
}

// specProbeCrypt is the probe's keystream (spec §4), written apart from
// probeCrypt.
func specProbeCrypt(ke, b, nonce, p []byte) {
	for i := 0; i*32 < len(p); i++ {
		m := hmac.New(sha256.New, ke)
		m.Write(b)
		m.Write(nonce)
		m.Write(binary.BigEndian.AppendUint32(nil, uint32(i)))
		block := m.Sum(nil)
		for j := 0; j < 32 && i*32+j < len(p); j++ {
			p[i*32+j] ^= block[j]
		}
	}
}

// The node's side of dnsseal-v1 (spec §2–§4), written apart from seal.go.
func specKey(k []byte, label string) []byte {
	m := hmac.New(sha256.New, k)
	m.Write([]byte(label))
	return m.Sum(nil)
}

func specChaCha(key, nonce, p []byte) {
	c, err := chacha20.NewUnauthenticatedCipher(key, append(append([]byte(nil), nonce...), 0, 0, 0, 0))
	if err != nil {
		panic(err)
	}
	c.XORKeyStream(p, p)
}

func specTag(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)[:4]
}

// specOpenQuery takes the seal off a query's payload.
func specOpenQuery(k, payload []byte) ([]byte, bool) {
	if len(payload) < 12 {
		return nil, false
	}
	n, t, c := payload[:8], payload[8:12], payload[12:]
	if !hmac.Equal(t, specTag(specKey(k, "dnsseal-v1 up tag"), n, c)) {
		return nil, false
	}
	inner := append([]byte(nil), c...)
	specChaCha(specKey(k, "dnsseal-v1 up"), n, inner)
	return inner, true
}

// specSealAnswer seals frames into TXT data of at most room bytes, padded
// to a multiple of 64 with R and T; r nil draws R.
func specSealAnswer(k, frames []byte, room int, r []byte) []byte {
	if r == nil {
		r = make([]byte, 8)
		_, _ = rand.Read(r)
	}
	plain := append([]byte(nil), frames...)
	if have := 12 + len(plain); room-have >= 2 {
		target := min((have+2+63)/64*64, room)
		plain = append(plain, make([]byte, target-have)...)
	}
	specChaCha(specKey(k, "dnsseal-v1 down"), r, plain)
	out := append(append([]byte(nil), r...), specTag(specKey(k, "dnsseal-v1 down tag"), r, plain)...)
	return append(out, plain...)
}

// resolverSim is a public resolver and its habits.
type resolverSim struct {
	egress    netip.Addr
	edns      int  // what it advertises to the node; 0: no OPT
	case20    bool // randomises the name's case toward the node
	minimise  bool // asks the apex and the name with NS and A first (RFC 9156)
	dropOver  int  // answers from the node over this many bytes are lost on the way
	tcOver    int  // its answers over UDP over this many bytes come truncated
	servfail  bool
	silent    bool
	forge     bool // answers TXT for the zone itself
	nxdomain  bool // answers NXDOMAIN for the zone itself
	dropFirst bool // the first copy of each query is lost
	node      handler

	mu   sync.Mutex
	seen map[string]bool
}

func (r *resolverSim) handle(network string, _ netip.Addr, q []byte) []byte {
	info, err := readQuery(q)
	if err != nil {
		return nil
	}
	var opt []dnsmessage.Resource
	if info.opt {
		opt = []dnsmessage.Resource{rrOPT(1232)}
	}
	switch {
	case r.silent:
		return nil
	case r.servfail:
		return respond(q, dnsmessage.RCodeServerFailure, false, nil, nil, opt)
	case r.nxdomain:
		return respond(q, dnsmessage.RCodeNameError, false, nil, nil, opt)
	case r.forge:
		junk := make([]byte, 43)
		_, _ = rand.Read(junk)
		return respond(q, dnsmessage.RCodeSuccess, false, []dnsmessage.Resource{rrTXT(info.raw, junk, 60)}, nil, opt)
	}
	if r.dropFirst {
		r.mu.Lock()
		first := !r.seen[info.name+info.q.Type.String()]
		if r.seen == nil {
			r.seen = map[string]bool{}
		}
		r.seen[info.name+info.q.Type.String()] = true
		r.mu.Unlock()
		if first {
			return nil
		}
	}
	upstream := func(name string, t dnsmessage.Type) []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsName(name), Type: t, Class: dnsmessage.ClassINET})
		if r.edns > 0 {
			_ = b.StartAdditionals()
			o := rrOPT(r.edns)
			_ = b.OPTResource(o.Header, dnsmessage.OPTResource{})
		}
		m, _ := b.Finish()
		return r.node("udp", r.egress, m)
	}
	if r.minimise {
		zone := info.name
		if i := strings.Index(zone, "."); i >= 0 && zone != dnsttZone && zone != mdnsZone {
			zone = zone[i+1:]
		}
		for _, step := range []struct {
			name string
			t    dnsmessage.Type
		}{{zone, dnsmessage.TypeNS}, {info.name, dnsmessage.TypeA}} {
			a := upstream(step.name, step.t)
			if a == nil {
				return respond(q, dnsmessage.RCodeServerFailure, false, nil, nil, opt)
			}
			var p dnsmessage.Parser
			if h, err := p.Start(a); err != nil || h.RCode != dnsmessage.RCodeSuccess {
				return respond(q, dnsmessage.RCodeNameError, false, nil, nil, opt) // RFC 8020: nothing below
			}
		}
	}
	name := info.raw
	if r.case20 {
		c := []byte(name)
		for i := 0; i < len(c); i += 2 {
			if c[i] >= 'a' && c[i] <= 'z' {
				c[i] -= 'a' - 'A'
			}
		}
		name = string(c)
	}
	a := upstream(name, info.q.Type)
	if a == nil {
		return respond(q, dnsmessage.RCodeServerFailure, false, nil, nil, opt)
	}
	if r.dropOver > 0 && len(a) > r.dropOver {
		return nil
	}
	var p dnsmessage.Parser
	h, err := p.Start(a)
	if err != nil || h.RCode == dnsmessage.RCodeRefused {
		return respond(q, dnsmessage.RCodeServerFailure, false, nil, nil, opt)
	}
	_ = p.SkipAllQuestions()
	an, _ := p.AllAnswers()
	ns, _ := p.AllAuthorities()
	for i := range an {
		if strings.EqualFold(an[i].Header.Name.String(), name+".") {
			an[i].Header.Name = info.q.Name
		}
	}
	out := respond(q, h.RCode, false, an, ns, opt)
	if network == "udp" && r.tcOver > 0 && len(out) > r.tcOver {
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: info.h.ID, Response: true, Truncated: true, RecursionDesired: info.h.RecursionDesired},
			Questions: []dnsmessage.Question{info.q}}
		out, _ = m.Pack()
	}
	return out
}

// world is a node with a dnstt zone (seal optional) and a masterdns zone,
// both delegated to it, three public resolvers, and the checker on the
// node.
type world struct {
	net       *memNet
	front     *front
	parents   []*parentSim
	key       []byte
	sealKey   []byte
	resolvers map[string]*resolverSim
	checker   *Checker
}

func seq(from byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = from + byte(i)
	}
	return b
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{net: newMemNet(), key: seq(0, 32), sealKey: seq(0x40, 32), resolvers: map[string]*resolverSim{}}
	w.front = &front{key: w.key, now: time.Now, zones: map[string]*frontZone{
		dnsttZone: {kind: "dnstt", ns: testNS, probe: true, seal: "optional", sealKey: w.sealKey, auth: "off"},
		mdnsZone:  {kind: "masterdns"},
	}}
	w.net.handle(nodeFront, w.front.handle)
	w.net.handle(systemAddr, systemResolver)
	for _, ip := range parentIPs {
		p := &parentSim{mode: map[string]string{dnsttZone: "right", mdnsZone: "right"}}
		w.parents = append(w.parents, p)
		w.net.handle(netip.AddrPortFrom(ip, 53), p.handle)
	}
	w.resolver("8.8.8.8", &resolverSim{egress: netip.MustParseAddr("172.253.0.1"), edns: 1400, case20: true})
	w.resolver("1.1.1.1", &resolverSim{egress: netip.MustParseAddr("162.158.0.1"), edns: 1232})
	w.resolver("9.9.9.9", &resolverSim{egress: netip.MustParseAddr("74.63.16.1"), edns: 1232, minimise: true})
	w.checker = &Checker{Net: w.net, System: []netip.AddrPort{systemAddr}, Local: func(a netip.Addr) bool { return a == nodeAddr },
		Retry: 40 * time.Millisecond, GiveUp: 150 * time.Millisecond, Round: 5 * time.Second}
	return w
}

// resolver puts a resolver at ip, leading to the node.
func (w *world) resolver(ip string, r *resolverSim) {
	r.node = w.front.handle
	w.resolvers[ip] = r
	w.net.handle(netip.AddrPortFrom(netip.MustParseAddr(ip), 53), r.handle)
}

func (w *world) zones() []Zone {
	return []Zone{
		{Service: "dns", Kind: "dnstt", Name: dnsttZone, NS: testNS, Host: nodeAddr.String(), ProbeKey: w.key, Seal: "optional", SealKey: w.sealKey, Auth: "off"},
		{Service: "mdns", Kind: "masterdns", Name: mdnsZone, NS: testNS, Host: nodeAddr.String()},
	}
}

func mustResolvers(t *testing.T, items ...string) []Resolver {
	t.Helper()
	rs, err := ParseResolvers(items)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}
