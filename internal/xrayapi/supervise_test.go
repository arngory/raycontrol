package xrayapi_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/arngory/raycontrol/internal/dnscheck"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/testca"
)

// TestSupervisedNode runs a node as rayd serve -supervise does it without
// systemd (CI, containers): REALITY with its site, Hysteria2 (hy2-obfs)
// and Yggdrasil with inner behind the front, all from the rendered files. A client then
// probes through both tunnels, and asks link directly from the address of
// its Hysteria2 session: its own session is listed (R4-20).
func TestSupervisedNode(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	niko := os.Getenv("NIKO_SERVER_BIN")
	if bin == "" || niko == "" {
		t.Skip("set XRAY_BIN and NIKO_SERVER_BIN (v0.7 or later)")
	}
	// The front and REALITY take port 443 as on a node.
	for _, network := range []string{"tcp", "udp"} {
		var err error
		if network == "tcp" {
			var ln net.Listener
			if ln, err = net.Listen("tcp", ":443"); err == nil {
				ln.Close()
			}
		} else {
			var pc net.PacketConn
			if pc, err = net.ListenPacket("udp", ":443"); err == nil {
				pc.Close()
			}
		}
		if err != nil {
			t.Skipf("port 443 (%s): %v; run as root or with net.ipv4.ip_unprivileged_port_start=0", network, err)
		}
	}
	ip := hostAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir := t.TempDir()
	rayd := os.Getenv("RAYD_BIN")
	if rayd == "" {
		rayd = filepath.Join(dir, "rayd")
		if out, err := exec.Command("go", "build", "-o", rayd, "github.com/arngory/raycontrol/cmd/rayd").CombinedOutput(); err != nil {
			t.Fatalf("go build rayd: %v\n%s", err, out)
		}
	}

	// The node's state, as rayctl would make it.
	db := filepath.Join(dir, "rayd.db")
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Init(ctx, st, provision.Options{Host: ip.String(), Domain: "example.test"}); err != nil {
		t.Fatal(err)
	}
	reality, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	hy, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2o", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// Yggdrasil brings inner with it: both run, behind the front's TCP 443.
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "yggdrasil", Name: "ygg", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// dnstt behind the front's UDP 53, which answers dnsprobe-v1 itself
	// (niko-server v0.8.3).
	dnsSvc, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var dnsZone struct {
		Zone string `json:"zone"`
	}
	json.Unmarshal([]byte(dnsSvc.Settings), &dnsZone)
	// The site's certificate from a test CA (rayctl service cert).
	ca, err := testca.New([]string{"*.example.test"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.SetCertificate(ctx, st, "site", ca.ChainPEM, ca.KeyPEM, time.Now()); err != nil {
		t.Fatal(err)
	}
	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{reality.ID, hy.ID})
	dev, key, err := st.CreateDevice(ctx, "alice", "laptop", "user")
	if err != nil {
		t.Fatal(err)
	}
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	probeKey, err := st.DNSProbeKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	linkOf := func(name string) string {
		i := slices.IndexFunc(profiles, func(p sub.Profile) bool { return p.Name == name })
		if i < 0 {
			t.Fatalf("no profile %s in %v", name, profiles)
		}
		return profiles[i].Link
	}
	subSvc, _ := st.ServiceByName(ctx, provision.SubscriptionService)
	subSecrets, _ := st.ServiceSecrets(ctx, subSvc.ID)
	pin := mustPin(t, subSecrets[provision.SecretTLSCert])
	dnsTargets, err := provision.DNSCheckTargets(ctx, st)
	if err != nil || len(dnsTargets) != 1 {
		t.Fatalf("DNS check targets %v %v", dnsTargets, err)
	}
	st.Close()

	// rayd and its data plane, short paths: unix sockets take 107 bytes.
	run, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(run)
	cmd := exec.Command(rayd, "serve", "-db", db, "-socket", filepath.Join(run, "rayd.sock"),
		"-rendered", filepath.Join(dir, "rendered"), "-run", filepath.Join(run, "run"),
		"-supervise", "-xray", bin, "-niko-server", niko, "-acme-directory", "", "-dns-check", "0")
	// Hysteria2's backend reaches test addresses only with this.
	cmd.Env = append(os.Environ(), "NIKO_SERVER_UNSAFE_ANY_DESTINATION=1")
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Error("rayd did not stop on SIGTERM")
		}
		if t.Failed() || testing.Verbose() {
			t.Logf("rayd:\n%s", logs.String())
		}
	}()

	// Every unit of the plan runs: its socket is there.
	paths := render.Paths{Run: filepath.Join(run, "run")}
	for _, sock := range []string{paths.InnerSocket("inner"), paths.FrontSocket("ygg", "fd"),
		paths.StatsSocket("hy2o"), paths.SiteSocket("site")} {
		for i := 0; ; i++ {
			if _, err := os.Stat(sock); err == nil {
				break
			}
			if i == 100 {
				t.Fatalf("no %s", sock)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// The front answers a resolver check with the subscription's key.
	if dnsZone.Zone == "" {
		t.Fatalf("no zone in %s", dnsSvc.Settings)
	}
	var probeAnswer []byte
	for range 50 {
		if probeAnswer, err = dnsProbe(net.JoinHostPort(ip.String(), "53"), probeKey, dnsZone.Zone); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	// What the node saw: EDNS 1232, no 0x20, this host's address.
	if err != nil || binary.BigEndian.Uint16(probeAnswer[16:18]) != 1232 || probeAnswer[18] != 0 ||
		netip.AddrFrom16([16]byte(probeAnswer[19:35])).Unmap() != ip {
		t.Fatalf("dnsprobe: %x %v", probeAnswer, err)
	}

	// The node's own check of the zone (internal/dnscheck) on the real
	// front: the apex with the NS name, a probe, and a poll of the dnstt
	// backend behind it, once the backend is up.
	checker := &dnscheck.Checker{}
	var zone dnscheck.ZoneResult
	for range 30 {
		zone = checker.Check(ctx, dnsTargets, nil, false).Zones[0]
		if zone.Front.State == dnscheck.OK && zone.Backend.State == dnscheck.OK {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if want := "SOA and probe on " + net.JoinHostPort(ip.String(), "53"); zone.Front.Detail != want || zone.Backend.State != dnscheck.OK ||
		!strings.HasPrefix(zone.Backend.Detail, "poll answered in") {
		t.Fatalf("the node's check of its zone: front %+v, backend %+v", zone.Front, zone.Backend)
	}
	checkThroughResolvers(t, ctx, ip, dnsTargets[0])

	probeVia := func(name string, socksPort int) {
		t.Helper()
		sc := sub.Client{Addr: net.JoinHostPort(render.ProbeName, "443"), Pin: pin, DeviceID: dev.ID, DeviceKey: key}
		hc := sc.HTTP()
		proxy, _ := url.Parse("socks5h://127.0.0.1:" + strconv.Itoa(socksPort))
		hc.Transport.(*http.Transport).Proxy = http.ProxyURL(proxy)
		c := probe.Client{HTTP: hc, Base: "https://" + sc.Addr, Authorize: sc.Authorize}
		var down probe.Transfer
		var err error
		for range 60 {
			if down, err = c.Down(ctx, 1<<20); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil || down.Server.Bytes != 1<<20 {
			t.Fatalf("probe through %s: %+v %v", name, down, err)
		}
	}

	// Through REALITY (self-steal on the site) into inner.
	port, stop := realitySocks(t, bin, linkOf("reality"), "")
	probeVia("REALITY", port)
	stop()

	// Through Hysteria2 behind the front, then link directly from the same
	// address: the session is the device's user's own.
	port, stop = hysteriaSocks(t, bin, linkOf("hy2o"), "", "")
	defer stop()
	probeVia("Hysteria2", port)
	sc := sub.Client{Addr: net.JoinHostPort(ip.String(), strconv.Itoa(m.SubscriptionPort())), Pin: pin, DeviceID: dev.ID, DeviceKey: key}
	c := probe.Client{HTTP: sc.HTTP(), Base: "https://" + sc.Addr, Authorize: sc.Authorize}
	ls, err := c.Link(ctx)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	var stats struct {
		Connections int
		Own         []struct {
			RTTus uint64 `json:"rtt_us"`
		}
	}
	raw := ls.Hysteria2[strconv.FormatInt(hy.ID, 10)]
	if err := json.Unmarshal(raw, &stats); err != nil || stats.Connections < 1 || len(stats.Own) < 1 || stats.Own[0].RTTus == 0 {
		t.Fatalf("link from %s: %s (%+v, %v)", ls.Address, raw, stats, err)
	}
}

// checkThroughResolvers checks the zone as rayd does, through resolvers of
// the test's own that forward to the real front as public ones do: EDNS
// 1232 with 0x20, 1220 and 512 toward the node. The parent is the test's
// too: a server of example.test on 127.0.0.2:53, beside the front's
// wildcard socket, delegates the zone to the node.
func checkThroughResolvers(t *testing.T, ctx context.Context, ip netip.Addr, zone dnscheck.Zone) {
	t.Helper()
	parent, err := listenUDPReuse("127.0.0.2:53")
	if err != nil {
		t.Logf("no parent of the test's own on 127.0.0.2:53 (%v): the check through resolvers is skipped", err)
		return
	}
	defer parent.Close()
	go serveDNS(parent, func(q []byte) []byte {
		return dnsAnswer(q, func(qq dnsmessage.Question, m *dnsmessage.Message) {
			if qq.Type == dnsmessage.TypeNS && strings.EqualFold(qq.Name.String(), zone.Name+".") {
				m.Authorities = []dnsmessage.Resource{dnsRR(zone.Name, &dnsmessage.NSResource{NS: dnsmessage.MustNewName(zone.NS + ".")})}
				m.Additionals = []dnsmessage.Resource{dnsRR(zone.NS, &dnsmessage.AResource{A: ip.As4()})}
			}
		})
	})
	// The host's resolver, which finds the parent.
	system, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer system.Close()
	go serveDNS(system, func(q []byte) []byte {
		return dnsAnswer(q, func(qq dnsmessage.Question, m *dnsmessage.Message) {
			switch {
			case qq.Type == dnsmessage.TypeSOA && qq.Name.String() == "example.test.":
				m.Answers = []dnsmessage.Resource{dnsRR("example.test", &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns1.example.test."),
					MBox: dnsmessage.MustNewName("hostmaster.example.test."), MinTTL: 60})}
			case qq.Type == dnsmessage.TypeNS && qq.Name.String() == "example.test.":
				m.Answers = []dnsmessage.Resource{dnsRR("example.test", &dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns1.example.test.")})}
				m.Additionals = []dnsmessage.Resource{dnsRR("ns1.example.test", &dnsmessage.AResource{A: [4]byte{127, 0, 0, 2}})}
			}
		})
	})
	var names []string
	for _, r := range []struct {
		edns   uint16
		case20 bool
	}{{1232, true}, {1220, false}, {512, false}} {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		go serveDNS(pc, func(q []byte) []byte { return forward(q, netip.AddrPortFrom(ip, 53), r.edns, r.case20) })
		names = append(names, "udp:"+pc.LocalAddr().String())
	}
	resolvers, err := dnscheck.ParseResolvers(names)
	if err != nil {
		t.Fatal(err)
	}
	checker := &dnscheck.Checker{System: []netip.AddrPort{netip.MustParseAddrPort(system.LocalAddr().String())}}
	z := checker.Check(ctx, []dnscheck.Zone{zone}, resolvers, false).Zones[0]
	if !z.Delegated || z.Parent.State != dnscheck.OK || z.Err() != nil {
		t.Fatalf("through resolvers: parent %+v, err %v", z.Parent, z.Err())
	}
	for i, want := range []struct {
		large dnscheck.State
		edns  int
		mixed bool
	}{{dnscheck.OK, 1232, true}, {dnscheck.OK, 1220, false}, {dnscheck.Warn, 512, false}} {
		r := z.Resolvers[i]
		if r.SOA.State != dnscheck.OK || r.Small.State != dnscheck.OK || r.Large.State != want.large || r.EDNS != want.edns ||
			r.Mixed != want.mixed || r.Egress != ip {
			t.Errorf("through %s: %+v", r.Resolver, r)
		}
	}
	if got := z.Summary(); got != "delegated; 3/3 resolvers; large 2/3; EDNS 512–1232" {
		t.Errorf("summary %q", got)
	}
}

// listenUDPReuse listens with SO_REUSEADDR, as the front does: an address
// of its own on its port.
func listenUDPReuse(addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1) }); err != nil {
			return err
		}
		return serr
	}}
	return lc.ListenPacket(context.Background(), "udp", addr)
}

// serveDNS answers each datagram on pc until it is closed; nil: no answer.
func serveDNS(pc net.PacketConn, answer func([]byte) []byte) {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if r := answer(append([]byte(nil), buf[:n]...)); r != nil {
			_, _ = pc.WriteTo(r, from)
		}
	}
}

// dnsAnswer answers q with what fill puts in: NOERROR, the question as it
// came; fill nil-answers stay NODATA.
func dnsAnswer(q []byte, fill func(dnsmessage.Question, *dnsmessage.Message)) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	qq, err := p.Question()
	if err != nil {
		return nil
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired},
		Questions: []dnsmessage.Question{qq}}
	fill(qq, &m)
	b, _ := m.Pack()
	return b
}

func dnsRR(name string, body dnsmessage.ResourceBody) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name + "."), Class: dnsmessage.ClassINET, TTL: 300}, Body: body}
}

// forward is a resolver: the question to the node without RD, with its own
// EDNS size and, with case20, the name's case mixed (0x20); the answer back
// to the client under the client's question and ID.
func forward(q []byte, node netip.AddrPort, edns uint16, case20 bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	qq, err := p.Question()
	if err != nil {
		return nil
	}
	up := qq
	if case20 {
		name := []byte(qq.Name.String())
		for i := 0; i < len(name); i += 2 {
			if name[i] >= 'a' && name[i] <= 'z' {
				name[i] -= 'a' - 'A'
			}
		}
		up.Name = dnsmessage.MustNewName(string(name))
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID ^ 0x5a5a})
	_ = b.StartQuestions()
	_ = b.Question(up)
	_ = b.StartAdditionals()
	var opt dnsmessage.ResourceHeader
	_ = opt.SetEDNS0(int(edns), dnsmessage.RCodeSuccess, false)
	_ = b.OPTResource(opt, dnsmessage.OPTResource{})
	uq, err := b.Finish()
	if err != nil {
		return nil
	}
	c, err := net.Dial("udp", node.String())
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(uq); err != nil {
		return nil
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil
	}
	var a dnsmessage.Message
	if err := a.Unpack(buf[:n]); err != nil {
		return nil
	}
	for i := range a.Answers {
		if strings.EqualFold(a.Answers[i].Header.Name.String(), qq.Name.String()) {
			a.Answers[i].Header.Name = qq.Name
		}
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true,
		RCode: a.RCode}, Questions: []dnsmessage.Question{qq}, Answers: a.Answers, Authorities: a.Authorities}
	var cliOpt dnsmessage.ResourceHeader
	_ = cliOpt.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
	m.Additionals = []dnsmessage.Resource{{Header: cliOpt, Body: &dnsmessage.OPTResource{}}}
	out, _ := m.Pack()
	return out
}

// hostAddr is an address of this host other than loopback: the node's, and
// the one the test's client comes from.
func hostAddr(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() {
			return p.Addr()
		}
	}
	t.Skip("no address other than loopback")
	return netip.Addr{}
}

// dnsProbe checks a resolver as a client does (docs/spec/dnsprobe-v1.md):
// a small probe sent straight to the node; it returns the decrypted
// plaintext after checking the answer's shape (as dnstt's) and its token.
func dnsProbe(server string, key []byte, zone string) ([]byte, error) {
	var b [24]byte
	b[0] = 1
	binary.BigEndian.PutUint32(b[2:6], uint32(time.Now().Unix()/60))
	if _, err := rand.Read(b[6:14]); err != nil {
		return nil, err
	}
	mac := func(k []byte, parts ...[]byte) []byte {
		m := hmac.New(sha256.New, k)
		for _, p := range parts {
			m.Write(p)
		}
		return m.Sum(nil)
	}
	copy(b[14:], mac(key, []byte("dnsprobe-v1 q"), []byte(zone), b[:14])[:10])
	label := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
	q := []byte{0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1}
	for _, l := range strings.Split(label+"."+zone, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 16, 0, 1)                      // TXT IN
	q = append(q, 0, 0, 41, 4, 0xd0, 0, 0, 0, 0, 0, 0) // OPT 1232
	c, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	r := make([]byte, 4096)
	n, err := c.Read(r)
	if err != nil {
		return nil, err
	}
	r = r[:n]
	questionEnd := 12 + len(label) + 1 + len(zone) + 2 + 4
	// As dnstt answers: QR and AA, one TXT with TTL 60.
	if n < questionEnd+12 || binary.BigEndian.Uint16(r[2:4]) != 0x8400 || binary.BigEndian.Uint16(r[6:8]) != 1 ||
		binary.BigEndian.Uint32(r[questionEnd+6:questionEnd+10]) != 60 {
		return nil, fmt.Errorf("answer of %d bytes: % x", n, r[:min(n, 16)])
	}
	rd := r[questionEnd+12 : questionEnd+12+int(binary.BigEndian.Uint16(r[questionEnd+10:questionEnd+12]))]
	var data []byte
	for len(rd) > 0 {
		l := int(rd[0])
		data, rd = append(data, rd[1:1+l]...), rd[1+l:]
	}
	// The answer's nonce, then the ciphertext.
	if len(data) < 8 {
		return nil, fmt.Errorf("TXT data of %d bytes", len(data))
	}
	nonce, plain := data[:8], data[8:]
	enc := mac(key, []byte("dnsprobe-v1 e"))
	for i := 0; i < len(plain); i += 32 {
		block := mac(enc, b[:], nonce, binary.BigEndian.AppendUint32(nil, uint32(i/32)))
		for j := 0; j < 32 && i+j < len(plain); j++ {
			plain[i+j] ^= block[j]
		}
	}
	if len(plain) != 35 || !bytes.Equal(plain[:16], mac(key, []byte("dnsprobe-v1 a"), b[:], plain[16:35])[:16]) {
		return plain, fmt.Errorf("token or length: %x", plain)
	}
	return plain, nil
}
