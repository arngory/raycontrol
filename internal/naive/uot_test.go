package naive

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/site"
)

// uotServer is a naive server over HTTP/2 whose UDP may reach loopback (and
// 127.0.0.1 only: 127.0.0.2 stands for what is not allowed), with the name
// echo.test for 127.0.0.1.
func uotServer(t *testing.T, idle time.Duration, opts ...func(*http.Transport)) (*Server, func(host string) (*http.Response, *paddedStream, func())) {
	t.Helper()
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsers(t, users, "secret-one")
	answer, _ := site.Responder(site.Answer404, "")
	var d net.Dialer
	h := &Server{Users: &Users{Path: users}, Answer: answer, Dial: d.DialContext, Log: slog.New(slog.DiscardHandler),
		Allow: func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") || a == netip.IPv6Loopback() },
		Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
			switch name {
			case "echo.test":
				return []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}, nil
			case "trap.test":
				return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil
			}
			return nil, errors.New("no such name")
		},
		uotIdle: idle}
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2"},
	}}
	for _, o := range opts {
		o(tr)
	}
	t.Cleanup(tr.CloseIdleConnections)
	connect := func(host string) (*http.Response, *paddedStream, func()) {
		t.Helper()
		pr, pw := io.Pipe()
		req, _ := http.NewRequest(http.MethodConnect, srv.URL, pr)
		req.Host = host
		req.Header.Set("Padding", paddingHeader())
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:secret-one")))
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT %s: %s", host, resp.Status)
		}
		return resp, &paddedStream{r: resp.Body, w: pw}, func() { pw.Close(); resp.Body.Close() }
	}
	return h, connect
}

// udpEcho answers each packet from its own port, and first from another
// one, which the client never sent to.
func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	ap := udpEchoAt(t, netip.MustParseAddr("127.0.0.1"))
	if !ap.IsValid() {
		t.Fatal("no UDP on 127.0.0.1")
	}
	return ap
}

// udpEchoAt is udpEcho on another address; invalid when the host has none
// such (IPv6).
func udpEchoAt(t *testing.T, at netip.Addr) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(at, 0)))
	if err != nil {
		t.Log(err)
		return netip.AddrPort{}
	}
	other, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(at, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close(); other.Close() })
	go func() {
		buf := make([]byte, 70000)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = other.WriteToUDPAddrPort(append([]byte("stranger:"), buf[:n]...), from)
			_, _ = pc.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// udpTrap counts what reaches an address the server must not send to.
func udpTrap(t *testing.T, at string) (netip.AddrPort, func() int) {
	t.Helper()
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(at)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	var got atomic.Int32
	go func() {
		buf := make([]byte, 70000)
		for {
			if _, _, err := pc.ReadFromUDPAddrPort(buf); err != nil {
				return
			}
			got.Add(1)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort(), func() int { return int(got.Load()) }
}

func v6(ap netip.AddrPort) []byte {
	a := ap.Addr().As16()
	b := append([]byte{0x01}, a[:]...)
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

func socksName(name string, port uint16) []byte {
	b := append([]byte{0x03, byte(len(name))}, name...)
	return binary.BigEndian.AppendUint16(b, port)
}

// eventually waits up to 5 s for cond.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(end) {
			t.Fatal(what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (l *uotLimits) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

func socksAddr(ap netip.AddrPort) []byte {
	b := []byte{0x01}
	b = append(b, ap.Addr().AsSlice()...)
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

func packet(addr []byte, data []byte) []byte {
	b := append([]byte(nil), addr...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func uotName(name string, port uint16) []byte {
	b := append([]byte{0x02, byte(len(name))}, name...)
	return binary.BigEndian.AppendUint16(b, port)
}

// readPacket reads one packet back, within 5 s: its source (when not
// connected) and data.
func readPacket(t *testing.T, r io.Reader, connected bool) (netip.AddrPort, []byte) {
	t.Helper()
	type packet struct {
		from netip.AddrPort
		data []byte
		err  error
	}
	got := make(chan packet, 1)
	go func() {
		var p packet
		if !connected {
			var kind [1]byte
			if _, p.err = io.ReadFull(r, kind[:]); p.err != nil {
				got <- p
				return
			}
			n := map[byte]int{0x00: 4, 0x01: 16}[kind[0]]
			if n == 0 {
				p.err = fmt.Errorf("source type %#x", kind[0])
				got <- p
				return
			}
			b := make([]byte, n+2)
			if _, p.err = io.ReadFull(r, b); p.err != nil {
				got <- p
				return
			}
			a, _ := netip.AddrFromSlice(b[:n])
			p.from = netip.AddrPortFrom(a, binary.BigEndian.Uint16(b[n:]))
		}
		var l [2]byte
		if _, p.err = io.ReadFull(r, l[:]); p.err == nil {
			p.data = make([]byte, binary.BigEndian.Uint16(l[:]))
			_, p.err = io.ReadFull(r, p.data)
		}
		got <- p
	}()
	select {
	case p := <-got:
		if p.err != nil {
			t.Fatal(p.err)
		}
		return p.from, p.data
	case <-time.After(5 * time.Second):
		t.Fatal("no packet came back")
		return netip.AddrPort{}, nil
	}
}

// reset reports whether the stream ended with an error (a reset), not a
// clean end.
func reset(t *testing.T, r io.Reader) bool {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, r); done <- err }()
	select {
	case err := <-done:
		return err != nil
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end")
		return false
	}
}

// UDP over TCP v2 (spec/naive-uot-v1.md): both modes, names, what is not
// allowed, answers from strangers, resets, idle time, limits.
func TestUoT(t *testing.T) {
	echo := udpEcho(t)
	// 127.0.0.2 is not allowed: nothing may reach it, whatever the form.
	trap, trapped := udpTrap(t, "127.0.0.2:0")
	h, connect := uotServer(t, 300*time.Millisecond)
	v4 := func(ap netip.AddrPort) []byte {
		b := append([]byte{0x00}, ap.Addr().AsSlice()...)
		return binary.BigEndian.AppendUint16(b, ap.Port())
	}

	// isConnect = 0: each packet its own address.
	_, s, done := connect(UoTName + ":0")
	if _, err := s.Write(append([]byte{0}, socksAddr(netip.MustParseAddrPort("0.0.0.0:0"))...)); err != nil {
		t.Fatal(err)
	}
	for i, data := range [][]byte{[]byte("one"), bytes.Repeat([]byte("x"), uotMaxAnswer), {}} {
		if _, err := s.Write(packet(v4(echo), data)); err != nil {
			t.Fatal(err)
		}
		// The stranger's packet first, never passed on: the echo is the
		// first that comes.
		from, got := readPacket(t, s, false)
		if from != echo || !bytes.Equal(got, data) {
			t.Fatalf("packet %d: from %s, %d bytes", i, from, len(got))
		}
	}
	// The longest a client may send goes out; its answer, longer than a
	// client takes, does not come back; the stream lives on.
	if _, err := s.Write(packet(v4(echo), bytes.Repeat([]byte("y"), uotMaxPayload))); err != nil {
		t.Fatal(err)
	}
	// By name: the first allowed address (127.0.0.2 is not).
	if _, err := s.Write(packet(uotName("echo.test", echo.Port()), []byte("named"))); err != nil {
		t.Fatal(err)
	}
	if from, got := readPacket(t, s, false); from != echo || string(got) != "named" {
		t.Fatalf("by name: %s %q", from, got)
	}
	// IPv4 in IPv6 is IPv4.
	mapped := netip.AddrPortFrom(netip.AddrFrom16(echo.Addr().As16()), echo.Port())
	if _, err := s.Write(packet(v6(mapped), []byte("mapped"))); err != nil {
		t.Fatal(err)
	}
	if from, got := readPacket(t, s, false); from != echo || string(got) != "mapped" {
		t.Fatalf("mapped: %s %q", from, got)
	}
	// Not allowed (as such, mapped, by name), no such name, port 0:
	// dropped, the stream lives on.
	for _, addr := range [][]byte{v4(trap), v6(netip.AddrPortFrom(netip.AddrFrom16(trap.Addr().As16()), trap.Port())),
		uotName("trap.test", trap.Port()), uotName("nowhere.test", 53), v4(netip.AddrPortFrom(echo.Addr(), 0))} {
		if _, err := s.Write(packet(addr, []byte("dropped"))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Write(packet(v4(echo), []byte("still"))); err != nil {
		t.Fatal(err)
	}
	if _, got := readPacket(t, s, false); string(got) != "still" {
		t.Fatalf("after the dropped: %q", got)
	}
	// Idle: the stream ends by itself, cleanly.
	if reset(t, s) {
		t.Fatal("an idle stream was reset")
	}
	done()

	// An IPv6 destination, its answer's source as 0x01.
	if echo6 := udpEchoAt(t, netip.IPv6Loopback()); echo6.IsValid() {
		_, s, done = connect(UoTName + ":0")
		_, _ = s.Write(append([]byte{0}, socksAddr(netip.MustParseAddrPort("0.0.0.0:0"))...))
		if _, err := s.Write(packet(v6(echo6), []byte("six"))); err != nil {
			t.Fatal(err)
		}
		if from, got := readPacket(t, s, false); from != echo6 || string(got) != "six" {
			t.Fatalf("IPv6: %s %q", from, got)
		}
		done()
	}

	// isConnect = 1: one destination, no addresses in the packets; by
	// address and by name.
	for _, dest := range [][]byte{socksAddr(echo), socksName("echo.test", echo.Port())} {
		_, s, done = connect(UoTName + ":443")
		if _, err := s.Write(append([]byte{1}, dest...)); err != nil {
			t.Fatal(err)
		}
		for _, data := range []string{"a", "bb", "ccc"} {
			if _, err := s.Write(packet(nil, []byte(data))); err != nil {
				t.Fatal(err)
			}
			if _, got := readPacket(t, s, true); string(got) != data {
				t.Fatalf("connected: %q", got)
			}
		}
		done()
	}

	// Resets: a destination not allowed, a packet too long, a bad request,
	// v1, a TCP destination that does not answer.
	for name, c := range map[string]struct {
		host string
		send []byte
	}{
		"connected, not allowed":          {UoTName + ":0", append([]byte{1}, socksAddr(trap)...)},
		"connected, by name, not allowed": {UoTName + ":0", append([]byte{1}, socksName("trap.test", trap.Port())...)},
		"too long": {UoTName + ":0", append(append([]byte{0}, socksAddr(netip.MustParseAddrPort("0.0.0.0:0"))...),
			binary.BigEndian.AppendUint16(v4(echo), uotMaxPayload+1)...)},
		"isConnect 2":      {UoTName + ":0", []byte{2, 0x01, 0, 0, 0, 0, 0, 0}},
		"address type":     {UoTName + ":0", []byte{0, 0x09}},
		"v1":               {uotLegacyName + ":0", []byte("x")},
		"tcp, no listener": {"127.0.0.1:1", []byte("x")},
	} {
		_, s, done := connect(c.host)
		_, _ = s.Write(c.send)
		if !reset(t, s) {
			t.Errorf("%s: not reset", name)
		}
		done()
	}
	if n := trapped(); n != 0 {
		t.Errorf("%d packets reached an address not allowed", n)
	}
	eventually(t, "streams still counted", func() bool { return h.uot.count() == 0 })
}

// A user's streams: uotPerUser at most, the next one reset; their slots
// come back.
func TestUoTStreamLimit(t *testing.T) {
	h, connect := uotServer(t, time.Minute)
	var dones []func()
	for range uotPerUser {
		_, _, done := connect(UoTName + ":0")
		dones = append(dones, done)
	}
	eventually(t, "streams not counted", func() bool { return h.uot.count() == uotPerUser })
	_, s, done := connect(UoTName + ":0")
	if !reset(t, s) {
		t.Error("over the user's limit: not reset")
	}
	done()
	for _, done := range dones {
		done()
	}
	eventually(t, "slots not given back", func() bool { return h.uot.count() == 0 })
}

// A client that never says where to does not hold its slot past the idle
// time either.
func TestUoTSilentClient(t *testing.T) {
	h, connect := uotServer(t, 300*time.Millisecond)
	_, _, done := connect(UoTName + ":0")
	defer done()
	eventually(t, "stream not counted", func() bool { return h.uot.count() == 1 })
	eventually(t, "a silent stream held its slot", func() bool { return h.uot.count() == 0 })
}

// A client that stops reading does not hold its stream past the idle time:
// the write that waits on it fails.
func TestUoTStuckClient(t *testing.T) {
	echo := udpEcho(t)
	h, connect := uotServer(t, 300*time.Millisecond, func(tr *http.Transport) {
		tr.HTTP2 = &http.HTTP2Config{MaxReceiveBufferPerStream: 64 << 10, MaxReceiveBufferPerConnection: 64 << 10}
	})
	_, s, done := connect(UoTName + ":0")
	defer done()
	go func() {
		_, _ = s.Write(append([]byte{0}, socksAddr(netip.MustParseAddrPort("0.0.0.0:0"))...))
		p := packet(append([]byte{0x00}, binary.BigEndian.AppendUint16(echo.Addr().AsSlice(), echo.Port())...), bytes.Repeat([]byte("z"), uotMaxAnswer))
		for range 1000 { // far more than the client's window
			if _, err := s.Write(p); err != nil {
				return
			}
		}
	}()
	eventually(t, "answers not sent", func() bool { return h.uot.count() == 1 })
	eventually(t, "a stuck stream held its slot", func() bool { return h.uot.count() == 0 })
}

func TestUoTLimits(t *testing.T) {
	var l uotLimits
	a, b := [32]byte{1}, [32]byte{2}
	for range uotPerUser {
		if !l.take(a) {
			t.Fatal("under the user's limit")
		}
	}
	if l.take(a) {
		t.Fatal("over the user's limit")
	}
	if !l.take(b) {
		t.Fatal("another user")
	}
	l.put(a)
	if !l.take(a) {
		t.Fatal("after one ended")
	}
	for range uotPerUser {
		l.put(a)
	}
	l.put(b)
	if l.total != 0 {
		t.Fatalf("left: %d", l.total)
	}
	// A user's tokens stay until they refill: closing streams gives none
	// back.
	if !l.take(a) || !l.newPeer(a) {
		t.Fatal("a user back")
	}
	l.put(a)
	l.sweep(time.Now())
	if l.users[a] == nil || l.users[b] != nil {
		t.Fatalf("swept: a kept %v (spent a token), b kept %v (spent none)", l.users[a] != nil, l.users[b] != nil)
	}
	l.sweep(time.Now().Add(time.Minute))
	if len(l.users) != 0 {
		t.Fatalf("not forgotten: %d", len(l.users))
	}
	for i := range uotPerService {
		if !l.take([32]byte{byte(i), byte(i >> 8), 7}) {
			t.Fatal("under the service's limit")
		}
	}
	if l.take([32]byte{9, 9, 9}) {
		t.Fatal("over the service's limit")
	}
}

// A user's new destinations and lookups are paced, across streams and
// after they end; a stream keeps 4096 destinations, the unused go first.
func TestUoTPacing(t *testing.T) {
	looked := 0
	s := &Server{Allow: func(netip.Addr) bool { return true }, Resolve: func(context.Context, string) ([]netip.Addr, error) {
		looked++
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}}
	user := [32]byte{1}
	stream := func() *uotStream {
		if !s.uot.take(user) {
			t.Fatal("no slot")
		}
		return &uotStream{s: s, ctx: context.Background(), user: user, names: map[string]uotResolved{}, peers: map[netip.AddrPort]int64{}}
	}
	dest := func(i int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), uint16(1000+i/256)) //nolint:gosec // test
	}
	u := stream()
	sent := 0
	for i := range 3 * uotPeerBurst {
		if u.mayReach(dest(i)) {
			sent++
		}
	}
	if sent != uotPeerBurst {
		t.Fatalf("new destinations: %d, want the burst %d", sent, uotPeerBurst)
	}
	if !u.mayReach(dest(0)) {
		t.Fatal("a destination it sent to")
	}
	// Another stream of the same user, after this one ended: no new tokens.
	s.uot.put(user)
	if v := stream(); v.mayReach(dest(5000)) {
		t.Fatal("a new stream got new tokens")
	}
	// The cap per stream, with tokens to spare.
	w := stream()
	for i := range uotPeers + 100 {
		s.uot.users[user].peers = bucket{uotPeerBurst, time.Now()}
		w.mayReach(netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 9)) //nolint:gosec // test
	}
	if len(w.peers) != uotPeers {
		t.Fatalf("destinations kept: %d", len(w.peers))
	}
	// Those not used for a while go when a new one comes.
	for p := range w.peers {
		w.peers[p] = time.Now().Add(-2 * uotPeerAge).UnixNano()
	}
	w.pruned = time.Time{} // at most once a second
	s.uot.users[user].peers = bucket{uotPeerBurst, time.Now()}
	if !w.mayReach(dest(77)) || len(w.peers) != 1 {
		t.Fatalf("stale destinations kept: %d", len(w.peers))
	}
	// Lookups: the burst, then none; a name looked up is kept.
	n := 0
	for i := range 2 * uotLookupBurst {
		if _, ok := w.resolve(uotAddr{name: fmt.Sprintf("n%d.test", i), port: 53}); ok {
			n++
		}
	}
	if n != uotLookupBurst || looked != uotLookupBurst {
		t.Fatalf("lookups: %d resolved, %d asked, want %d", n, looked, uotLookupBurst)
	}
	if _, ok := w.resolve(uotAddr{name: "n0.test", port: 53}); !ok || looked != uotLookupBurst {
		t.Fatal("a kept name looked up again")
	}
}

// isConnect = 1 spends a new destination too: with none left, a reset.
func TestUoTConnectedPaced(t *testing.T) {
	echo := udpEcho(t)
	h, connect := uotServer(t, time.Minute)
	_, s, done := connect(UoTName + ":0")
	_, _ = s.Write(append([]byte{1}, socksAddr(echo)...))
	if _, err := s.Write(packet(nil, []byte("a"))); err != nil {
		t.Fatal(err)
	}
	if _, got := readPacket(t, s, true); string(got) != "a" {
		t.Fatalf("connected: %q", got)
	}
	h.uot.mu.Lock()
	for _, u := range h.uot.users {
		u.peers = bucket{0, time.Now()}
	}
	h.uot.mu.Unlock()
	_, s2, done2 := connect(UoTName + ":0")
	_, _ = s2.Write(append([]byte{1}, socksAddr(echo)...))
	if !reset(t, s2) {
		t.Error("connected without a token: not reset")
	}
	done2()
	done()
}

// A connected socket hears "port unreachable" and goes on: the destination
// may open the port later.
func TestUoTICMPError(t *testing.T) {
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	dest := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	pc.Close()
	_, connect := uotServer(t, time.Minute)
	_, s, done := connect(UoTName + ":0")
	defer done()
	_, _ = s.Write(append([]byte{1}, socksAddr(dest)...))
	if _, err := s.Write(packet(nil, []byte("nobody"))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // the ICMP error comes back
	pc, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(dest))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 100)
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err == nil {
			_, _ = pc.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	if _, err := s.Write(packet(nil, []byte("now"))); err != nil {
		t.Fatal(err)
	}
	if _, got := readPacket(t, s, true); string(got) != "now" {
		t.Fatalf("after port unreachable: %q", got)
	}
}

// The sockets serveUoT makes, connected or not, do not broadcast.
func TestUoTSocket(t *testing.T) {
	for _, to := range []netip.AddrPort{{}, netip.MustParseAddrPort("127.0.0.1:9")} {
		c, err := uotSocket(context.Background(), to)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := c.SyscallConn()
		v := -1
		_ = raw.Control(func(fd uintptr) { v, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST) })
		c.Close()
		if v != 0 {
			t.Errorf("socket to %v: SO_BROADCAST %d", to, v)
		}
	}
}

// UoT's sockets do not broadcast, which Go would let them.
func TestUoTNoBroadcast(t *testing.T) {
	send := func(lc net.ListenConfig) error {
		c, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, err = c.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4bcast, Port: 9})
		return err
	}
	if err := send(net.ListenConfig{}); errors.Is(err, syscall.EACCES) {
		t.Fatal("Go's own socket refuses broadcast: the test proves nothing")
	}
	if err := send(net.ListenConfig{Control: noBroadcast}); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("broadcast with noBroadcast: %v", err)
	}
}

// Reading a packet's address and length allocates nothing (names aside).
func TestUoTReadAllocs(t *testing.T) {
	one := packet([]byte{0x00, 192, 0, 2, 1, 0, 53}, []byte("x"))
	r := bufio.NewReaderSize(bytes.NewReader(bytes.Repeat(one, 1000)), 4<<10)
	allocs := testing.AllocsPerRun(500, func() {
		if _, err := readAddr(r, false); err != nil {
			t.Fatal(err)
		}
		l, err := next(r, 2)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = r.Discard(int(binary.BigEndian.Uint16(l)))
	})
	if allocs != 0 {
		t.Fatalf("allocations per packet: %v", allocs)
	}
}

// stuckStream is a client that sends and never reads: its writes wait for
// the write deadline.
type stuckStream struct {
	io.Reader
	deadline chan struct{}
	once     sync.Once
}

func (s *stuckStream) Write([]byte) (int, error) {
	<-s.deadline
	return 0, os.ErrDeadlineExceeded
}
func (s *stuckStream) SetReadDeadline(time.Time) error { return nil }
func (s *stuckStream) SetWriteDeadline(time.Time) error {
	s.once.Do(func() { close(s.deadline) })
	return nil
}

// A stream whose client stopped reading is reset, not ended: HTTP/3 would
// otherwise close it cleanly after the forced deadline.
func TestUoTStuckReset(t *testing.T) {
	echo := udpEcho(t)
	s := &Server{Allow: func(a netip.Addr) bool { return a == echo.Addr() }, uotIdle: 200 * time.Millisecond}
	user := [32]byte{3}
	s.uot.take(user)
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() {
		_, _ = pw.Write(append([]byte{0}, socksAddr(netip.MustParseAddrPort("0.0.0.0:0"))...))
		_, _ = pw.Write(packet(append([]byte{0x00}, binary.BigEndian.AppendUint16(echo.Addr().AsSlice(), echo.Port())...), []byte("x")))
	}()
	st := &stuckStream{Reader: pr, deadline: make(chan struct{})}
	if err := s.serveUoT(context.Background(), user, st, st); !errors.Is(err, errRefused) {
		t.Fatalf("a stuck stream ended with %v, not a reset", err)
	}
}
