package naive

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/site"
)

// uotServer is a naive server over HTTP/2 whose UDP may reach loopback (and
// 127.0.0.1 only: 127.0.0.2 stands for what is not allowed), with the name
// echo.test for 127.0.0.1.
func uotServer(t *testing.T, idle time.Duration) (*Server, func(host string) (*http.Response, *paddedStream, func())) {
	t.Helper()
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsers(t, users, "secret-one")
	answer, _ := site.Responder(site.Answer404, "")
	var d net.Dialer
	h := &Server{Users: &Users{Path: users}, Answer: answer, Dial: d.DialContext, Log: slog.New(slog.DiscardHandler),
		Allow: func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") },
		Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
			if name == "echo.test" {
				return []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}, nil
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
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	other, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
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

// readPacket reads one packet back: its source (when not connected) and data.
func readPacket(t *testing.T, r io.Reader, connected bool) (netip.AddrPort, []byte) {
	t.Helper()
	var from netip.AddrPort
	if !connected {
		head := make([]byte, 7)
		if _, err := io.ReadFull(r, head); err != nil {
			t.Fatal(err)
		}
		if head[0] != 0x00 {
			t.Fatalf("source type %#x", head[0])
		}
		from = netip.AddrPortFrom(netip.AddrFrom4([4]byte(head[1:5])), binary.BigEndian.Uint16(head[5:7]))
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(r, data); err != nil {
		t.Fatal(err)
	}
	return from, data
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
	_, connect := uotServer(t, 300*time.Millisecond)
	v4 := func(ap netip.AddrPort) []byte {
		b := append([]byte{0x00}, ap.Addr().AsSlice()...)
		return binary.BigEndian.AppendUint16(b, ap.Port())
	}

	// isConnect = 0: each packet its own address.
	_, s, done := connect(UoTName + ":0")
	if _, err := s.Write(append([]byte{0}, socksAddr(netip.MustParseAddrPort("0.0.0.0:0"))...)); err != nil {
		t.Fatal(err)
	}
	for i, data := range [][]byte{[]byte("one"), bytes.Repeat([]byte("x"), 60000), {}} {
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
	// By name: the first allowed address (127.0.0.2 is not).
	if _, err := s.Write(packet(uotName("echo.test", echo.Port()), []byte("named"))); err != nil {
		t.Fatal(err)
	}
	if from, got := readPacket(t, s, false); from != echo || string(got) != "named" {
		t.Fatalf("by name: %s %q", from, got)
	}
	// Not allowed, or no such name: dropped, the stream lives on.
	for _, addr := range [][]byte{v4(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), echo.Port())), uotName("nowhere.test", 53),
		v4(netip.AddrPortFrom(echo.Addr(), 0))} {
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

	// isConnect = 1: one destination, no addresses in the packets.
	_, s, done = connect(UoTName + ":443")
	if _, err := s.Write(append([]byte{1}, socksAddr(echo)...)); err != nil {
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

	// Resets: a destination not allowed, a packet too long, a bad request,
	// v1, a TCP destination that does not answer.
	for name, c := range map[string]struct {
		host string
		send []byte
	}{
		"connected, not allowed": {UoTName + ":0", append([]byte{1}, socksAddr(netip.MustParseAddrPort("127.0.0.2:53"))...)},
		"too long": {UoTName + ":0", append(append([]byte{0}, socksAddr(netip.MustParseAddrPort("0.0.0.0:0"))...),
			append(v4(echo), 0xff, 0xff)...)},
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
	if l.total != 0 || len(l.users) != 0 {
		t.Fatalf("left: %d %v", l.total, l.users)
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
