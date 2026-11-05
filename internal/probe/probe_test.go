package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/summary"
)

func testServer(t *testing.T, daily int64) (*Server, *http.Client, string, *net.UDPConn) {
	t.Helper()
	s := &Server{Daily: daily, Log: slog.New(slog.DiscardHandler),
		Auth: func(r *http.Request) (string, error) {
			if d := r.Header.Get("X-Device"); d != "" {
				return d, nil
			}
			return "", errors.New("no device")
		}}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s.UDPPort = pc.LocalAddr().(*net.UDPAddr).Port
	go s.ServeUDP(pc)
	t.Cleanup(func() { pc.Close() })
	ts := httptest.NewUnstartedServer(s)
	ts.EnableHTTP2 = true
	ts.Config.ConnContext = ConnContext
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return s, ts.Client(), ts.URL, pc
}

func get(t *testing.T, c *http.Client, method, url, device string, body io.Reader) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, body)
	if device != "" {
		req.Header.Set("X-Device", device)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestTCPProbes(t *testing.T) {
	_, c, url, _ := testServer(t, DefaultDaily)
	if resp := get(t, c, "GET", url+PathDown+"?bytes=10", "", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("without a device: %d", resp.StatusCode)
	}

	// Down: N bytes, then the server's result in the trailer.
	resp := get(t, c, "GET", url+PathDown+"?bytes=3000000", "phone", nil)
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	res := resp.Trailer.Get(ResultTrailer)
	if err != nil || n != 3000000 || !strings.HasPrefix(res, "bytes=3000000; ms=") || !strings.Contains(res, "rtt_us=") {
		t.Fatalf("down: %d bytes, %v, trailer %q (%s)", n, err, res, resp.Proto)
	}

	// Up: what arrived, from the first byte to the last, and TCP_INFO.
	resp = get(t, c, "POST", url+PathUp+"?bytes=2000000", "phone", bytes.NewReader(make([]byte, 2000000)))
	var up Result
	json.NewDecoder(resp.Body).Decode(&up)
	resp.Body.Close()
	if up.Bytes != 2000000 || up.TCP == nil || up.TCP.RTTus == 0 {
		t.Fatalf("up: %+v", up)
	}
	// HTTP/1.1: the trailer comes after a chunked body.
	cfg := c.Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.NextProtos = []string{"http/1.1"}
	h1 := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}}
	resp = get(t, h1, "GET", url+PathDown+"?bytes=100000", "phone", nil)
	n, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 1 || n != 100000 || !strings.HasPrefix(resp.Trailer.Get(ResultTrailer), "bytes=100000;") {
		t.Fatalf("down over %s: %d bytes, trailer %q", resp.Proto, n, resp.Trailer.Get(ResultTrailer))
	}
	if resp := get(t, c, "GET", url+PathDown+"?bytes=0", "phone", nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("0 bytes: %d", resp.StatusCode)
	}
	if resp := get(t, c, "GET", url+PathDown+"?bytes="+strconv.Itoa(MaxBytes+1), "phone", nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("over the limit: %d", resp.StatusCode)
	}
}

func TestLimits(t *testing.T) {
	s, c, url, _ := testServer(t, 128<<20)
	// One probe per device at a time: a down that is not read holds it.
	// 64 MiB: more than the client's HTTP/2 window and the socket buffers
	// take, so the server is still writing when the client stops.
	const big = 64 << 20
	resp := get(t, c, "GET", url+PathDown+"?bytes="+strconv.Itoa(big), "phone", nil)
	if second := get(t, c, "GET", url+PathDown+"?bytes=10", "phone", nil); second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a second probe at once: %d", second.StatusCode)
	}
	if other := get(t, c, "GET", url+PathDown+"?bytes=10", "laptop", nil); other.StatusCode != http.StatusOK {
		t.Fatalf("another device: %d", other.StatusCode)
	}
	// Cut short: only what was sent counts against the day.
	buf := make([]byte, 100000)
	io.ReadFull(resp.Body, buf)
	resp.Body.Close()
	deadline := time.Now().Add(5 * time.Second)
	var used int64
	for {
		s.mu.Lock()
		busy := s.busy["phone"]
		used = s.used["phone"]
		s.mu.Unlock()
		if !busy {
			if used >= big {
				t.Fatalf("a cut probe counted %d bytes", used)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the cut probe still holds the device")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The day's volume: 128 MiB, of which some is spent.
	if resp := get(t, c, "GET", url+PathDown+"?bytes="+strconv.Itoa(int(128<<20-used+1)), "phone", nil); resp.StatusCode != http.StatusTooManyRequests ||
		resp.Header.Get("Retry-After") == "" {
		t.Fatalf("over the day's volume: %d", resp.StatusCode)
	}
	resp = get(t, c, "GET", url+PathDown+"?bytes=1000000", "phone", nil)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("within the day's volume: %d", resp.StatusCode)
	}
}

func TestUDPEcho(t *testing.T) {
	_, c, url, _ := testServer(t, DefaultDaily)
	resp := get(t, c, "POST", url+PathUDP, "phone", nil)
	var sess UDPSession
	json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	token, _ := base64.RawURLEncoding.DecodeString(sess.Token)
	if len(token) != 16 || sess.Seconds != 30 || sess.MaxRate != MaxRate || sess.Budget != UDPBudget {
		t.Fatalf("session %+v", sess)
	}
	// The UDP echo holds the device too.
	if busy := get(t, c, "GET", url+PathDown+"?bytes=10", "phone", nil); busy.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a TCP probe during the echo: %d", busy.StatusCode)
	}
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sess.Port}
	conn, err := net.DialUDP("udp", nil, server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	datagram := func(seq uint32, size int) []byte {
		b := make([]byte, size)
		copy(b, token)
		binary.BigEndian.PutUint32(b[16:], seq)
		binary.BigEndian.PutUint64(b[20:], uint64(time.Now().UnixNano()))
		for i := HeaderSize; i < size; i++ {
			b[i] = byte(i)
		}
		return b
	}
	got := make([]byte, 2000)
	for seq, size := range []int{HeaderSize, 200, 1400} {
		sent := datagram(uint32(seq), size)
		before := time.Now()
		conn.Write(sent)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(got)
		if err != nil || n != size || !bytes.Equal(got[:28], sent[:28]) || !bytes.Equal(got[HeaderSize:n], sent[HeaderSize:]) {
			t.Fatalf("echo %d: %d bytes, %v", seq, n, err)
		}
		at := time.Unix(0, int64(binary.BigEndian.Uint64(got[28:])))
		if at.Before(before.Add(-time.Second)) || at.After(time.Now().Add(time.Second)) {
			t.Fatalf("the server's time %v", at)
		}
	}
	// Another sender with the token, a wrong token, a short datagram: nothing.
	other, _ := net.DialUDP("udp", nil, server)
	defer other.Close()
	other.Write(datagram(9, 100))
	bad := datagram(10, 100)
	bad[0] ^= 1
	conn.Write(bad)
	conn.Write(datagram(11, HeaderSize-1))
	for _, c := range []*net.UDPConn{other, conn} {
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if n, err := c.Read(got); err == nil {
			t.Fatalf("an echo of %d bytes that should not be", n)
		}
	}
	resp = get(t, c, "GET", url+PathUDP+"?token="+sess.Token, "laptop", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("another device's count: %d", resp.StatusCode)
	}
	resp = get(t, c, "GET", url+PathUDP+"?token="+sess.Token, "phone", nil)
	var sum UDPSummary
	json.NewDecoder(resp.Body).Decode(&sum)
	resp.Body.Close()
	if sum.Received != 3 || sum.Echoed != 3 || sum.Dropped != 0 || sum.Bytes != 2*(HeaderSize+200+1400) {
		t.Fatalf("summary %+v", sum)
	}
	// Ended: no more echoes, and the device is free.
	conn.Write(datagram(12, 100))
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Read(got); err == nil {
		t.Fatal("an echo after the end")
	}
	if free := get(t, c, "GET", url+PathDown+"?bytes=10", "phone", nil); free.StatusCode != http.StatusOK {
		t.Fatalf("after the echo: %d", free.StatusCode)
	}
}

func TestUDPRate(t *testing.T) {
	s := &Server{}
	token := [16]byte{1}
	s.sessions = map[[16]byte]*session{token: {device: "d", reserved: 1 << 20, expires: time.Now().Add(time.Minute)}}
	now := time.Now()
	echoed := 0
	for i := 0; i < MaxRate+50; i++ {
		if s.admit(token, "a", 100, now) {
			echoed++
		}
	}
	if echoed != MaxRate || s.sessions[token].sum.Dropped != 50 {
		t.Fatalf("echoed %d in one second, dropped %d", echoed, s.sessions[token].sum.Dropped)
	}
	if !s.admit(token, "a", 100, now.Add(time.Second)) {
		t.Fatal("the next second is refused")
	}
	// The budget: both directions count.
	s.sessions[token].reserved = s.sessions[token].sum.Bytes + 150
	if s.admit(token, "a", 100, now.Add(time.Second)) {
		t.Fatal("over the budget")
	}
}

func TestClient(t *testing.T) {
	_, hc, url, _ := testServer(t, DefaultDaily)
	c := Client{HTTP: hc, Base: url, Authorize: func(r *http.Request) { r.Header.Set("X-Device", "phone") }}
	ctx := context.Background()
	down, err := c.Down(ctx, 4<<20)
	if err != nil || down.Bytes != 4<<20 || down.Server.Bytes != 4<<20 || down.Server.TCP == nil || down.Mbps() <= 0 {
		t.Fatalf("down %+v %v", down, err)
	}
	up, err := c.Up(ctx, 2<<20)
	if err != nil || up.Server.Bytes != 2<<20 || up.Server.TCP == nil {
		t.Fatalf("up %+v %v", up, err)
	}
	e, err := c.Echo(ctx, 40, 1200, 5*time.Millisecond)
	if err != nil || e.Sent != 40 || e.Received != 40 || e.Server.Received != 40 || e.LostUp() != 0 || e.LostDown() != 0 ||
		e.RTTMin <= 0 || e.RTTMax < e.RTTAvg || e.RTTAvg < e.RTTMin {
		t.Fatalf("echo %+v %v", e, err)
	}
}

// sock_diag sees the host's connections with TCP_INFO; the stats sum up
// those from one address to the tunnel ports.
func TestLink(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	for range 3 {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write(make([]byte, 100000))
		io.ReadFull(c, make([]byte, 100000))
	}
	conns, err := tcpConnections()
	if err != nil {
		t.Fatal(err)
	}
	st := aggregate(conns, netip.MustParseAddr("127.0.0.1"), []uint16{port})
	if st.Connections != 3 || st.RTTus.Max == 0 || st.RTTus.Min > st.RTTus.Median || st.SegsOut == 0 {
		t.Fatalf("stats %+v", st)
	}
	if other := aggregate(conns, netip.MustParseAddr("203.0.113.9"), []uint16{port}); other.Connections != 0 {
		t.Fatalf("another address: %+v", other)
	}

	// Through a tunnel the request comes from loopback: no answer about it.
	_, c, url, _ := testServer(t, DefaultDaily)
	if resp := get(t, c, "GET", url+PathLink, "phone", nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("link from loopback: %d", resp.StatusCode)
	}
	if resp := get(t, c, "GET", url+PathLink, "phone", nil); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("link twice in 5 s: %d", resp.StatusCode)
	}
}

// A Hysteria2 backend's stats socket: the address in, its JSON out.
func TestHysteriaStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		fmt.Fprintf(c, `{"connections":1,"asked":%q}`+"\n", strings.TrimSpace(line))
	}()
	raw, err := hysteriaStats(path, netip.MustParseAddr("198.51.100.7"), "u7")
	var got struct {
		Connections int
		Asked       string
	}
	json.Unmarshal(raw, &got)
	if err != nil || got.Connections != 1 || got.Asked != "198.51.100.7 u7" {
		t.Fatalf("stats %s %v", raw, err)
	}
}

// A backend before niko-server v0.7 closes on a line with a name: the
// address alone then still gets the aggregates.
func TestSessionStatsOldBackend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadString('\n')
			if ip, err := netip.ParseAddr(strings.TrimSpace(line)); err == nil {
				fmt.Fprintf(c, `{"connections":1,"asked":%q}`+"\n", ip)
			}
			c.Close()
		}
	}()
	raw, err := sessionStats(path, netip.MustParseAddr("198.51.100.7"), "u7")
	var got struct {
		Connections int
		Asked       string
	}
	json.Unmarshal(raw, &got)
	if err != nil || got.Connections != 1 || got.Asked != "198.51.100.7" {
		t.Fatalf("stats from an old backend %s %v", raw, err)
	}
}

// The report endpoint: off without a collector, 409 through a tunnel, and
// the collector's errors as status codes.
func TestReport(t *testing.T) {
	s, c, url, _ := testServer(t, DefaultDaily)
	if resp := get(t, c, "POST", url+PathReport, "phone", strings.NewReader("{}")); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("no collector: %d", resp.StatusCode)
	}
	var got []string
	s.Report = func(_ context.Context, device string, addr netip.Addr, body io.Reader) error {
		b, _ := io.ReadAll(body)
		got = append(got, device+" "+addr.String()+" "+string(b))
		switch string(b) {
		case "off":
			return summary.ErrDisabled
		case "again":
			return summary.ErrRepeated
		case "bad":
			return fmt.Errorf("%w: test", summary.ErrInvalid)
		case "broken":
			return errors.New("disk")
		case "away":
			return summary.ErrUnavailable
		}
		return nil
	}
	if resp := get(t, c, "POST", url+PathReport, "phone", strings.NewReader("ok")); resp.StatusCode != http.StatusConflict {
		t.Fatalf("through a tunnel: %d", resp.StatusCode)
	}
	for body, want := range map[string]int{"ok": 204, "off": 404, "again": 429, "bad": 400, "broken": 500, "away": 503} {
		req := httptest.NewRequest("POST", PathReport, strings.NewReader(body))
		req.RemoteAddr = "[::ffff:203.0.113.5]:4321"
		w := httptest.NewRecorder()
		s.report(w, req, "phone")
		if w.Code != want {
			t.Errorf("%s: %d, want %d", body, w.Code, want)
		}
		if (body == "again" || body == "away") && w.Header().Get("Retry-After") == "" {
			t.Errorf("%d without Retry-After", w.Code)
		}
	}
	if len(got) != 6 || !slices.Contains(got, "phone 203.0.113.5 ok") {
		t.Fatalf("calls %q", got)
	}
}
