package naive

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/site"
)

// ackServer is a naive server over HTTP/2 for the user u5 (password pw),
// with ICMP on, and a CONNECT to it: with niko-ack: 1 or without, early
// being what the client sends before it has the answer.
func ackServer(t *testing.T, setup func(*Server)) (*Server, func(target string, ack bool, early []byte) (*http.Response, *paddedStream)) {
	t.Helper()
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12"})
	answer, _ := site.Responder(site.Answer404, "")
	h := &Server{Users: &Users{Path: users}, Answer: answer, ICMP: true, icmpOpen: newFakeNet().open, Log: slog.New(slog.DiscardHandler)}
	setup(h)
	url := serveNaive(t, h)
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2"},
	}}
	t.Cleanup(tr.CloseIdleConnections)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return h, func(target string, ack bool, early []byte) (*http.Response, *paddedStream) {
		t.Helper()
		pr, pw := io.Pipe()
		t.Cleanup(func() { pw.Close() })
		req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, url, pr)
		req.Host = target
		req.Header.Set("Padding", paddingHeader())
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:pw")))
		if ack {
			req.Header.Set(AckHeader, "1")
		}
		s := &paddedStream{w: pw}
		if early != nil {
			go func() { _, _ = s.Write(early) }()
		}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("CONNECT %s: %v", target, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		s.r = resp.Body
		return resp, s
	}
}

// refused is an answer that is no tunnel: the status, the reason, naive's
// Padding header as on a 200 (without it a naive client stops padding on
// its next streams), and nothing after them.
func refused(t *testing.T, what string, resp *http.Response, status int, reason string) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != status || resp.Header.Get(AckHeader) != reason || len(body) != 0 || err != nil {
		t.Errorf("%s: %s, niko-ack %q, %d bytes after it (%v); want %d, %q and nothing", what, resp.Status, resp.Header.Get(AckHeader), len(body), err, status, reason)
	}
	if n := len(resp.Header.Get("Padding")); n < 30 || n > 61 {
		t.Errorf("%s: a refusal with a Padding header of %d bytes, a 200 has 30 to 61", what, n)
	}
}

// A CONNECT with niko-ack: 1 is answered after the dial: 200 once the
// destination took the connection, with what the client sent meanwhile
// passed on first; 502 with the reason when it did not; 504 when the dial's
// time ran out, at that time and not before.
func TestAckConnect(t *testing.T) {
	// The destinations: one that echoes, one that is not there.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := gone.Addr().String()
	gone.Close()

	const dialWait = 400 * time.Millisecond
	var slow atomic.Int64  // how long a dial takes before it goes on
	var dials atomic.Int32 // dials begun
	var dialed atomic.Int32
	held := make(chan struct{}) // closed: the dial to the held destination goes on, and fails
	var d net.Dialer
	h, connect := ackServer(t, func(h *Server) {
		h.dialWait = dialWait
		h.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			defer dialed.Add(1)
			select {
			case <-time.After(time.Duration(slow.Load())):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			switch addr {
			case "192.0.2.1:443": // a destination that never answers
				<-ctx.Done()
				return nil, ctx.Err()
			case "192.0.2.9:443":
				<-held
				return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
			case "192.0.2.2:443":
				return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}
			case "nosuch.test:443":
				return nil, &net.DNSError{Err: "no such host", Name: "nosuch.test", IsNotFound: true}
			case "slowdns.test:443":
				return nil, &net.DNSError{Err: "i/o timeout", Name: "slowdns.test", IsTimeout: true}
			case "192.0.2.3:443":
				return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.EPERM)}
			}
			return d.DialContext(ctx, network, addr)
		}
	})

	// A live destination: the answer comes after the dial, and the early
	// bytes are the first the destination gets.
	slow.Store(int64(200 * time.Millisecond))
	early := bytes.Repeat([]byte("early bytes "), 3000) // more than a frame, through naive's padding
	resp, s := connect(echo.Addr().String(), true, early)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Padding") == "" || resp.Header.Get(AckHeader) != "" {
		t.Fatalf("a live destination: %s %v", resp.Status, resp.Header)
	}
	if dialed.Load() != 1 {
		t.Fatal("the 200 came before the dial was done")
	}
	got := make([]byte, len(early))
	if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, early) {
		t.Fatalf("the early bytes came back changed (%v)", err)
	}
	if _, err := s.Write([]byte("later")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(s, got[:5]); err != nil || string(got[:5]) != "later" {
		t.Fatalf("after the early bytes: %q %v", got[:5], err)
	}
	slow.Store(0)

	// Destinations that did not take the connection.
	for _, c := range []struct {
		what, target, reason string
	}{
		{"a closed port", dead, ackRefused},
		{"no route", "192.0.2.2:443", ackUnreachable},
		{"no such name", "nosuch.test:443", ackUnreachable},
		{"a lookup that timed out", "slowdns.test:443", ackUnreachable},
		{"stopped by the node's rules", "192.0.2.3:443", ackDenied},
	} {
		resp, _ := connect(c.target, true, []byte("early"))
		refused(t, c.what, resp, http.StatusBadGateway, c.reason)
	}

	// A destination that stays silent: 504 when the dial's time is over,
	// not before, and no reason with it.
	start := time.Now()
	resp, _ = connect("192.0.2.1:443", true, nil)
	if took := time.Since(start); took < dialWait || took > dialWait+3*time.Second {
		t.Errorf("a silent destination was answered after %v, the dial's time is %v", took, dialWait)
	}
	refused(t, "a silent destination", resp, http.StatusGatewayTimeout, "")

	// The limits' answer comes before the dial, as without niko-ack.
	h.lim.mu.Lock()
	u := h.lim.userLocked("u5", time.Now())
	u.tcp += tcpPerUser
	h.lim.mu.Unlock()
	before := dials.Load()
	resp, _ = connect(echo.Addr().String(), true, nil)
	if dials.Load() != before {
		t.Errorf("over the user's limit: %d dials", dials.Load()-before)
	}
	refused(t, "over the user's limit", resp, http.StatusTooManyRequests, "")
	h.lim.mu.Lock()
	u.tcp -= tcpPerUser
	h.lim.mu.Unlock()

	// UoT and ICMP streams have no dial: 200 at once, whatever the header.
	slow.Store(int64(time.Hour))
	for _, host := range []string{UoTName + ":0", ICMPName + ":0"} {
		resp, _ := connect(host, true, nil)
		if resp.StatusCode != http.StatusOK || resp.Header.Get(AckHeader) != "" {
			t.Errorf("%s with niko-ack: %s %v", host, resp.Status, resp.Header)
		}
	}

	// Without the header nothing changed: 200 before the dial, which is
	// held here until the answer has come, and a dial that fails resets the
	// stream.
	slow.Store(0)
	before = dialed.Load()
	resp, s = connect("192.0.2.9:443", false, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Padding") == "" {
		t.Fatalf("without niko-ack: %s", resp.Status)
	}
	if dialed.Load() != before {
		t.Error("without niko-ack the 200 waited for the dial")
	}
	close(held)
	if !reset(t, s) {
		t.Error("without niko-ack a failed dial ended the stream cleanly")
	}
}

// A destination that is not public is the node's policy's to refuse: 502
// and "denied", through the server's own dial.
func TestAckConnectDenied(t *testing.T) {
	_, connect := ackServer(t, func(*Server) {})
	resp, _ := connect("127.0.0.1:443", true, nil)
	refused(t, "loopback", resp, http.StatusBadGateway, ackDenied)
}

// The mapping of a failed dial: 502 with one of three reasons, or 504 when
// the dial's whole time ran out; over all the attempts of a dial, whichever
// came first; never a status a naive client reads as its password refused.
func TestAckRefusal(t *testing.T) {
	op := func(errno syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
	}
	silent := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for _, c := range []struct {
		err     error
		expired bool
		status  int
		reason  string
	}{
		{op(syscall.ECONNREFUSED), false, 502, ackRefused},
		{op(syscall.EHOSTUNREACH), false, 502, ackUnreachable},
		{op(syscall.ENETUNREACH), false, 502, ackUnreachable},
		{op(syscall.EPERM), false, 502, ackDenied},
		{&net.OpError{Op: "dial", Net: "tcp", Err: errNotPublic}, false, 502, ackDenied},
		{errNotPublic, false, 502, ackDenied},
		{&net.DNSError{Err: "no such host", IsNotFound: true}, false, 502, ackUnreachable},
		{&net.DNSError{Err: "timeout", IsTimeout: true}, true, 502, ackUnreachable},
		// A lookup the dial's time ended: no address was ever silent.
		{lookupError{context.DeadlineExceeded}, true, 502, ackUnreachable},
		{lookupError{errLookups}, false, 502, ackUnreachable},
		// 504 is the dial's whole time, and nothing less.
		{context.DeadlineExceeded, true, 504, ""},
		{silent, true, 504, ""},
		{silent, false, 502, ackUnreachable},
		{op(syscall.ETIMEDOUT), false, 502, ackUnreachable},
		{errAttempts, false, 502, ackUnreachable},
		// No attempt waited: its time was over when the addresses came.
		{errNoTime, true, 502, ackUnreachable},
		// Several attempts: refused before silent before the rest, in
		// whatever order they ended; denied only when all were.
		{attemptErrors{silent, op(syscall.ECONNREFUSED)}, true, 502, ackRefused},
		{attemptErrors{op(syscall.EHOSTUNREACH), op(syscall.ECONNREFUSED)}, false, 502, ackRefused},
		{attemptErrors{op(syscall.EPERM), op(syscall.ECONNREFUSED)}, false, 502, ackRefused},
		{attemptErrors{op(syscall.EHOSTUNREACH), silent}, true, 504, ""},
		{attemptErrors{op(syscall.EPERM), silent}, true, 504, ""},
		{attemptErrors{silent, op(syscall.EHOSTUNREACH)}, false, 502, ackUnreachable},
		{attemptErrors{silent, silent}, false, 502, ackUnreachable},
		{attemptErrors{op(syscall.EPERM), op(syscall.EHOSTUNREACH)}, false, 502, ackUnreachable},
		{attemptErrors{op(syscall.EPERM), op(syscall.EACCES)}, true, 502, ackDenied},
	} {
		status, reason := ackRefusal(c.err, c.expired)
		if status != c.status || reason != c.reason {
			t.Errorf("%v (expired %v): %d %q, want %d %q", c.err, c.expired, status, reason, c.status, c.reason)
		}
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusProxyAuthRequired:
			t.Errorf("%v: status %d, which a client takes for its password refused", c.err, status)
		}
	}
}
