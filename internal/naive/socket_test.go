//go:build linux

package naive

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/arngory/raycontrol/internal/nikoipc"
	"github.com/arngory/raycontrol/internal/site"
)

func notSentLowatOf(t *testing.T, c net.Conn) int {
	t.Helper()
	sc, ok := c.(syscall.Conn)
	if !ok {
		t.Fatalf("%T gives no socket", c)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var serr error
	if err := rc.Control(func(fd uintptr) { v, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT) }); err != nil || serr != nil {
		t.Fatal(err, serr)
	}
	return v
}

// keptListener keeps the connections it accepts: the server's sockets.
type keptListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *keptListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.conns = append(l.conns, c)
		l.mu.Unlock()
	}
	return c, err
}

// An HTTP/2 connection's socket holds little unsent while the connection
// carries datagrams (UoT, ICMP), so that they do not wait behind megabytes
// of a download, and is as the system has it otherwise: with TCP tunnels
// alone, and again once the last datagram stream is gone.
func TestDatagramsBoundUnsent(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsers(t, users, "secret-one")
	answer, _ := site.Responder(site.Answer404, "")
	h := &Server{Users: &Users{Path: users}, Answer: answer, ICMP: true, icmpOpen: newFakeNet().open, Log: slog.New(slog.DiscardHandler),
		Dial: func(context.Context, string, string) (net.Conn, error) {
			c, s := net.Pipe()
			go func() { _, _ = io.Copy(io.Discard, s) }()
			return c, nil
		}}
	srv := httptest.NewUnstartedServer(h)
	srv.Config = h.HTTPServer()
	kept := &keptListener{Listener: srv.Listener}
	srv.Listener = kept
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2"},
	}}
	t.Cleanup(tr.CloseIdleConnections)
	open := func(host string) (closeStream func()) {
		t.Helper()
		pr, pw := io.Pipe()
		req, _ := http.NewRequest(http.MethodConnect, srv.URL, pr)
		req.Host = host
		req.Header.Set("Padding", paddingHeader())
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:secret-one")))
		resp, err := tr.RoundTrip(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT %s: %v %v", host, resp, err)
		}
		return func() { pw.Close(); resp.Body.Close() }
	}
	socket := func() net.Conn {
		t.Helper()
		kept.mu.Lock()
		defer kept.mu.Unlock()
		if len(kept.conns) != 1 {
			t.Fatalf("%d connections, want the one", len(kept.conns))
		}
		return kept.conns[0]
	}
	bound := func(want int, when string) {
		t.Helper()
		eventually(t, fmt.Sprintf("%s: TCP_NOTSENT_LOWAT is not %d", when, want), func() bool { return notSentLowatOf(t, socket()) == want })
	}

	tcp := open("192.0.2.1:443")
	defer tcp()
	// The system's own: no bound to speak of (it reads as all ones, or as
	// not set).
	own := notSentLowatOf(t, socket())
	if own == notSentLowat {
		t.Fatalf("a TCP tunnel alone: TCP_NOTSENT_LOWAT is %d already", own)
	}
	first := open(UoTName + ":0")
	bound(notSentLowat, "a UoT stream")
	ping := open(ICMPName + ":0")
	first()
	bound(notSentLowat, "an ICMP stream after the UoT stream ended")
	ping()
	bound(own, "the last datagram stream gone")
}

// The socket of a connection the front passed (nikoipc) is found under
// its TLS as an accepted one is; a connection with no socket of its own
// has none, and datagrams on it change nothing.
func TestConnContextSockets(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	sock := filepath.Join(t.TempDir(), "fd.sock")
	ipc, err := nikoipc.ListenFD(sock, os.Getuid(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer ipc.Close()
	front, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sock, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	client, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := tcp.Accept()
	if err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddrPort(client.LocalAddr().String())
	if err := nikoipc.Pass(front, accepted.(*net.TCPConn), nikoipc.Handoff{Route: "naive", Src: src, Dst: src, SNI: "n.example.com"}); err != nil {
		t.Fatal(err)
	}
	accepted.Close()
	passed, err := ipc.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer passed.Close()

	own := notSentLowatOf(t, passed)
	done := datagramStream(connContext(context.Background(), tls.Server(passed, &tls.Config{MinVersion: tls.VersionTLS13})))
	if got := notSentLowatOf(t, passed); got != notSentLowat || own == notSentLowat {
		t.Errorf("a passed socket with datagrams: TCP_NOTSENT_LOWAT %d, want %d (%d before)", got, notSentLowat, own)
	}
	done()
	if got := notSentLowatOf(t, passed); got != own {
		t.Errorf("a passed socket after them: TCP_NOTSENT_LOWAT %d, %d before", got, own)
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx := context.Background()
	if got := connContext(ctx, tls.Server(a, &tls.Config{MinVersion: tls.VersionTLS13})); got != ctx {
		t.Error("a pipe has a socket")
	}
	datagramStream(ctx)()
}
