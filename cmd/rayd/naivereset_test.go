package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/nikoipc"
)

// testFront plays niko-server's front for naive-quic: the datagrams of UDP
// clients go to the backend it is attached to (IPC mode packet), the
// backend's answers back to them.
type testFront struct {
	t   *testing.T
	udp *net.UDPConn

	mu   sync.Mutex
	back *net.UnixConn
}

func newTestFront(t *testing.T) *testFront {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &testFront{t: t, udp: udp}
	t.Cleanup(func() {
		f.cut()
		udp.Close()
	})
	local := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, client, err := udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			f.mu.Lock()
			back := f.back
			f.mu.Unlock()
			if back != nil {
				_ = nikoipc.Front(back, netip.AddrPortFrom(client.Addr().Unmap(), client.Port()), local, buf[:n])
			}
		}
	}()
	return f
}

// attach connects the front to the backend's socket.
func (f *testFront) attach(socket string) {
	f.t.Helper()
	back, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: socket, Net: "unixpacket"})
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.back = back
	f.mu.Unlock()
	go func() {
		buf := make([]byte, 65535+64)
		for {
			n, err := back.Read(buf)
			if err != nil || n == 0 {
				return
			}
			client, _, payload, err := nikoipc.Answer(buf[:n])
			f.mu.Lock()
			current := f.back == back
			f.mu.Unlock()
			if err == nil && current {
				_, _ = f.udp.WriteToUDPAddrPort(payload, client)
			}
		}
	}()
}

// cut takes the backend away as a kill of its process does: nothing more
// of it reaches a client, its last words least of all.
func (f *testFront) cut() {
	f.mu.Lock()
	back := f.back
	f.back = nil
	f.mu.Unlock()
	if back != nil {
		back.Close()
	}
}

// lockedBuffer collects what several goroutines write.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// A naive process started anew tells a client of the one before it that
// its connection is gone, at the client's next packet: the stateless reset
// carries the token the first process gave, as both have the service's key
// (-reset-key). Without the key the client hears nothing and waits out its
// idle time.
func TestNaiveStatelessReset(t *testing.T) {
	// What quic-go has to say of a connection whose buffers it cannot size
	// goes to the standard log, once a process and at every start of one:
	// over the front's datagrams (nikoipc.PacketConn) there is nothing to
	// say. These are the first QUIC servers of the tests that are on no
	// UDP socket.
	var said lockedBuffer
	stdlog.SetOutput(&said)
	t.Cleanup(func() {
		stdlog.SetOutput(os.Stderr)
		if s := said.String(); strings.Contains(s, "buffer") {
			t.Errorf("quic-go warns of the front's datagram socket: %s", s)
		}
	})
	keyFile := filepath.Join(t.TempDir(), "quic-reset.key")
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		restart func() quicOptions // the second process's
		reset   bool
	}{
		{"the service's key", func() quicOptions {
			o := quicOptions{}
			var err error
			if o.resetKey, err = readResetKey(keyFile); err != nil {
				t.Fatal(err)
			}
			return o
		}, true},
		{"no key", func() quicOptions { return quicOptions{} }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ns, cert := naiveTest(t, sink)
			front := newTestFront(t)
			dir := t.TempDir()
			log := slog.New(slog.DiscardHandler)
			// start is a naive process's QUIC side behind the front; stop
			// ends it.
			start := func(name string, o quicOptions) (stop func()) {
				socket := filepath.Join(dir, name+".sock")
				pc, err := nikoipc.ListenPacket(socket, os.Getuid(), log)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { done <- serveHTTP3(ctx, pc, fixedCert(cert), ns, o) }()
				front.attach(socket)
				return func() {
					cancel()
					if err := <-done; err != nil {
						t.Errorf("serveHTTP3: %v", err)
					}
				}
			}
			first := quicOptions{}
			var err error
			if first.resetKey, err = readResetKey(keyFile); err != nil {
				t.Fatal(err)
			}
			stop := start("first", first)

			// A client whose own idle time is far away.
			conns := make(chan *quic.Conn, 1)
			tr := &http3.Transport{TLSClientConfig: naiveClientTLS(), QUICConfig: &quic.Config{MaxIdleTimeout: time.Minute},
				Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
					conn, err := quic.DialAddrEarly(ctx, front.udp.LocalAddr().String(), tlsConf, conf)
					if err == nil {
						conns <- conn
					}
					return conn, err
				}}
			t.Cleanup(func() { _ = tr.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			req, pw := naiveConnect(ctx, t, "https://naive.test", "192.0.2.1:443")
			resp, err := tr.RoundTrip(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("CONNECT: %v %v", resp, err)
			}
			t.Cleanup(func() { resp.Body.Close() })
			conn := <-conns

			// The process is killed, and one starts in its place.
			front.cut()
			stop()
			t.Cleanup(start("second", c.restart()))

			// The client's next packets are for a connection the new
			// process does not know.
			go func() { _, _ = pw.Write([]byte("more")) }()
			select {
			case <-conn.Context().Done():
				var reset *quic.StatelessResetError
				if cause := context.Cause(conn.Context()); !c.reset || !errors.As(cause, &reset) {
					t.Fatalf("the client's connection ended with %v", cause)
				}
			case <-time.After(2 * time.Second):
				if c.reset {
					t.Fatal("the client got no stateless reset: it would wait out its idle time")
				}
			}
		})
	}
}

// The key file's errors name the file and what is wrong, never what is in
// it.
func TestReadResetKey(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	key := strings.Repeat("5a", 32)
	got, err := readResetKey(write("good", key+"\n"))
	if err != nil || hex.EncodeToString(got[:]) != key {
		t.Fatalf("a good key: %v", err)
	}
	if _, err := readResetKey(filepath.Join(dir, "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no file: %v", err)
	}
	for name, content := range map[string]string{"short": key[:62], "long": key + "5a", "nothex": strings.Repeat("zz", 32), "empty": ""} {
		k, err := readResetKey(write(name, content))
		if err == nil || k != nil {
			t.Errorf("%s: taken", name)
		} else if content != "" && strings.Contains(err.Error(), content[:8]) {
			t.Errorf("%s: the error shows the file's content: %v", name, err)
		}
	}
}
