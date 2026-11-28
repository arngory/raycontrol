package h3serve

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Window is asked before a connection's receive window grows, with the
// connection its requests know (Conn) and an end that comes with the
// connection's; what it says is what quic-go does. Without it the server's
// QUIC configuration is the same but for the hook.
func TestWindow(t *testing.T) {
	o := Options{Idle: time.Minute, MaxStreams: 100, PendingStreams: 10, MaxHeaderBytes: 16 << 10}
	plain, hooked := Config(o), config(o, func(*quic.Conn, uint64) bool { return false })
	if hooked.AllowConnectionWindowIncrease == nil || plain.AllowConnectionWindowIncrease != nil {
		t.Fatal("the hook is not where it belongs")
	}
	hooked.AllowConnectionWindowIncrease, hooked.GetConfigForClient, plain.GetConfigForClient = nil, nil, nil
	if !reflect.DeepEqual(plain, hooked) {
		t.Fatalf("the hook changed the configuration:\n%+v\n%+v", plain, hooked)
	}
	for _, grant := range []bool{false, true} {
		var mu sync.Mutex
		var asked []*quic.Conn
		var grown uint64
		var ends []<-chan struct{}
		o.Window = func(c *quic.Conn, done <-chan struct{}, delta uint64) bool {
			mu.Lock()
			defer mu.Unlock()
			asked, ends = append(asked, c), append(ends, done)
			if grant {
				grown += delta
			}
			return grant
		}
		const body = 16 << 20
		conns := make(chan *quic.Conn, 16)
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conns <- Conn(r.Context())
			n, _ := io.Copy(io.Discard, r.Body)
			if n != body {
				w.WriteHeader(http.StatusBadRequest)
			}
		})
		raw, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		// A round trip of some 10 ms: quic-go grows a window that is read
		// within a few of them, which loopback's alone are too short for.
		udp := &delayed{PacketConn: raw}
		cert := selfSigned(t)
		ctx, stop := context.WithCancel(context.Background())
		served := make(chan error, 1)
		go func() {
			served <- Serve(ctx, udp, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, h, o)
		}()
		addr := udp.LocalAddr().String()
		tr := &http3.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
				CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}},
			Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, addr, tlsConf, conf)
			}}
		// quic-go asks once a window is read fast for its round trip: a
		// few uploads, for a slow run (the race detector).
		var qc *quic.Conn
		var n int
		var done []<-chan struct{}
		for range 5 {
			req, _ := http.NewRequest(http.MethodPost, "https://h3.test/", bytes.NewReader(make([]byte, body)))
			resp, err := tr.RoundTrip(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("grant %v: %v %v", grant, resp, err)
			}
			resp.Body.Close()
			if c := <-conns; qc == nil {
				qc = c
			} else if c != qc {
				t.Fatal("the requests' connection changed")
			}
			mu.Lock()
			n, done = len(asked), ends
			mu.Unlock()
			if n > 0 {
				break
			}
		}
		mu.Lock()
		for _, c := range asked {
			if c != qc {
				t.Errorf("asked of another connection than the request's")
			}
		}
		mu.Unlock()
		if qc == nil || n == 0 {
			t.Fatalf("grant %v: the request's connection known %v, asked %d times", grant, qc != nil, n)
		}
		_ = tr.Close()
		for _, d := range done {
			select {
			case <-d:
			case <-time.After(5 * time.Second):
				t.Fatal("the connection's end did not come")
			}
		}
		stop()
		if err := <-served; err != nil {
			t.Fatal(err)
		}
		if grant && grown == 0 {
			t.Fatal("granted, the window did not grow")
		}
	}
	if Conn(context.Background()) != nil {
		t.Fatal("a connection of no request")
	}
}

// delayed is a server's socket whose datagrams go 10 ms late.
type delayed struct{ net.PacketConn }

func (d *delayed) WriteTo(b []byte, addr net.Addr) (int, error) {
	p := append([]byte(nil), b...)
	time.AfterFunc(10*time.Millisecond, func() { _, _ = d.PacketConn.WriteTo(p, addr) })
	return len(b), nil
}
