package xrayapi_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// natRelay is a client's NAT: the client sends to it, it sends on to the
// front from a port of its own, and rebind gives it a new port, as a NAT
// whose mapping expired does. The old port is gone, and what comes to it
// with it; the client sees nothing of it.
type natRelay struct {
	t      *testing.T
	in     *net.UDPConn
	server *net.UDPAddr

	mu     sync.Mutex
	out    *net.UDPConn
	client *net.UDPAddr
}

func newNATRelay(t *testing.T, server *net.UDPAddr) *natRelay {
	t.Helper()
	in, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &natRelay{t: t, in: in, server: server}
	t.Cleanup(func() {
		_ = in.Close()
		r.mu.Lock()
		_ = r.out.Close()
		r.mu.Unlock()
	})
	r.rebind()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := in.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			r.client = from
			out := r.out
			r.mu.Unlock()
			_, _ = out.Write(buf[:n])
		}
	}()
	return r
}

// rebind moves the relay to a new port.
func (r *natRelay) rebind() {
	out, err := net.DialUDP("udp4", nil, r.server)
	if err != nil {
		r.t.Fatal(err)
	}
	r.mu.Lock()
	old := r.out
	r.out = out
	r.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := out.Read(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			client := r.client
			r.mu.Unlock()
			if client != nil {
				_, _ = r.in.WriteToUDP(buf[:n], client)
			}
		}
	}()
}

// nikoRoutesByCID skips the test unless the niko-server at niko takes
// routable connection IDs (v0.18.0; the pin may be older).
func nikoRoutesByCID(t *testing.T, niko string) {
	t.Helper()
	if !nikoTakesCID(t, niko) {
		t.Skip("the niko-server at NIKO_SERVER_BIN does not route by connection ID (v0.18.0)")
	}
}

// nikoTakesCID reports whether the niko-server at niko takes the front's
// options of routable connection IDs.
func nikoTakesCID(t *testing.T, niko string) bool {
	t.Helper()
	dir := t.TempDir()
	cfg := `{"schema":1,"role":"front","backends":{"q":{"socket":"/run/q.sock","mode":"packet","uid":1,"cid_label":1}},
		"udp":{"listen":["127.0.0.1:443"],"routes":[{"sni":["q.example.com"],"backend":"q"}],"cid_keys_file":"/run/q.keys"}}`
	path := filepath.Join(dir, "front.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(niko, "check", "-c", path).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "cid_") {
		t.Fatalf("niko-server check: %v\n%s", err, out)
	}
	return err == nil
}

// datagramBack sends data to the echo in QUIC datagrams until one comes
// back, within: the first after a new address may go before the node has
// validated the path, and be lost.
func (n *naiveUDPNode) datagramBack(ctx context.Context, rs *http3.RequestStream, data string, within time.Duration) bool {
	want := append(n.head(), data...)
	end := time.Now().Add(within)
	for time.Now().Before(end) {
		if err := rs.SendDatagram(bytes.Clone(want)); err != nil {
			return false
		}
		rctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		got, err := rs.ReceiveDatagram(rctx)
		cancel()
		if err == nil && bytes.Equal(got, want) {
			return true
		}
	}
	return false
}

// TestQUICRebindWithNikoServer: a naive-quic client whose NAT gives it a
// new port mid-connection, through the niko-server front at
// NIKO_SERVER_BIN (v0.18.0 or later) with what render writes for it
// (spec/quic-cid-route-v1.md): the front's key and the services' labels,
// naive's label and secret, from which naive-quic's connection IDs carry
// its label. The front pins the new port by that label, quic-go validates
// the path and moves there, and the connect-udp request goes on carrying
// UDP, twice over. Rendered for the pin (no labels in the front), the
// connection is lost at the new port, as it was before. CI runs it with
// the pinned niko-server (v0.18.0 since raycontrol v0.31.0, v0.18.3 since
// v0.31.3, v0.18.4 since v0.35.1).
func TestQUICRebindWithNikoServer(t *testing.T) {
	niko := os.Getenv("NIKO_SERVER_BIN")
	if niko == "" {
		t.Skip("set NIKO_SERVER_BIN to a niko-server of v0.18.0 or later")
	}
	nikoRoutesByCID(t, niko)
	for _, c := range []struct {
		name     string
		tag      string
		survives bool
	}{
		{"labels", "v0.18.0", true},
		{"the front reads no labels", "v0.17.1", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			node := startNaiveUDPNodeFor(t, ctx, c.tag)
			relay := newNATRelay(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: node.port})
			_, rs := node.connectUDPVia(t, ctx, relay.in.LocalAddr().String())
			node.echoed(t, ctx, rs, "before")
			for i := range 2 {
				relay.rebind()
				got := node.datagramBack(ctx, rs, "after new port "+strconv.Itoa(i), 5*time.Second)
				if !c.survives {
					if got {
						t.Fatal("the connection went on without the front's labels")
					}
					return
				}
				if !got {
					t.Fatalf("no datagram back after new port %d", i)
				}
			}
			// What the node counted: one request, its datagrams.
			if s := node.ns.UDPStats(); s.Requests != 1 {
				t.Fatalf("%+v", s)
			}
		})
	}
}
