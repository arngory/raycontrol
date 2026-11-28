package naive

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/h3serve"
	"github.com/arngory/raycontrol/internal/site"
)

// tunnelCost (F) is what an idle TCP tunnel holds of the process: its
// heap and its goroutines' stacks, measured over each transport with N
// idle tunnels whose client is another process (this test binary run
// again), so that the client's own streams are not counted. Not under the
// race detector, which makes every goroutine and allocation larger.
func TestTunnelCost(t *testing.T) {
	if testing.Short() || raceDetector {
		t.Skip("a measurement: not with -short or -race")
	}
	const n = 200
	overProtos(t, func(t *testing.T) {
		users := filepath.Join(t.TempDir(), "users.json")
		writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12"})
		answer, _ := site.Responder(site.Answer404, "")
		var mu sync.Mutex
		var ends []net.Conn // the destinations' ends, idle
		t.Cleanup(func() {
			mu.Lock()
			defer mu.Unlock()
			for _, c := range ends {
				c.Close()
			}
		})
		h := &Server{Users: &Users{Path: users}, Answer: answer, Log: slog.New(slog.DiscardHandler),
			Dial: func(context.Context, string, string) (net.Conn, error) {
				c, s := net.Pipe()
				mu.Lock()
				ends = append(ends, s)
				mu.Unlock()
				return c, nil
			}}
		h.mem.budget = 1 << 40
		var addr string
		switch protoOf(t) {
		case "h2":
			addr = serveNaive(t, h)
		case "h3":
			addr = serveH3(t, h)
		}
		heap := func() int64 {
			runtime.GC()
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			return int64(m.HeapInuse + m.StackInuse) //nolint:gosec // G115: a test's heap
		}
		// A first tunnel: the connection, its buffers, the server's pools.
		child := costClient(t, protoOf(t), addr, 1)
		eventually(t, "the first tunnel", func() bool { return h.MemoryStats().Charge == tunnelCost })
		before := heap()
		child.more(n)
		end := time.Now().Add(20 * time.Second)
		for h.MemoryStats().Charge != (n+1)*tunnelCost {
			if time.Now().After(end) {
				t.Fatalf("%d of %d tunnels", h.MemoryStats().Charge/tunnelCost, n+1)
			}
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
		per := (heap() - before) / n
		t.Logf("%s: %d KiB a tunnel (F is %d KiB)", protoOf(t), per>>10, tunnelCost>>10)
		if per > tunnelCost {
			t.Errorf("an idle tunnel holds %d KiB, more than F (%d KiB)", per>>10, tunnelCost>>10)
		}
	})
}

// serveH3 serves h over HTTP/3 as rayd does (serveOver's), and gives its
// address.
func serveH3(t *testing.T, h *Server) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := testCert(t)
	h.H3Conn = func(ctx context.Context) any {
		if c := h3serve.Conn(ctx); c != nil {
			return c
		}
		return nil
	}
	so := h3Options()
	so.Window = func(c *quic.Conn, done <-chan struct{}, delta uint64) bool { return h.AllowH3Window(c, done, delta) }
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- h3serve.Serve(ctx, pc, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, h, so)
	}()
	t.Cleanup(func() {
		stop()
		<-done
	})
	return pc.LocalAddr().String()
}

// costChild is the client process of TestTunnelCost.
type costChild struct {
	in  io.WriteCloser
	out *bufio.Reader
	t   *testing.T
}

// costClient starts the client process with n tunnels open.
func costClient(t *testing.T, proto, addr string, n int) *costChild {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestTunnelCostClient$") //nolint:gosec // G204: this test binary
	cmd.Env = append(os.Environ(), "NAIVE_COST_CLIENT="+proto+" "+addr)
	in, _ := cmd.StdinPipe()
	outPipe, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		in.Close()
		_ = cmd.Wait()
	})
	c := &costChild{in: in, out: bufio.NewReader(outPipe), t: t}
	c.more(n)
	return c
}

// more opens n more tunnels and waits for their 200s.
func (c *costChild) more(n int) {
	c.t.Helper()
	fmt.Fprintf(c.in, "%d\n", n)
	for {
		line, err := c.out.ReadString('\n')
		if err != nil {
			c.t.Fatalf("the client: %v", err)
		}
		if strings.HasPrefix(line, "open ") {
			return
		}
	}
}

// TestTunnelCostClient is TestTunnelCost's client, in a process of its own:
// for each number it reads, that many tunnels more, held open until its
// input ends.
func TestTunnelCostClient(t *testing.T) {
	spec := os.Getenv("NAIVE_COST_CLIENT")
	if spec == "" {
		t.Skip("TestTunnelCost's client")
	}
	proto, addr, _ := strings.Cut(spec, " ")
	var tr http.RoundTripper
	url := addr
	if proto == "h3" {
		url = "https://naive.test"
		tr = &http3.Transport{TLSClientConfig: testClientTLS(), QUICConfig: &quic.Config{MaxIdleTimeout: time.Minute},
			Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, addr, tlsConf, conf)
			}}
	} else {
		tr = &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: testClientTLS("h2")}
	}
	in := bufio.NewScanner(os.Stdin)
	open := 0
	for in.Scan() {
		n, _ := strconv.Atoi(in.Text())
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				pr, _ := io.Pipe()
				req, _ := http.NewRequest(http.MethodConnect, url, pr)
				req.Host = "192.0.2.1:443"
				req.Header.Set("Padding", paddingHeader())
				req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:pw")))
				resp, err := tr.RoundTrip(req)
				if err != nil || resp.StatusCode != http.StatusOK {
					fmt.Fprintln(os.Stderr, "cost client:", resp, err)
				}
			})
		}
		wg.Wait()
		open += n
		fmt.Printf("open %d\n", open)
	}
}
