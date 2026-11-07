package sub_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/arngory/raycontrol/internal/appmirror"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/sub"
)

// writeRelease leaves a release in dir as a fetch does, SHA256SUMS signed
// as minisign signs (prehashed); it returns the public key.
func writeRelease(t *testing.T, dir, tag string, files map[string][]byte) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	var sums strings.Builder
	names := slices.Sorted(func(yield func(string) bool) {
		for n := range files {
			if !yield(n) {
				return
			}
		}
	})
	for _, n := range names {
		h := sha256.Sum256(files[n])
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), n)
	}
	sb := []byte(sums.String())
	h := blake2b.Sum512(sb)
	sig := ed25519.Sign(priv, h[:])
	trusted := appmirror.App + " " + tag
	global := ed25519.Sign(priv, append(slices.Clone(sig), trusted...))
	minisig := fmt.Sprintf("untrusted comment: test\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(append(append([]byte("ED"), id...), sig...)), trusted,
		base64.StdEncoding.EncodeToString(global))

	rd := filepath.Join(dir, appmirror.App, tag)
	if err := os.MkdirAll(rd, 0o700); err != nil {
		t.Fatal(err)
	}
	r := appmirror.Release{Tag: tag, Verified: time.Now().UTC()}
	put := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(rd, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		r.Files = append(r.Files, appmirror.File{Name: name, Size: int64(len(b)), SHA256: hex.EncodeToString(h[:])})
	}
	put("SHA256SUMS", sb)
	put("SHA256SUMS.minisig", []byte(minisig))
	for _, n := range names {
		put(n, files[n])
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rd, "release.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), id...), pub...))
}

// frozenConn stops reading the socket once frozen is set, as a frozen app
// that keeps its connection does: the receive window closes and the
// server's writes block in the kernel.
type frozenConn struct {
	net.Conn
	frozen *atomic.Bool
	thaw   <-chan struct{}
}

func (c *frozenConn) Read(p []byte) (int, error) {
	if c.frozen.Load() {
		<-c.thaw
	}
	return c.Conn.Read(p)
}

// appEnv is a node serving one release of 32 MiB through the real
// subscription server.
type appEnv struct {
	t    *testing.T
	f    fixture
	m    *appmirror.Mirror
	ctx  context.Context
	addr string
	size int
	thaw chan struct{}
}

func newAppEnv(t *testing.T, stall time.Duration) *appEnv {
	f := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dir := t.TempDir()
	big := make([]byte, 32<<20)
	_, _ = rand.Read(big)
	pub := writeRelease(t, dir, "v1.0.0", map[string][]byte{"niko.apk": big})
	m := &appmirror.Mirror{Store: f.st, Dir: dir, PubKey: pub, API: "https://127.0.0.1:1", Conn: probe.Conn, Stall: stall}
	if err := f.st.SetSetting(ctx, "app_mirror", []byte("on")); err != nil {
		t.Fatal(err)
	}
	go m.Run(ctx, nil)
	for i := 0; len(m.Status(ctx).Releases) != 1; i++ {
		if i == 100 {
			t.Fatal("the release was not loaded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet(), App: m, Stall: stall}
	go srv.Serve(ctx, addr, f.tlsCfg)
	e := &appEnv{t: t, f: f, m: m, ctx: ctx, addr: addr, size: len(big), thaw: make(chan struct{})}
	t.Cleanup(func() { close(e.thaw) })
	for i := 0; e.place() != 206; i++ {
		if i == 100 {
			t.Fatal("the server did not answer")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return e
}

// client: HTTP/2 or HTTP/1.1; frozen, when set, stops the reads of the
// socket; rcvbuf, when set, makes the socket's receive buffer small.
func (e *appEnv) client(h2 bool, frozen *atomic.Bool, rcvbuf int) *http.Client {
	p := new(http.Protocols)
	if h2 {
		p.SetHTTP2(true)
	} else {
		p.SetHTTP1(true)
	}
	tr := &http.Transport{
		Protocols:       p,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if rcvbuf > 0 {
				_ = conn.(*net.TCPConn).SetReadBuffer(rcvbuf)
			}
			if frozen == nil {
				return conn, nil
			}
			return &frozenConn{Conn: conn, frozen: frozen, thaw: e.thaw}, nil
		},
	}
	if frozen != nil && h2 {
		// Flow control never holds the server: the socket does.
		tr.HTTP2 = &http.HTTP2Config{MaxReceiveBufferPerStream: 1 << 30, MaxReceiveBufferPerConnection: 1 << 30}
	}
	e.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

func (e *appEnv) req(hdr ...string) *http.Request {
	r, _ := http.NewRequestWithContext(e.ctx, "GET", "https://"+e.addr+appmirror.Path+"niko/v1.0.0/niko.apk", nil)
	r.Header.Set(sub.DeviceHeader, e.f.device.ID)
	r.Header.Set("Authorization", sub.AuthToken(e.f.key, time.Now().Unix()/60))
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	return r
}

// start begins a download and reads its first 256 KiB.
func (e *appEnv) start(c *http.Client, wantProto int) *http.Response {
	resp, err := c.Do(e.req())
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != 200 || resp.ProtoMajor != wantProto {
		e.t.Fatalf("%s %d", resp.Proto, resp.StatusCode)
	}
	if _, err := io.ReadFull(resp.Body, make([]byte, 256<<10)); err != nil {
		e.t.Fatal(err)
	}
	return resp
}

// downloads under way on the node.
func (e *appEnv) downloads() int { return e.m.Status(e.ctx).Downloads }

// place asks for one byte as the same device: 206 once the server answers.
func (e *appEnv) place() int {
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	defer c.CloseIdleConnections()
	resp, err := c.Do(e.req("Range", "bytes=0-0"))
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// A download whose client stops taking bytes gives its place back within
// about Stall (app-update-v1 §2): over HTTP/1.1 by the connection's write
// deadline; over HTTP/2 with the socket unread by the server's
// WriteByteTimeout (a stream's deadline only queues a reset behind the
// frame the stalled socket holds: the place was held until rayd restarted);
// over HTTP/2 with the socket read and the body not, by the stream's
// deadline.
func TestAppStalledDownload(t *testing.T) {
	const stall = 2 * time.Second
	for _, c := range []struct {
		name   string
		h2     bool
		freeze bool // the socket unread, else the body
	}{
		{"http1 socket", false, true},
		{"http2 socket", true, true},
		{"http2 body", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newAppEnv(t, stall)
			var frozen atomic.Bool
			var fc *atomic.Bool
			if c.freeze {
				fc = &frozen
			}
			e.start(e.client(c.h2, fc, 0), map[bool]int{false: 1, true: 2}[c.h2])
			frozen.Store(true) // and the body is no longer read
			if n := e.downloads(); n != 1 {
				t.Fatalf("while the download goes on: %d under way", n)
			}
			start := time.Now()
			for e.downloads() != 0 {
				if time.Since(start) > 3*stall+5*time.Second {
					t.Fatalf("the place still held %s after the client stopped (Stall %s)", time.Since(start).Round(time.Second), stall)
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Logf("the place free %s after the client stopped", time.Since(start).Round(100*time.Millisecond))
		})
	}
}

// A phone that changed networks resumes at once on a new connection; the
// old one, silent, would hold the device's place until Stall (60 s), past
// the client's retries on 429. The new download cuts it and goes on.
func TestAppDownloadTakeover(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			t.Parallel()
			e := newAppEnv(t, time.Minute)
			var frozen atomic.Bool
			e.start(e.client(h2, &frozen, 0), map[bool]int{false: 1, true: 2}[h2])
			frozen.Store(true)
			start := time.Now()
			resp, err := e.client(h2, nil, 0).Do(e.req("Range", "bytes=1000-"))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			n, err := io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != 206 || err != nil || n != int64(e.size-1000) {
				t.Fatalf("the resume: %d, %d bytes, %v", resp.StatusCode, n, err)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("the resume took %s", d)
			}
			for i := 0; e.downloads() != 0; i++ {
				if i == 100 {
					t.Fatalf("%d downloads under way after both", e.downloads())
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// A slow client that keeps reading is not cut, past Stall many times
// over (§2: only a download whose piece does not leave for Stall is): the
// writes wait on it in small steps, however large the kernel's buffers.
func TestAppSlowDownload(t *testing.T) {
	const stall = time.Second
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			t.Parallel()
			e := newAppEnv(t, stall)
			resp := e.start(e.client(h2, nil, 32<<10), map[bool]int{false: 1, true: 2}[h2])
			// ~160 KB/s for 5 Stall: the server's writes block on the
			// client again and again.
			buf := make([]byte, 8<<10)
			for start := time.Now(); time.Since(start) < 5*stall; {
				if _, err := io.ReadFull(resp.Body, buf); err != nil {
					t.Fatalf("cut after %s: %v", time.Since(start).Round(100*time.Millisecond), err)
				}
				time.Sleep(50 * time.Millisecond)
			}
			if n := e.downloads(); n != 1 {
				t.Errorf("%d downloads under way, want 1", n)
			}
		})
	}
}
