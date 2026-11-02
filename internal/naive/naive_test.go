package naive

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/site"
)

func writeUsers(t *testing.T, path string, passwords ...string) {
	t.Helper()
	var hashes []string
	for _, p := range passwords {
		hashes = append(hashes, HashPassword(p))
	}
	b, _ := json.Marshal(hashes)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNaive(t *testing.T) {
	// The destination: an echo server.
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

	users := filepath.Join(t.TempDir(), "users.json")
	writeUsers(t, users, "secret-one")
	answer, _ := site.Responder(site.Answer404, "")
	var d net.Dialer
	h := &Server{Users: &Users{Path: users}, Answer: answer, Dial: d.DialContext, Log: slog.New(slog.DiscardHandler)}
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	srv.StartTLS()
	defer srv.Close()

	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2"},
	}}
	defer tr.CloseIdleConnections()
	connect := func(password string, padding bool) (*http.Response, *io.PipeWriter, error) {
		pr, pw := io.Pipe()
		req, err := http.NewRequest(http.MethodConnect, srv.URL, pr)
		if err != nil {
			return nil, nil, err
		}
		req.Host = echo.Addr().String()
		if padding {
			req.Header.Set("Padding", paddingHeader())
		}
		if password != "" {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:"+password)))
		}
		resp, err := tr.RoundTrip(req)
		return resp, pw, err
	}

	resp, pw, err := connect("secret-one", true)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Padding") == "" || resp.ProtoMajor != 2 {
		t.Fatalf("CONNECT: %s %v", resp.Status, resp.Header)
	}
	client := &paddedStream{r: resp.Body, w: pw}
	// More writes than padded frames: both framings are crossed.
	for i := range 12 {
		msg := bytes.Repeat([]byte{byte('a' + i)}, 100+i*1000)
		if _, err := client.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("echo %d: %v", i, err)
		}
	}
	pw.Close()
	resp.Body.Close()

	// The client closes its side first: what the destination still sends
	// arrives. The destination answers after it read everything.
	late, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer late.Close()
	go func() {
		c, err := late.Accept()
		if err != nil {
			return
		}
		got, _ := io.ReadAll(c)
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write(append([]byte("got "), got...))
		c.Close()
	}()
	pr2, pw2 := io.Pipe()
	req, _ := http.NewRequest(http.MethodConnect, srv.URL, pr2)
	req.Host = late.Addr().String()
	req.Header.Set("Padding", paddingHeader())
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:secret-one")))
	resp2, err := tr.RoundTrip(req)
	if err != nil || resp2.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %v %v", resp2, err)
	}
	half := &paddedStream{r: resp2.Body, w: pw2}
	if _, err := half.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	pw2.Close()
	answer2, _ := io.ReadAll(half)
	resp2.Body.Close()
	if string(answer2) != "got request" {
		t.Fatalf("after a half-close: %q", answer2)
	}

	// Whatever is not an authenticated naive CONNECT gets the site: an
	// empty 404, never 407.
	for name, c := range map[string]struct {
		password string
		padding  bool
	}{"wrong password": {"secret-two", true}, "no password": {"", true}, "no padding": {"secret-one", false}} {
		resp, pw, err := connect(c.password, c.padding)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		pw.Close()
		if resp.StatusCode != http.StatusNotFound || len(body) != 0 {
			t.Fatalf("%s: %s %q", name, resp.Status, body)
		}
	}
	get, err := (&http.Client{Transport: tr}).Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	get.Body.Close()
	if get.StatusCode != http.StatusNotFound {
		t.Fatalf("GET: %s", get.Status)
	}

	// A rotated credential: the file changes, the process reads it again.
	time.Sleep(10 * time.Millisecond)
	writeUsers(t, users, "secret-two")
	h.Users.mu.Lock()
	h.Users.checked = time.Time{}
	h.Users.mu.Unlock()
	if !h.Users.Accepts("secret-two") || h.Users.Accepts("secret-one") {
		t.Fatal("the users file was not read again")
	}
}

func TestPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"1.1.1.1": true, "2606:4700:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "192.168.1.1": false, "172.16.0.1": false, "100.64.1.1": false,
		"169.254.169.254": false, "::1": false, "fe80::1": false, "fd00::1": false, "0.0.0.0": false, "224.0.0.1": false,
		"::ffff:127.0.0.1": false,
	} {
		if got := Public(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Public(%s) = %v", addr, got)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if c, err := PublicDialer().DialContext(ctx, "tcp", ln.Addr().String()); err == nil || !strings.Contains(err.Error(), "not public") {
		if c != nil {
			c.Close()
		}
		t.Fatalf("dialed loopback: %v", err)
	}
}
