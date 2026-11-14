package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/arngory/raycontrol/internal/certfile"
	"github.com/arngory/raycontrol/internal/nikoipc"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/testca"
)

// testCommand makes the test binary run one of rayd's commands, as its
// unit does: the tests below start it as a process of its own.
const testCommand = "RAYD_TEST_COMMAND"

func TestMain(m *testing.M) {
	if cmd := os.Getenv(testCommand); cmd != "" {
		var err error
		switch cmd {
		case "naive":
			err = cmdNaive(os.Args[1:])
		case "site":
			err = cmdSite(os.Args[1:])
		default:
			err = errors.New("not a command of the tests")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "rayd "+cmd+":", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const reloadName = "n.example.test"

// reloadCA is one CA for these tests (its keys take seconds to make), and
// what clients trust.
var reloadCA = sync.OnceValues(func() (*testca.CA, error) {
	return testca.NewCA(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
})

type siteKeyPair struct {
	key *rsa.PrivateKey
	pem []byte // PKCS#8, PEM
	der []byte // PKCS#8
}

func newSiteKeyPair(t *testing.T) siteKeyPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return siteKeyPair{key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), der}
}

// issueChain is a new certificate for the key, as a renewal gives one:
// PEM, and the leaf in DER.
func issueChain(t *testing.T, k siteKeyPair) (chainPEM, leaf []byte) {
	t.Helper()
	ca, err := reloadCA()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.Issue([]string{"*.example.test"}, &k.key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return testca.PEM(chain), chain[0]
}

func clientTLS(t *testing.T, protos ...string) *tls.Config {
	t.Helper()
	ca, err := reloadCA()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.RootPEM)
	return &tls.Config{RootCAs: roots, ServerName: reloadName, NextProtos: protos, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
}

// replaceFile writes as rayd's apply does: a finished file renamed over
// the old one.
func replaceFile(t *testing.T, path string, content []byte) {
	t.Helper()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		t.Fatal(err)
	}
}

// request sends one HTTP/1.1 request on a connection that stays open and
// reads the answer: the connection is alive.
func request(t *testing.T, c *tls.Conn, when string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "GET /nothing HTTP/1.1\r\nHost: "+reloadName+"\r\n\r\n"); err != nil {
		t.Fatalf("the open connection %s: %v", when, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("the open connection %s: %v", when, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the open connection %s: status %d", when, resp.StatusCode)
	}
}

// passed plays the front for a backend behind tcpmux: each handshake is a
// TCP connection whose socket it passes to the backend's socket.
func passed(t *testing.T, socket, route string) func() (*tls.Conn, []byte, error) {
	t.Helper()
	front, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: socket, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close() })
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	cfg := clientTLS(t, "http/1.1")
	return func() (*tls.Conn, []byte, error) {
		client, err := net.Dial("tcp", tcp.Addr().String())
		if err != nil {
			return nil, nil, err
		}
		t.Cleanup(func() { client.Close() })
		accepted, err := tcp.Accept()
		if err != nil {
			return nil, nil, err
		}
		src := netip.MustParseAddrPort(client.LocalAddr().String())
		err = nikoipc.Pass(front, accepted.(*net.TCPConn), nikoipc.Handoff{Route: route, Src: src, Dst: src, SNI: reloadName})
		accepted.Close() // the backend has its own copy
		if err != nil {
			return nil, nil, err
		}
		c := tls.Client(client, cfg)
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if err := c.Handshake(); err != nil {
			return nil, nil, err
		}
		return c, c.ConnectionState().PeerCertificates[0].Raw, nil
	}
}

// eventually makes handshakes until one gets the leaf want.
func eventually(t *testing.T, dial func() (*tls.Conn, []byte, error), want []byte, wait time.Duration) bool {
	t.Helper()
	for deadline := time.Now().Add(wait); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		c, leaf, err := dial()
		if err != nil {
			t.Fatalf("a handshake while waiting for the new certificate: %v", err)
		}
		c.Close()
		if bytes.Equal(leaf, want) {
			return true
		}
	}
	return false
}

// output is what a process or a logger wrote, read while it still writes.
type output struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.Write(p)
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.String()
}

// startCommand runs one of rayd's commands as a process of its own and
// returns it with what it logs.
func startCommand(t *testing.T, name string, args ...string) (*exec.Cmd, *output) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), testCommand+"="+name)
	out := &output{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	})
	return cmd, out
}

func waitSocket(t *testing.T, path string, out *output) {
	t.Helper()
	for range 200 {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("no socket at %s:\n%s", path, out)
}

// running reports that the process has not exited.
func running(cmd *exec.Cmd) bool { return cmd.Process.Signal(syscall.Signal(0)) == nil }

// reloadsWithoutRestart is the finding B6 for a process that reads its
// chain from a rendered file: the renewed chain, written as apply writes
// it, reaches the next handshake; the process is the same one and the
// connection that was open still answers.
func reloadsWithoutRestart(t *testing.T, cmd *exec.Cmd, out *output, chainFile string, k siteKeyPair, first []byte,
	dial func() (*tls.Conn, []byte, error)) {
	t.Helper()
	open, leaf, err := dial()
	if err != nil {
		t.Fatalf("the first handshake: %v\n%s", err, out)
	}
	if !bytes.Equal(leaf, first) {
		t.Fatal("the first handshake did not get the certificate of the files")
	}
	request(t, open, "before the renewal")

	renewedPEM, renewed := issueChain(t, k)
	replaceFile(t, chainFile, renewedPEM)
	// The process looks every certfile.DefaultEvery.
	if !eventually(t, dial, renewed, certfile.DefaultEvery+10*time.Second) {
		t.Fatalf("the renewed chain is not served:\n%s", out)
	}
	if !running(cmd) {
		t.Fatalf("the process exited:\n%s", out)
	}
	request(t, open, "after the renewal")
	if !strings.Contains(out.String(), "certificate reloaded") {
		t.Fatalf("no reload in the log:\n%s", out)
	}
}

// rayd naive, as its unit runs it: a renewal of the site's certificate
// cuts no tunnel.
func TestNaiveReloadsCertificate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	k := newSiteKeyPair(t)
	chainPEM, leaf := issueChain(t, k)
	chainFile, keyFile, users, socket := filepath.Join(dir, "chain.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "users.json"),
		filepath.Join(dir, "naive.sock")
	replaceFile(t, chainFile, chainPEM)
	replaceFile(t, keyFile, k.pem)
	replaceFile(t, users, []byte("{}\n"))
	cmd, out := startCommand(t, "naive", "-users", users, "-chain", chainFile, "-key", keyFile, "-socket", socket,
		"-front-uid", strconv.Itoa(os.Getuid()))
	waitSocket(t, socket, out)
	reloadsWithoutRestart(t, cmd, out, chainFile, k, leaf, passed(t, socket, "naive"))
}

// rayd site, the same: REALITY's target keeps answering through a renewal.
func TestSiteReloadsCertificate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	k := newSiteKeyPair(t)
	chainPEM, leaf := issueChain(t, k)
	chainFile, keyFile, socket := filepath.Join(dir, "chain.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "site.sock")
	replaceFile(t, chainFile, chainPEM)
	replaceFile(t, keyFile, k.pem)
	cmd, out := startCommand(t, "site", "-chain", chainFile, "-key", keyFile, "-socket", socket)
	waitSocket(t, socket, out)
	cfg := clientTLS(t, "http/1.1")
	dial := func() (*tls.Conn, []byte, error) {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "unix", socket, cfg)
		if err != nil {
			return nil, nil, err
		}
		t.Cleanup(func() { c.Close() })
		return c, c.ConnectionState().PeerCertificates[0].Raw, nil
	}
	reloadsWithoutRestart(t, cmd, out, chainFile, k, leaf, dial)
}

// DoH, which rayd serves itself with the certificate from the store: a new
// chain, and the site's next key with its chain, go to the listener as it
// runs; a chain that does not parse leaves the one in use; the connection
// that was open answers throughout.
func TestDoHReloadsCertificate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.test"}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"reality", "doh"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: kind, Name: kind, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	k := newSiteKeyPair(t)
	chainPEM, leaf := issueChain(t, k)
	set := func(chain, key []byte) {
		t.Helper()
		// Together, as the certificate manager stores them.
		if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{
			provision.SecretTLSChain: chain, provision.SecretTLSKey: key}}); err != nil {
			t.Fatal(err)
		}
	}
	set(chainPEM, k.der)

	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run"), Supervised: true}
	if err := os.MkdirAll(filepath.Dir(paths.DoHSocket("doh")), 0o750); err != nil {
		t.Fatal(err)
	}
	// The changes rayd's loops wake on, and how many rounds serveDoH began.
	var mu sync.Mutex
	wake, rounds := make(chan struct{}), 0
	changes := func() <-chan struct{} {
		mu.Lock()
		defer mu.Unlock()
		rounds++
		return wake
	}
	began := func() int {
		mu.Lock()
		defer mu.Unlock()
		return rounds
	}
	// settle wakes serveDoH and returns once it has been through the store
	// since: a second round has begun.
	settle := func() {
		t.Helper()
		for target := began() + 2; began() < target; {
			mu.Lock()
			old := wake
			wake = make(chan struct{})
			mu.Unlock()
			close(old)
			for at, i := began(), 0; began() == at && i < 400; i++ {
				time.Sleep(5 * time.Millisecond)
			}
		}
	}
	out := &output{}
	log := slog.New(slog.NewTextHandler(out, nil))
	done := make(chan struct{})
	go func() { serveDoH(ctx, st, paths, changes, log); close(done) }()
	defer func() { cancel(); <-done }()
	for i := 0; ; i++ {
		if _, err := os.Stat(paths.DoHSocket("doh")); err == nil {
			break
		}
		if i == 400 {
			t.Fatal("no DoH socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	dial := passed(t, paths.DoHSocket("doh"), "doh")
	served := func(what string, want []byte) {
		t.Helper()
		c, got, err := dial()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		c.Close()
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: another certificate is served", what)
		}
	}

	open, got, err := dial()
	if err != nil || !bytes.Equal(got, leaf) {
		t.Fatalf("the first handshake: %v", err)
	}
	request(t, open, "at the start")

	// A renewal: the same key.
	renewedPEM, renewed := issueChain(t, k)
	set(renewedPEM, k.der)
	settle()
	served("after the renewal", renewed)
	request(t, open, "after the renewal")

	// A chain that is none, and one for another key: the listener keeps
	// the certificate it has, and keeps running.
	other := newSiteKeyPair(t)
	otherPEM, otherLeaf := issueChain(t, other)
	for what, chain := range map[string][]byte{"garbage in the store": []byte("garbage"), "a chain for another key": otherPEM} {
		set(chain, k.der)
		settle()
		served(what, renewed)
	}
	request(t, open, "after the broken chains")

	// The site's next key with its chain (a key change): no restart either.
	set(otherPEM, other.der)
	settle()
	served("after the key change", otherLeaf)
	request(t, open, "after the key change")

	if c := strings.Count(out.String(), "doh serving"); c != 1 {
		t.Fatalf("the listener started %d times:\n%s", c, out.String())
	}
	if c := strings.Count(out.String(), "doh certificate reloaded"); c != 2 {
		t.Fatalf("%d reloads logged, want 2:\n%s", c, out.String())
	}
}

// HTTP/3 (naive-quic, DoH3) answers with the certificate of each handshake
// too: a QUIC connection made after the change gets the new one.
func TestHTTP3ReloadsCertificate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k := newSiteKeyPair(t)
	pair := func() (tls.Certificate, []byte) {
		chainPEM, leaf := issueChain(t, k)
		cert, err := tls.X509KeyPair(chainPEM, k.pem)
		if err != nil {
			t.Fatal(err)
		}
		return cert, leaf
	}
	first, firstLeaf := pair()
	certs := &certfile.Holder{}
	certs.Set(first)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveHTTP3(ctx, pc, certs.GetCertificate, http.NotFoundHandler()) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serveHTTP3: %v", err)
		}
	}()
	leafOf := func() []byte {
		t.Helper()
		dctx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		conn, err := quic.DialAddr(dctx, pc.LocalAddr().String(), clientTLS(t, "h3"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.CloseWithError(0, "")
		return conn.ConnectionState().TLS.PeerCertificates[0].Raw
	}
	if !bytes.Equal(leafOf(), firstLeaf) {
		t.Fatal("the first QUIC handshake did not get the first certificate")
	}
	second, secondLeaf := pair()
	certs.Set(second)
	if !bytes.Equal(leafOf(), secondLeaf) {
		t.Fatal("a QUIC handshake after the change did not get the new certificate")
	}
}

// rayd site completes a short chain with its root and refuses one too
// short for REALITY, at the start and at a reload alike (siteCertificate).
func TestSiteCertificate(t *testing.T) {
	k := newSiteKeyPair(t)
	chainPEM, _ := issueChain(t, k)
	cert, err := siteCertificate(chainPEM, k.pem)
	if err != nil || len(cert.Certificate) != 3 {
		t.Fatalf("the test chain: %d certificates, %v", len(cert.Certificate), err)
	}
	// The leaf alone, under a root the host does not know: too short.
	block, _ := pem.Decode(chainPEM)
	if _, err := siteCertificate(pem.EncodeToMemory(block), k.pem); err == nil || !strings.Contains(err.Error(), "REALITY needs") {
		t.Fatalf("a leaf alone: %v", err)
	}
	dir := t.TempDir()
	chainFile, keyFile := filepath.Join(dir, "chain.pem"), filepath.Join(dir, "key.pem")
	replaceFile(t, chainFile, chainPEM)
	replaceFile(t, keyFile, k.pem)
	l, err := loadCertificate(chainFile, keyFile, siteCertificate, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	replaceFile(t, chainFile, pem.EncodeToMemory(block))
	if changed, err := l.Reload(); changed || err == nil || len(l.Current().Certificate) != 3 {
		t.Fatalf("a leaf alone at a reload: changed %v, %v", changed, err)
	}
}
