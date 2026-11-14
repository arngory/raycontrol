package xrayapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/arngory/raycontrol/internal/nikoipc"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/testca"
)

// frontPackets plays the front's UDP side for one client address: a
// net.PacketConn whose datagrams travel the backend's packet socket.
type frontPackets struct {
	c             *net.UnixConn
	client, local netip.AddrPort
}

func (f *frontPackets) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 1<<16+64)
	n, err := f.c.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	_, _, payload, err := nikoipc.Answer(buf[:n])
	if err != nil {
		return 0, nil, err
	}
	return copy(b, payload), net.UDPAddrFromAddrPort(f.local), nil
}

func (f *frontPackets) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nikoipc.Front(f.c, f.client, f.local, b)
}
func (f *frontPackets) Close() error                       { return f.c.Close() }
func (f *frontPackets) LocalAddr() net.Addr                { return net.UDPAddrFromAddrPort(f.client) }
func (f *frontPackets) SetDeadline(t time.Time) error      { return f.c.SetDeadline(t) }
func (f *frontPackets) SetReadDeadline(t time.Time) error  { return f.c.SetReadDeadline(t) }
func (f *frontPackets) SetWriteDeadline(t time.Time) error { return f.c.SetWriteDeadline(t) }

// lockedBuffer is a process's output, read while it still writes.
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

// TestRenewedChainWithNikoServer records what a niko-server backend does
// when the site's certificate is renewed (spec/cert-pin-v1.md §6, §12): the
// chain file is replaced as rayd's apply replaces it, the key stays. The
// pinned niko-server (v0.17.0) takes the new chain by itself: handshakes
// made after it get the new leaf from the same process, Hysteria2
// (hy2-masq, QUIC) and Yggdrasil (TLS over TCP) alike.
//
// raycontrol does not rely on it yet: live still restarts these backends
// when the chain changes (live's TestApplyCertificateRenewal), which cuts
// their users' sessions at every renewal. Marking their chain as a file
// the process rereads needs exactly what this test checks, so it has to
// pass on the pinned version first. Set NIKO_SERVER_BIN.
func TestRenewedChainWithNikoServer(t *testing.T) {
	niko := os.Getenv("NIKO_SERVER_BIN")
	if niko == "" {
		t.Skip("set NIKO_SERVER_BIN to the pinned niko-server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.test"}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"reality", "hy2-masq", "yggdrasil"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: kind, Name: kind, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	// The site's certificate from a test CA, which signs again for the
	// same key, as ACME does at a renewal.
	ca, err := testca.NewCA(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	issue := func() (chainPEM, leaf []byte) {
		t.Helper()
		chain, err := ca.Issue([]string{"*.example.test"}, &key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return testca.PEM(chain), chain[0]
	}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run"), Supervised: true}
	// apply writes the backends' rendered files as live does: a finished
	// file renamed over the old one, only when the content changed.
	apply := func() {
		t.Helper()
		m, err := render.CollectForRender(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		files, _, err := render.Render(m, paths)
		if err != nil && !render.Partial(err) {
			t.Fatal(err)
		}
		for _, f := range files {
			if f.Service != "hy2-masq" && f.Service != "yggdrasil" {
				continue
			}
			if old, err := os.ReadFile(f.Path); err == nil && bytes.Equal(old, f.Content) {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(f.Path), 0o750); err != nil {
				t.Fatal(err)
			}
			tmp := f.Path + ".tmp"
			if err := os.WriteFile(tmp, f.Content, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, f.Path); err != nil {
				t.Fatal(err)
			}
		}
	}
	chainPEM, first := issue()
	if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{
		provision.SecretTLSChain: chainPEM, provision.SecretTLSKey: keyDER}}); err != nil {
		t.Fatal(err)
	}
	apply()

	// start runs a backend as its unit does: its runtime directories, the
	// copies of its keys, then the process.
	start := func(service, socket string, credentials ...string) (*exec.Cmd, *lockedBuffer) {
		t.Helper()
		for _, d := range []string{filepath.Join(paths.Run, service), paths.FrontDir(service)} {
			if err := os.MkdirAll(d, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range credentials {
			b, err := os.ReadFile(filepath.Join(paths.Rendered, service, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(paths.Credential(service, name), b, 0o400); err != nil {
				t.Fatal(err)
			}
		}
		out := &lockedBuffer{}
		cmd := exec.Command(niko, "backend", "-c", filepath.Join(paths.Rendered, service, "backend.json"))
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		})
		for i := 0; ; i++ {
			if _, err := os.Stat(socket); err == nil {
				return cmd, out
			}
			if i == 400 {
				t.Fatalf("%s: no socket at %s:\n%s", service, socket, out)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.RootPEM)
	clientTLS := func(protos ...string) *tls.Config {
		return &tls.Config{RootCAs: roots, ServerName: "backend.example.test", NextProtos: protos,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	}
	local := netip.MustParseAddrPort("203.0.113.7:443")

	// Hysteria2: a QUIC handshake through the backend's packet socket.
	hySocket := paths.FrontSocket("hy2-masq", "packet")
	hyCmd, hyOut := start("hy2-masq", hySocket, render.HysteriaKey)
	port := uint16(40000)
	hysteria := func() ([]byte, error) {
		front, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: hySocket, Net: "unixpacket"})
		if err != nil {
			return nil, err
		}
		port++ // a new client address: a new connection for the backend
		pc := &frontPackets{c: front, client: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), port), local: local}
		defer pc.Close()
		dctx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		conn, err := quic.Dial(dctx, pc, net.UDPAddrFromAddrPort(local), clientTLS("h3"), nil)
		if err != nil {
			return nil, err
		}
		defer func() { _ = conn.CloseWithError(0, "") }()
		return conn.ConnectionState().TLS.PeerCertificates[0].Raw, nil
	}

	// Yggdrasil: a TLS handshake on a TCP connection passed to the backend's
	// fd socket; what follows TLS (the link's handshake) is not needed here.
	yggSocket := paths.FrontSocket("yggdrasil", "fd")
	yggCmd, yggOut := start("yggdrasil", yggSocket, render.YggdrasilTLSKey, render.YggdrasilNodeKey)
	yggFront, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: yggSocket, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer yggFront.Close()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	yggdrasil := func() ([]byte, error) {
		client, err := net.Dial("tcp", tcp.Addr().String())
		if err != nil {
			return nil, err
		}
		defer client.Close()
		accepted, err := tcp.Accept()
		if err != nil {
			return nil, err
		}
		src := netip.MustParseAddrPort(client.LocalAddr().String())
		err = nikoipc.Pass(yggFront, accepted.(*net.TCPConn), nikoipc.Handoff{Route: "yggdrasil", Src: src, Dst: local, SNI: "backend.example.test"})
		accepted.Close() // the backend has its own copy
		if err != nil {
			return nil, err
		}
		c := tls.Client(client, clientTLS())
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if err := c.Handshake(); err != nil {
			return nil, err
		}
		return c.ConnectionState().PeerCertificates[0].Raw, nil
	}

	backends := []struct {
		name      string
		handshake func() ([]byte, error)
		cmd       *exec.Cmd
		out       *lockedBuffer
	}{{"hy2-masq", hysteria, hyCmd, hyOut}, {"yggdrasil", yggdrasil, yggCmd, yggOut}}
	for _, b := range backends {
		if leaf, err := b.handshake(); err != nil || !bytes.Equal(leaf, first) {
			t.Fatalf("%s: the first handshake: %v\n%s", b.name, err, b.out)
		}
	}

	// The renewal: another chain for the same key.
	renewedPEM, renewed := issue()
	if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{provision.SecretTLSChain: renewedPEM}}); err != nil {
		t.Fatal(err)
	}
	apply()
	for _, b := range backends {
		taken := false
		for deadline := time.Now().Add(15 * time.Second); !taken && time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
			leaf, err := b.handshake()
			if err != nil {
				t.Fatalf("%s: a handshake after the renewal: %v\n%s", b.name, err, b.out)
			}
			taken = bytes.Equal(leaf, renewed)
		}
		if !taken {
			t.Errorf("%s still answers with the certificate it started with: it needs a restart for a renewal\n%s", b.name, b.out)
		}
		// The same process: it was not restarted, by anyone.
		if err := b.cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Errorf("%s exited: %v\n%s", b.name, err, b.out)
		}
	}
}
