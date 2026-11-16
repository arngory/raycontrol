package xrayapi_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/h3serve"
	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/nikoipc"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// TestNaiveUDPWithNikoServer: naive-udp-v1 through the pinned niko-server
// front, as a node runs it. A naive service with udp=on, rendered; its
// link says udp=1; the front routes QUIC for the naive name to rayd
// naive's packet socket (udpmux, R3-5), where h3serve serves it with
// datagrams as rayd naive -udp does. A connect-udp request through the
// front carries UDP both ways: a QUIC datagram, and a capsule for what does
// not fit the node's packets of 1250 bytes. Set NIKO_SERVER_BIN.
func TestNaiveUDPWithNikoServer(t *testing.T) {
	niko := os.Getenv("NIKO_SERVER_BIN")
	if niko == "" {
		t.Skip("set NIKO_SERVER_BIN to the pinned niko-server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "127.0.0.1", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true,
		Settings: `{"ports":["tcp/` + strconv.Itoa(port) + `"]}`}); err != nil {
		t.Fatal(err)
	}
	naiveSvc, err := provision.CreateService(ctx, st, store.Service{Kind: "naive", Name: "naive", Enabled: true, Settings: `{"udp":true}`})
	if err != nil {
		t.Fatal(err)
	}
	var naiveName struct{ SNI string }
	_ = json.Unmarshal([]byte(naiveSvc.Settings), &naiveName)
	siteSvc, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	// The site's certificate, which naive answers under.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: naiveName.SNI}, DNSNames: []string{naiveName.SNI},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	st.SetServiceSecret(ctx, siteSvc.ID, provision.SecretTLSKey, keyDER)
	st.SetServiceSecret(ctx, siteSvc.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	user, _ := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{naiveSvc.ID})

	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
	for _, d := range []string{paths.FrontDir("reality"), filepath.Dir(paths.NaiveSocket("naive")), filepath.Dir(paths.SiteSocket("site"))} {
		os.MkdirAll(d, 0o755)
	}
	files, _, err := render.Render(m, paths)
	if err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
	for _, f := range files {
		os.MkdirAll(filepath.Dir(f.Path), 0o755)
		os.WriteFile(f.Path, f.Content, 0o644)
	}
	if _, err := os.Stat(filepath.Join(paths.Rendered, "naive", render.NaiveUsers)); err != nil {
		t.Fatalf("naive not rendered: %v", err)
	}
	link, _ := url.Parse(sub.NaiveLink(m, m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.ID == naiveSvc.ID })],
		m.Creds[naiveSvc.ID][user.ID]))
	password, _ := link.User.Password()
	if link.Query().Get("udp") != "1" || link.Query().Get("uot") != "2" || password == "" {
		t.Fatalf("naive link %s", link.Redacted())
	}

	// rayd naive's sockets before the front, as on a node; its QUIC side
	// with datagrams, as rayd naive -udp serves it.
	quiet := slog.New(slog.DiscardHandler)
	nl, err := nikoipc.ListenFD(paths.NaiveSocket("naive"), os.Getuid(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer nl.Close()
	nl3, err := nikoipc.ListenPacket(paths.NaiveQUICSocket("naive"), os.Getuid(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	ns := &naive.Server{Users: &naive.Users{Path: filepath.Join(paths.Rendered, "naive", render.NaiveUsers)}, Answer: http.NotFoundHandler(),
		UDP: true, Log: quiet, Allow: func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") }}
	ns.H3 = func(ctx context.Context, w http.ResponseWriter) (func() naive.H3Stream, bool) {
		take, ok := h3serve.Datagrams(ctx, w)
		if !ok {
			return nil, false
		}
		return func() naive.H3Stream { return take() }, true
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	sctx, stop := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() {
		served <- h3serve.Serve(sctx, nl3, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, ns,
			h3serve.Options{Idle: render.QUICIdle, MaxStreams: naive.MaxStreams, PendingStreams: naive.PendingStreams,
				MaxHeaderBytes: naive.MaxHeaderBytes, Datagrams: true})
	}()
	defer func() {
		stop()
		<-served
	}()
	runFront(t, niko, filepath.Join(paths.Rendered, "front", "front.json"), port)

	// An echo the request reaches.
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	at := echo.LocalAddr().(*net.UDPAddr).AddrPort()

	// The client: QUIC to the front's port under the naive name, its
	// SETTINGS with datagrams, a connect-udp request with the link's
	// password.
	roots := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(der)
	roots.AddCert(leaf)
	qc, err := quic.DialAddr(ctx, "127.0.0.1:"+strconv.Itoa(port), &tls.Config{ServerName: naiveName.SNI, RootCAs: roots,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{http3.NextProtoH3}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("QUIC through the front: %v", err)
	}
	defer qc.CloseWithError(0, "")
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(qc)
	rs, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodConnect, "https://"+naiveName.SNI+"/.well-known/masque/udp/%2A/%2A/", nil)
	req.Proto = naive.ConnectUDP
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set(naive.UDPHeader, "1")
	req.Header.Set("Padding", naive.PaddingHeader())
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:"+password)))
	if err := rs.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	resp, err := rs.ReadResponse()
	if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get(naive.UDPHeader) != "1" {
		t.Fatalf("connect-udp through the front: %v %v", resp, err)
	}
	defer func() { rs.CancelRead(0); rs.CancelWrite(0) }()
	// [Context ID 2][4][address][port][data]
	head := append([]byte{2, 4}, at.Addr().AsSlice()...)
	head = binary.BigEndian.AppendUint16(head, at.Port())
	if err := rs.SendDatagram(append(bytes.Clone(head), "through the front"...)); err != nil {
		t.Fatal(err)
	}
	got, err := rs.ReceiveDatagram(ctx)
	if err != nil || !bytes.Equal(got, append(bytes.Clone(head), "through the front"...)) {
		t.Fatalf("datagram back: %q %v", got, err)
	}
	// 1300 bytes: more than the node's packets of 1250 take, a capsule each
	// way.
	big := bytes.Repeat([]byte{'c'}, 1300)
	capsule := append([]byte{0x00, 0x40 | byte((len(head)+len(big))>>8), byte(len(head) + len(big))}, head...)
	if _, err := rs.Write(append(capsule, big...)); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(capsule)+len(big))
	if _, err := io.ReadFull(rs, back); err != nil || !bytes.Equal(back, append(capsule, big...)) {
		t.Fatalf("capsule back: %d bytes, %v", len(back), err)
	}
	// An answer counts once the connection's sender handed it to QUIC, a
	// datagram once its write returned: either may come after the client
	// has the answer.
	for end := time.Now().Add(5 * time.Second); (ns.UDPStats().Out != 2 || ns.UDPStats().In != 2) && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	if s := ns.UDPStats(); s.Requests != 1 || s.In != 2 || s.Out != 2 || s.CapsulesIn != 1 || s.CapsulesOut != 1 {
		t.Fatalf("%+v", s)
	}
	// The end: the client's FIN, the node's.
	_ = rs.Close()
	if _, err := io.ReadAll(rs); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("the end: %v", err)
	}
}
