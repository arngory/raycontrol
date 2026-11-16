package h3serve

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/quiccid"
)

// scids is a server's socket that keeps the Source Connection IDs of the
// long-header packets it sends: the IDs a client addresses it by.
type scids struct {
	net.PacketConn
	mu  sync.Mutex
	ids [][]byte
}

func (s *scids) WriteTo(b []byte, addr net.Addr) (int, error) {
	// first byte, version (4), DCID length and DCID, SCID length and SCID
	if len(b) > 6 && b[0]&0x80 != 0 {
		if d := int(b[5]); len(b) > 7+d {
			if n := int(b[6+d]); len(b) >= 7+d+n {
				s.mu.Lock()
				s.ids = append(s.ids, bytes.Clone(b[7+d:7+d+n]))
				s.mu.Unlock()
			}
		}
	}
	return s.PacketConn.WriteTo(b, addr)
}

// With Options.ConnIDs the server's connection IDs are the generator's:
// 8 bytes that carry the backend's label under the node's secret
// (spec/quic-cid-route-v1.md). A generator of another length is refused.
func TestConnIDs(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, quiccid.SecretLen)
	gen, err := quiccid.NewGenerator(secret, 4242)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc := &scids{PacketConn: udp}
	cert := selfSigned(t)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	o := Options{Idle: time.Minute, MaxStreams: 100, PendingStreams: 10, MaxHeaderBytes: 16 << 10, ConnIDs: gen}
	go func() {
		done <- Serve(ctx, pc, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), o)
	}()
	defer func() {
		stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}},
		Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, udp.LocalAddr().String(), tlsConf, conf)
		}}
	defer tr.Close()
	req, _ := http.NewRequest(http.MethodGet, "https://h3.test/", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	codec, _ := quiccid.NewCodec(secret)
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if len(pc.ids) == 0 {
		t.Fatal("no long header from the server")
	}
	for _, id := range pc.ids {
		if label, ok := codec.Label(id); len(id) != ConnIDLen || !ok || label != 4242 {
			t.Fatalf("server connection ID %x: label %d %v", id, label, ok)
		}
	}

	short := shortIDs{}
	err = Serve(context.Background(), udp, nil, nil, Options{ConnIDs: short})
	if err == nil {
		t.Fatal("IDs of 4 bytes served")
	}
}

type shortIDs struct{}

func (shortIDs) GenerateConnectionID() (quic.ConnectionID, error) {
	return quic.ConnectionIDFromBytes([]byte{1, 2, 3, 4}), nil
}
func (shortIDs) ConnectionIDLen() int { return 4 }
