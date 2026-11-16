package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	h3qlog "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/arngory/raycontrol/internal/naive"
)

// h3Seen is what a QUIC client learns of a server before any password:
// the transport parameters and the HTTP/3 SETTINGS it was sent.
type h3Seen struct {
	mu       sync.Mutex
	params   *qlog.ParametersSet
	settings *h3qlog.SettingsFrame
}

func (s *h3Seen) AddProducer() qlogwriter.Recorder { return s }
func (s *h3Seen) SupportsSchemas(string) bool      { return true }
func (s *h3Seen) Close() error                     { return nil }

func (s *h3Seen) RecordEvent(e qlogwriter.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch e := e.(type) {
	case qlog.ParametersSet:
		if e.Initiator == qlog.InitiatorRemote {
			s.params = &e
		}
	case h3qlog.FrameParsed:
		switch f := e.Frame.Frame.(type) {
		case h3qlog.SettingsFrame:
			s.settings = &f
		case *h3qlog.SettingsFrame:
			s.settings = f
		}
	}
}

// serveQUIC serves h as rayd serves a name over QUIC, on a UDP socket of
// loopback, and gives its address.
func serveQUIC(t *testing.T, h http.Handler, cert tls.Certificate, o quicOptions) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveHTTP3(ctx, pc, fixedCert(cert), h, o) }()
	t.Cleanup(func() {
		stop()
		if err := <-done; err != nil {
			t.Errorf("serveHTTP3: %v", err)
		}
	})
	return pc.LocalAddr().String()
}

func testResetKey(t *testing.T) *quic.StatelessResetKey {
	t.Helper()
	var key quic.StatelessResetKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return &key
}

// strangerReset sends a server a packet of no connection it knows, with a
// connection ID of the sender's choice in front, and gives the stateless
// reset that comes back.
func strangerReset(t *testing.T, addr string, id []byte) []byte {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := make([]byte, 100)
	_, _ = rand.Read(p)
	p[0] = p[0]&0x7f | 0x40 // a short header
	copy(p[1:], id)
	buf := make([]byte, 1500)
	for range 20 {
		_, _ = c.Write(p)
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if n, err := c.Read(buf); err == nil && n >= 21 {
			return append([]byte(nil), buf[:n]...)
		}
	}
	t.Fatal("no stateless reset")
	return nil
}

// quicFace is what a client without a password or a token learns of a
// QUIC server: its transport parameters and HTTP/3 SETTINGS (each
// connection's own IDs and token taken out), its answer to a request that
// is not its, and the length of its stateless reset.
type quicFace struct {
	params   qlog.ParametersSet
	settings h3qlog.SettingsFrame
	status   int
	reset    int // a stateless reset's length
}

// naive-quic and DoH3 are not told from each other by one who has no
// password and no token: the same transport parameters, connection IDs of
// the same length, the same HTTP/3 SETTINGS, the same answer to a request
// that is not theirs, and a stateless reset from both for a packet of no
// connection.
func TestQUICNamesLookAlike(t *testing.T) {
	ns, cert := naiveTest(t, sink)
	faces := quicFaces(t, map[string]string{
		"naive-quic": serveQUIC(t, ns, cert, quicOptions{resetKey: testResetKey(t)}),
		"DoH3":       serveQUIC(t, noTokens(), cert, quicOptions{resetKey: testResetKey(t)}),
	})
	n, d := faces["naive-quic"], faces["DoH3"]
	if !reflect.DeepEqual(n, d) {
		t.Errorf("naive-quic is told from DoH3:\n naive-quic %+v\n DoH3       %+v", n, d)
	}
	if n.params.InitialMaxStreamsBidi != naive.MaxStreams || n.settings.MaxFieldSectionSize != naive.MaxHeaderBytes || n.status != http.StatusNotFound {
		t.Errorf("naive-quic: %d streams, %d bytes of header, status %d", n.params.InitialMaxStreamsBidi, n.settings.MaxFieldSectionSize, n.status)
	}
}

// naive-quic with udp=on announces HTTP/3 datagrams to whoever completes a
// handshake (spec/naive-udp-v1.md §7, §10.1): max_datagram_frame_size in
// its transport parameters and SETTINGS_H3_DATAGRAM. DoH3 on the same
// address does not, and those two lines are all that tells them apart
// here. They change what each does too, after the handshake as they come:
// DoH3 closes a connection that sends a DATAGRAM frame (quic-go's
// FRAME_ENCODING_ERROR, as for any frame not negotiated), and naive-quic
// closes with H3_SETTINGS_ERROR one whose SETTINGS announce HTTP/3
// datagrams without the transport parameter (RFC 9297 §2.1.1). Neither
// tells a prober more than the transport parameter does.
func TestQUICNamesDatagrams(t *testing.T) {
	ns, cert := naiveTest(t, sink)
	o := naiveUDP(ns, true)
	o.resetKey = testResetKey(t)
	faces := quicFaces(t, map[string]string{
		"naive-quic": serveQUIC(t, ns, cert, o),
		"DoH3":       serveQUIC(t, noTokens(), cert, quicOptions{resetKey: testResetKey(t)}),
	})
	n, d := faces["naive-quic"], faces["DoH3"]
	if n.settings.Datagram == nil || !*n.settings.Datagram || n.params.MaxDatagramFrameSize != 16383 {
		t.Fatalf("naive-quic with udp=on: SETTINGS_H3_DATAGRAM %v, max_datagram_frame_size %d", n.settings.Datagram, n.params.MaxDatagramFrameSize)
	}
	if d.settings.Datagram != nil || d.params.MaxDatagramFrameSize == 16383 {
		t.Fatalf("DoH3: SETTINGS_H3_DATAGRAM %v, max_datagram_frame_size %d", d.settings.Datagram, d.params.MaxDatagramFrameSize)
	}
	n.settings.Datagram, n.params.MaxDatagramFrameSize = d.settings.Datagram, d.params.MaxDatagramFrameSize
	if !reflect.DeepEqual(n, d) {
		t.Errorf("naive-quic with udp=on is told from DoH3 by more than datagrams:\n naive-quic %+v\n DoH3       %+v", n, d)
	}
}

// quicFaces are the faces of the servers at their addresses, by name.
func quicFaces(t *testing.T, servers map[string]string) map[string]quicFace {
	t.Helper()
	faces := map[string]quicFace{}
	for name, addr := range servers {
		seen := &h3Seen{}
		tr := &http3.Transport{TLSClientConfig: naiveClientTLS(),
			QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second,
				Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return seen }},
			Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, addr, tlsConf, conf)
			}}
		req, _ := http.NewRequest(http.MethodGet, "https://naive.test/", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
		var f quicFace
		deadline := time.Now().Add(5 * time.Second)
		for {
			seen.mu.Lock()
			ok := seen.params != nil && seen.settings != nil
			if ok {
				f = quicFace{params: *seen.params, settings: *seen.settings, status: resp.StatusCode}
			}
			seen.mu.Unlock()
			if ok {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: the client saw no transport parameters or no SETTINGS", name)
			}
			time.Sleep(10 * time.Millisecond)
		}
		_ = tr.Close()
		// What is each connection's own: its IDs, and the token of one.
		if n := f.params.InitialSourceConnectionID.Len(); n != quicConnIDLen {
			t.Errorf("%s: a connection ID of %d bytes, want %d", name, n, quicConnIDLen)
		}
		if f.params.StatelessResetToken == nil {
			t.Errorf("%s: no stateless reset token", name)
		}
		f.params.InitialSourceConnectionID, f.params.OriginalDestinationConnectionID = quic.ConnectionID{}, quic.ConnectionID{}
		f.params.StatelessResetToken = nil
		f.reset = len(strangerReset(t, addr, []byte{1, 2, 3, 4, 5, 6, 7, 8}))
		faces[name] = f
	}
	return faces
}

// The token of a stateless reset is a function of the service's key and a
// connection ID of quicConnIDLen bytes: the server tells the token of any
// ID that is not live to whoever asks, at every start the same, so the IDs
// must be too many to ask for all. With quic-go's 4 bytes the whole table
// was 2^32 tokens.
func TestResetTokenByConnectionID(t *testing.T) {
	if quicConnIDLen < 8 {
		t.Fatalf("connection IDs of %d bytes: 2^%d reset tokens can be read out", quicConnIDLen, 8*quicConnIDLen)
	}
	ns, cert := naiveTest(t, sink)
	key := testResetKey(t)
	id := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	token := func(id []byte) []byte {
		mac := hmac.New(sha256.New, key[:])
		mac.Write(id)
		return mac.Sum(nil)[:16]
	}
	for range 2 { // a process, and the one started after it
		reset := strangerReset(t, serveQUIC(t, ns, cert, quicOptions{resetKey: key}), id)
		got := reset[len(reset)-16:]
		if !bytes.Equal(got, token(id)) {
			t.Fatalf("the token of %x is %x, want that of all its %d bytes, %x", id, got, len(id), token(id))
		}
		if bytes.Equal(got, token(id[:4])) {
			t.Fatalf("the token of %x is that of its first four bytes", id)
		}
	}
}

func heldMemory() (bytes uint64, goroutines int) {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse + m.StackInuse, runtime.NumGoroutine()
}

// A QUIC peer without a password cannot pin the process with streams it
// never sends a request on. It opens every stream a connection may have
// and sends on each three bytes: a HEADERS frame said to be 8 KiB long, and
// nothing of it. Only naive.PendingStreams of them are taken, each has the
// header's time, and when that is over the connection is closed and
// nothing of it is left. (http3.Server's own loop took all 1348 and waited
// without an end: 22 MiB a connection for 4 KiB sent.)
func TestQUICPendingHeaders(t *testing.T) {
	const headerWait = time.Second
	ns, cert := naiveTest(t, sink)
	addr := serveQUIC(t, ns, cert, quicOptions{headerWait: headerWait})
	before, goroutines := heldMemory()

	// The peer, in a function of its own: what it holds of its connection
	// is not the server's, and is let go before the count.
	var pinned int64 // the process's memory while the streams wait, the peer's own with it
	streams, during := func() (streams, during int) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		conn, err := quic.DialAddr(ctx, addr, naiveClientTLS("h3"), &quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.CloseWithError(0, "") }()
		for {
			octx, stop := context.WithTimeout(ctx, 300*time.Millisecond)
			str, err := conn.OpenStreamSync(octx)
			stop()
			if err != nil {
				break // the server's cap, or its close
			}
			// HEADERS (type 1), length 8192 as a two-byte varint.
			if _, err := str.Write([]byte{0x01, 0x60, 0x00}); err != nil {
				break
			}
			streams++
		}
		if streams < naive.PendingStreams {
			t.Fatalf("the peer opened %d streams only", streams)
		}
		// While the headers have their time: no more than PendingStreams
		// are served, whatever the peer opened.
		var held uint64
		held, during = heldMemory()
		pinned = int64(held) - int64(before)
		// Then the server closes the connection, and says why.
		select {
		case <-conn.Context().Done():
			var app *quic.ApplicationError
			if cause := context.Cause(conn.Context()); !errors.As(cause, &app) || !app.Remote || app.ErrorCode != quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad) {
				t.Errorf("the connection ended with %v, want the server's H3_EXCESSIVE_LOAD", cause)
			}
		case <-time.After(headerWait + 10*time.Second):
			t.Fatalf("%d streams without a header were held past their time", streams)
		}
		return streams, during
	}()
	if extra := during - goroutines; extra > 3*naive.PendingStreams {
		t.Errorf("%d goroutines for %d streams without a header: more than the %d taken at a time need", extra, streams, naive.PendingStreams)
	}
	// Nothing of it is left.
	var after uint64
	var left int
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		after, left = heldMemory()
		if left <= goroutines+4 || time.Now().After(end) {
			break
		}
	}
	if left > goroutines+4 {
		t.Errorf("%d goroutines left of a connection that is closed", left-goroutines)
	}
	// 22 MiB when every stream had a goroutine and a buffer; what is held
	// now is the two QUIC connections' own (1348 streams each, here in one
	// process).
	if pinned > 12<<20 {
		t.Errorf("%d KiB held while %d streams waited for their headers", pinned>>10, streams)
	}
	t.Logf("%d streams of 3 bytes each: %d goroutines and %d KiB while they had their time, %d goroutines and %d KiB left after",
		streams, during-goroutines, pinned>>10, left-goroutines, (int64(after)-int64(before))>>10)
}

// A request whose header comes late, but within its time, is served, and
// the time it had for the header no longer bounds it: a tunnel lasts.
func TestQUICHeaderTime(t *testing.T) {
	const headerWait = 500 * time.Millisecond
	ns, cert := naiveTest(t, sink)
	tr := serveNaiveH3(t, ns, cert, quicOptions{headerWait: headerWait})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, pw := naiveConnect(ctx, t, "https://naive.test", "192.0.2.1:443")
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	defer resp.Body.Close()
	// Past the header's time the tunnel still reads what the client sends.
	time.Sleep(3 * headerWait)
	if _, err := naive.ClientStream(nil, pw).Write([]byte("still here")); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() {
		_, err := resp.Body.Read(make([]byte, 1))
		read <- err
	}()
	select {
	case err := <-read:
		t.Fatalf("the tunnel ended %v after its header's time: %v", 3*headerWait, err)
	case <-time.After(2 * headerWait):
	}
}
