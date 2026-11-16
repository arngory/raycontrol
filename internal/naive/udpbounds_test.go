package naive

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/h3serve"
	"github.com/arngory/raycontrol/internal/site"
)

// loudUDP is a destination on loopback that answers each datagram with n
// datagrams of size bytes, and counts the datagrams it got by size.
func loudUDP(t *testing.T, n, size int) (netip.AddrPort, func(size int) int) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	var got [70000]atomic.Int32
	go func() {
		buf := make([]byte, 70000)
		for {
			m, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			got[m].Add(1)
			for range n {
				_, _ = c.WriteToUDPAddrPort(bytes.Repeat([]byte{'L'}, size), from)
			}
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).AddrPort(), func(size int) int { return int(got[size].Load()) }
}

// quicInitial is a QUIC v1 packet with a long header, n bytes long.
func quicInitial(n int) []byte {
	b := binary.BigEndian.AppendUint32([]byte{0xc3}, 1)
	b = append(b, 8)
	return append(b, make([]byte, n-len(b))...)
}

func dropped(h *Server, kind int) int64 { return h.udp.dropped[kind].Load() }

// stacks counts the goroutines whose stacks have a frame of fn.
func stacks(fn string) int {
	buf := make([]byte, 16<<20)
	n := runtime.Stack(buf, true)
	c := 0
	for g := range strings.SplitSeq(string(buf[:n]), "\n\n") {
		if strings.Contains(g, fn) {
			c++
		}
	}
	return c
}

// droppingPC is a server's socket that drops what it sends while drop is
// set: a client whose network stops taking the node's packets, or one that
// acknowledges none, while it keeps sending.
type droppingPC struct {
	net.PacketConn
	drop atomic.Bool
}

func (d *droppingPC) WriteTo(b []byte, a net.Addr) (int, error) {
	if d.drop.Load() {
		return len(b), nil
	}
	return d.PacketConn.WriteTo(b, a)
}

// A client that keeps sending and acknowledges nothing keeps its
// connection's queue of datagrams full (quic-go's 32) for as long as it
// likes. Requests whose answers wait for that queue come and go, reset one
// after another: none waits in it, nothing of them outlives them, and what
// the process holds does not grow with their number. (Each one's sender of
// answers waited in quic-go's SendDatagram before, and stayed there with
// all it held after its request ended: some 100 KiB a request, without a
// bound.)
func TestUDPClientNotAcknowledging(t *testing.T) {
	loudAt, _ := loudUDP(t, 64, 1000)
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12"})
	answer, _ := site.Responder(site.Answer404, "")
	h := &Server{Users: &Users{Path: users}, Answer: answer, UDP: true, H3: h3Datagrams, Log: slog.New(slog.DiscardHandler)}
	h.Allow = func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") }
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc := &droppingPC{PacketConn: raw}
	cert := testCert(t)
	ctx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	so := h3Options()
	so.Datagrams = true
	go func() {
		served <- h3serve.Serve(ctx, pc, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, h, so)
	}()
	defer func() {
		stop()
		<-served
	}()
	qc, err := quic.DialAddr(t.Context(), raw.LocalAddr().String(), testClientTLS(http3.NextProtoH3),
		&quic.Config{MaxIdleTimeout: 60 * time.Second, EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer qc.CloseWithError(0, "")
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(qc)
	<-cc.ReceivedSettings()
	open := func(readAnswer bool) *http3.RequestStream {
		t.Helper()
		rs, err := cc.OpenRequestStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodConnect, "https://naive.test/.well-known/masque/udp/%2A/%2A/", nil)
		req.Proto = ConnectUDP
		req.Header.Set(UDPHeader, "1")
		req.Header.Set("Padding", paddingHeader())
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:pw")))
		if err := rs.SendRequestHeader(req); err != nil {
			t.Fatal(err)
		}
		if readAnswer {
			if resp, err := rs.ReadResponse(); err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("%v %v", resp, err)
			}
		}
		// One capsule to the loud destination: its answers fill the
		// connection's queue of datagrams.
		dg := udpDatagram(udpDest(loudAt), []byte("go"))
		if _, err := rs.Write(append(appendVarint(appendVarint(nil, capsuleDatagram), uint64(len(dg))), dg...)); err != nil {
			t.Fatal(err)
		}
		return rs
	}
	// One request as usual; then the client's network stops taking the
	// node's packets: nothing the node sends is acknowledged.
	open(true)
	time.Sleep(200 * time.Millisecond)
	pc.drop.Store(true)
	// The queues of the connection fill: a few rounds of requests first, so
	// that what is measured is what grows with their number.
	run := func(n int) {
		for range n {
			rs := open(false)
			time.Sleep(20 * time.Millisecond)
			rs.CancelRead(0) // the client is done with it: reset both ways
			rs.CancelWrite(0)
		}
		eventually(t, "the requests' places are held", func() bool { return h.lim.count() == 1 })
		time.Sleep(1500 * time.Millisecond) // past the writers' grace
	}
	run(10)
	heap0, requests0 := heapInUse(), stacks("internal/naive.(*udpRequest)")
	run(80)
	heap1, requests1 := heapInUse(), stacks("internal/naive.(*udpRequest)")
	senders, inQUIC := stacks("h3serve.(*sender).run"), stacks("(*datagramQueue).Add")
	t.Logf("held %+d KiB over 80 requests; goroutines of requests %d then %d; senders %d, in quic-go's queue %d; %+v",
		(int64(heap1)-int64(heap0))>>10, requests0, requests1, senders, inQUIC, h.UDPStats())
	// The first request, still open, has its reader, writer and readers
	// of datagrams and capsules; none of the 90 others has any.
	if requests1 > requests0 || requests1 > 4 {
		t.Errorf("goroutines of requests: %d after 10 resets, %d after 90", requests0, requests1)
	}
	// One sender for the connection, waiting in quic-go's queue; nothing
	// else of the node's waits there.
	if senders != 1 || inQUIC > 1 {
		t.Errorf("%d senders, %d goroutines in quic-go's queue of datagrams", senders, inQUIC)
	}
	// What grows is quic-go's: the state of each stream the client reset,
	// kept until the client acknowledges its end, which it never does here
	// (some 12 KiB a stream, the connection's streams at most; a heap
	// profile shows newStream and its frames). Before, each request also
	// left about 100 KiB of its own, 8 MiB in all.
	if grown := int64(heap1) - int64(heap0); grown > 3<<20 {
		t.Errorf("%d KiB more held after 80 more requests", grown>>10)
	}
	if dropped(h, dropQueue) == 0 {
		t.Error("nothing dropped from the queues")
	}
}

// The QUIC rule on the client's capsules (§4.4): a pair whose first
// datagram is QUIC's takes capsules of 1252 bytes at most; a longer one
// does not reach the destination. A capsule the rule drops makes no pair:
// the next datagram is still the pair's first. Another pair takes long
// capsules.
func TestUDPQUICRuleUpstream(t *testing.T) {
	dest, got := loudUDP(t, 0, 0)
	other, otherGot := loudUDP(t, 0, 0)
	h, c := udpServer(t, nil)
	q := c.open(udpRequestOf{})
	pairs := func() int {
		h.lim.mu.Lock()
		defer h.lim.mu.Unlock()
		return h.lim.users["u5"].pairs
	}
	// A long QUIC capsule first: dropped, and no pair of it.
	q.capsule(capsuleDatagram, udpDatagram(udpDest(dest), quicInitial(1300)))
	eventually(t, "not dropped by the QUIC rule", func() bool { return dropped(h, dropQUIC) == 1 })
	if p := pairs(); p != 0 || h.UDPStats().In != 0 {
		t.Fatalf("%d pairs, %d sent", p, h.UDPStats().In)
	}
	// A QUIC datagram makes the pair, marked.
	q.send(udpDest(dest), quicInitial(100))
	eventually(t, "the first datagram did not go", func() bool { return got(100) == 1 })
	// A long capsule of the pair's, QUIC or not, does not go; one of 1252
	// does.
	q.capsule(capsuleDatagram, udpDatagram(udpDest(dest), bytes.Repeat([]byte{'x'}, 1253)))
	q.capsule(capsuleDatagram, udpDatagram(udpDest(dest), quicInitial(1300)))
	q.capsule(capsuleDatagram, udpDatagram(udpDest(dest), quicInitial(quicCapsuleMax)))
	eventually(t, "1252 bytes did not go", func() bool { return got(quicCapsuleMax) == 1 })
	if got(1253) != 0 || got(1300) != 0 || dropped(h, dropQUIC) != 3 {
		t.Fatalf("past the rule: %d of 1253, %d of 1300; %d dropped", got(1253), got(1300), dropped(h, dropQUIC))
	}
	// A pair that began with something else takes them.
	q.send(udpDest(other), []byte("hello"))
	// The datagram and the capsule come by two ways: the capsule after.
	eventually(t, "the other pair's first datagram did not go", func() bool { return otherGot(len("hello")) == 1 })
	q.capsule(capsuleDatagram, udpDatagram(udpDest(other), quicInitial(1300)))
	eventually(t, "an unmarked pair's capsule did not go", func() bool { return otherGot(1300) == 1 })
}

// The longest HTTP datagram a client may send fits a capsule: its Context
// ID in the longest form a varint has (8 bytes), a name of 255 bytes, the
// port, 65 507 bytes of data. It reads, and goes; one byte more in a
// capsule resets the stream (TestReadCapsuleHead).
func TestUDPLongestCapsule(t *testing.T) {
	longest := append([]byte{0xc0, 0, 0, 0, 0, 0, 0, udpContext}, udpDestName(strings.Repeat("a", 255), 53)...)
	longest = append(longest, make([]byte, uotMaxPayload)...)
	if len(longest) != capsuleMax {
		t.Fatalf("the longest datagram is %d bytes, capsules take %d", len(longest), capsuleMax)
	}
	dest, data, why := parseUDP(longest)
	if why >= 0 || len(dest.name) != 255 || len(data) != uotMaxPayload {
		t.Fatalf("%d: %d bytes of name, %d of data", why, len(dest.name), len(data))
	}
	echo := udpEcho(t)
	_, c := udpServer(t, func(h *Server) {
		h.Resolve = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{echo.Addr()}, nil }
	})
	q := c.open(udpRequestOf{})
	longest = append([]byte{0xc0, 0, 0, 0, 0, 0, 0, udpContext}, udpDestName(strings.Repeat("a", 255), echo.Port())...)
	q.capsule(capsuleDatagram, append(longest, make([]byte, uotMaxPayload)...))
	// The echo's answer is past what the node passes back: the request
	// lives on.
	q.send(udpDest(echo), []byte("after"))
	if g := q.recv(); string(g.data) != "after" {
		t.Fatalf("%q", g.data)
	}
}

// A capsule that waited more than 100 ms since its answer came is dropped
// (§4.4): a client that opens its stream's window late gets the newest
// answers, not the stale ones; the queue keeps the newest (the oldest give
// way).
func TestUDPCapsuleLate(t *testing.T) {
	loudAt, _ := loudUDP(t, 64, 1400)
	h, c := udpServer(t, nil, udpOpts{window: 4 << 10})
	q := c.open(udpRequestOf{noRead: true})
	q.send(udpDest(loudAt), []byte("go"))
	eventually(t, "no capsule pushed out of the queue", func() bool { return dropped(h, dropQueue) > 0 })
	time.Sleep(300 * time.Millisecond)
	// The client reads now: what waited goes as late.
	go func() { _, _ = io.Copy(io.Discard, q.rs) }()
	eventually(t, "no capsule dropped as late", func() bool { return dropped(h, dropLate) > 0 })
	q.send(udpDest(loudAt), []byte("go"))
	eventually(t, "no fresh capsule after the late ones", func() bool { return h.UDPStats().CapsulesOut > 4 })
	t.Logf("%+v; late %d, queue %d", h.UDPStats(), dropped(h, dropLate), dropped(h, dropQueue))
}

// A socket that does not open is 503 before any answer, with Padding; the
// place is given back.
func TestUDP503(t *testing.T) {
	h, c := udpServer(t, func(h *Server) {
		h.udpSocket = func(context.Context) (*net.UDPConn, error) { return nil, errors.New("no sockets") }
	})
	q := c.open(udpRequestOf{})
	if q.resp.StatusCode != http.StatusServiceUnavailable || q.resp.Header.Get("Padding") == "" || q.resp.Header.Get(UDPHeader) != "" {
		t.Fatalf("%s %v", q.resp.Status, q.resp.Header)
	}
	if st := h.UDPStats(); st.Refused != 1 || st.Requests != 0 || h.lim.count() != 0 {
		t.Fatalf("%+v, %d places", st, h.lim.count())
	}
}

// With the per-user limits off (rayctl conn-limit off), datagram requests
// are as UoT's streams: no quiet one gives way at the user's 256, which
// stays; pairs are not counted.
func TestUDPConnLimitOff(t *testing.T) {
	echo := udpEcho(t)
	h, c := udpServer(t, nil)
	h.SetConnLimit(false)
	q := c.open(udpRequestOf{})
	q.send(udpDest(echo), []byte("x"))
	q.recv()
	h.lim.mu.Lock()
	pairs := h.lim.users["u5"].pairs
	h.lim.mu.Unlock()
	if pairs != 0 {
		t.Fatalf("%d pairs counted with the limits off", pairs)
	}
	for range uotPerUser - 1 {
		if s, _ := h.lim.uotTake("u5", func(error) {}); s == nil {
			t.Fatal("no place")
		}
	}
	h.lim.mu.Lock()
	for s := range h.lim.users["u5"].slots {
		s.last.Store(mono() - int64(quietAfter) - int64(time.Second))
	}
	h.lim.mu.Unlock()
	if over := c.open(udpRequestOf{}); over.resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over the limit with the limits off: %s", over.resp.Status)
	}
	q.send(udpDest(echo), []byte("still"))
	if g := q.recv(); string(g.data) != "still" {
		t.Fatalf("%q", g.data)
	}
}

// A new destination past the user's tokens for new destinations is
// dropped as limit; the request lives on, and its pairs go on.
func TestUDPDropLimit(t *testing.T) {
	echo := udpEcho(t)
	other := udpEcho(t)
	h, c := udpServer(t, nil)
	q := c.open(udpRequestOf{})
	q.send(udpDest(echo), []byte("x"))
	q.recv()
	h.lim.mu.Lock()
	h.lim.users["u5"].peers = bucket{0, h.lim.clock()}
	h.lim.mu.Unlock()
	q.send(udpDest(other), []byte("new"))
	eventually(t, "a new destination past the tokens not dropped", func() bool { return dropped(h, dropLimit) == 1 })
	q.send(udpDest(echo), []byte("old"))
	if g := q.recv(); g.from != echo || string(g.data) != "old" {
		t.Fatalf("%+v", g)
	}
}

// A write to a destination that fails is a drop of its own (write): every
// datagram of a client is sent or dropped, and counted as one of the two.
// The broadcast address, allowed here, fails each write: the request's
// socket has no SO_BROADCAST (EACCES).
func TestUDPDropWrite(t *testing.T) {
	echo := udpEcho(t)
	broadcast := netip.MustParseAddrPort("255.255.255.255:9")
	h, c := udpServer(t, func(h *Server) {
		h.Allow = func(a netip.Addr) bool { return a == echo.Addr() || a == broadcast.Addr() }
	})
	q := c.open(udpRequestOf{})
	q.send(udpDest(broadcast), []byte("everyone"))
	eventually(t, "a failed write not counted", func() bool { return dropped(h, dropWrite) == 1 })
	q.send(udpDest(echo), []byte("after"))
	if g := q.recv(); string(g.data) != "after" {
		t.Fatalf("%q", g.data)
	}
	if st := h.UDPStats(); st.In != 1 {
		t.Fatalf("%+v", st)
	}
}

// IPv6 both ways, a datagram and a capsule; an IPv4 address in IPv6 is
// IPv4's. Where the host has no IPv6 (some sandboxes), skipped.
func TestUDPIPv6(t *testing.T) {
	echo := udpEchoAt(t, netip.IPv6Loopback())
	if !echo.IsValid() {
		t.Skip("no IPv6 on this host")
	}
	_, c := udpServer(t, nil)
	q := c.open(udpRequestOf{})
	q.send(udpDest(echo), []byte("six"))
	if g := q.recv(); g.from != echo || string(g.data) != "six" || g.capsule {
		t.Fatalf("%+v", g)
	}
	big := bytes.Repeat([]byte{'x'}, 1300)
	q.capsule(capsuleDatagram, udpDatagram(udpDest(echo), big))
	if g := q.recv(); g.from != echo || !bytes.Equal(g.data, big) || !g.capsule {
		t.Fatalf("%v %d bytes, capsule %v", g.from, len(g.data), g.capsule)
	}
	v4 := udpEcho(t)
	mapped := netip.AddrPortFrom(netip.AddrFrom16(v4.Addr().As16()), v4.Port())
	q.send(udpDest(mapped), []byte("mapped"))
	if g := q.recv(); g.from != v4 || string(g.data) != "mapped" {
		t.Fatalf("%+v", g)
	}
}

// When the client's connection goes, at once, every goroutine of its
// datagram requests ends, its connection's sender too, and every place is
// given back; half of them ended cleanly first.
func TestUDPConnectionGone(t *testing.T) {
	echo := udpEcho(t)
	h, c := udpServer(t, nil)
	// The connection's sender is there from the start.
	requests, senders := stacks("internal/naive.(*udpRequest)"), stacks("h3serve.(*sender).run")-1
	var qs []*udpReq
	for range 20 {
		q := c.open(udpRequestOf{})
		q.send(udpDest(echo), []byte("x"))
		q.recv()
		qs = append(qs, q)
	}
	if n := stacks("internal/naive.(*udpRequest)"); n < requests+20 {
		t.Fatalf("%d goroutines of 20 requests", n-requests)
	}
	for _, q := range qs[:10] {
		_ = q.rs.Close()
	}
	eventually(t, "the places of the requests ended are held", func() bool { return h.lim.count() == 10 })
	_ = c.cc.CloseWithError(0, "")
	eventually(t, "the places of the connection's requests are held", func() bool { return h.lim.count() == 0 })
	eventually(t, "goroutines of requests are left", func() bool {
		return stacks("internal/naive.(*udpRequest)") == requests && stacks("h3serve.(*sender).run") == senders
	})
}
