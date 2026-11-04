// Package probe measures the channel between a device and the node
// (docs/spec/probe-v1.md, docs/08-decisions.md R4-16): TCP down and up over
// the subscription endpoint's HTTPS, with the server's view of the
// connection (TCP_INFO), and a UDP echo on the same port number. A device
// has one probe at a time, each up to 30 s, within a daily volume.
package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Name is where a client reaches the probes through a tunnel: the exits
// (Xray, rayd naive, the Hysteria2 backends) send it to the endpoint.
const Name = "probe.raycontrol.invalid"

// Paths, limits and the trailer of a down probe.
const (
	PathDown = "/probe/v1/down"
	PathUp   = "/probe/v1/up"
	PathUDP  = "/probe/v1/udp"

	MaxBytes     = 256 << 20 // one TCP probe
	MaxTime      = 30 * time.Second
	DefaultDaily = 1 << 30 // per device and UTC day, both directions
	MaxRate      = 1000    // echoed datagrams per second
	UDPBudget    = 64 << 20

	// ResultTrailer carries the server's result of a down probe.
	ResultTrailer = "Probe-Result"

	tokenSize = 16
	// HeaderSize is the least datagram: token, sequence, the client's time,
	// the server's time.
	HeaderSize = tokenSize + 4 + 8 + 8
)

// Result is the server's view of a TCP probe.
type Result struct {
	Bytes int64    `json:"bytes"`
	Ms    int64    `json:"ms"`
	TCP   *TCPInfo `json:"tcp,omitempty"`
}

// TCPInfo is what the kernel knows of the connection (TCP_INFO).
type TCPInfo struct {
	RTTus       uint32 `json:"rtt_us"`
	RTTVarus    uint32 `json:"rttvar_us"`
	MinRTTus    uint32 `json:"min_rtt_us"`
	Retrans     uint32 `json:"retrans"`
	DeliveryBps uint64 `json:"delivery_bps"`
	Cwnd        uint32 `json:"cwnd"`
	PMTU        uint32 `json:"pmtu"`
}

// String is the trailer form: "bytes=N; ms=M; rtt_us=…".
func (r Result) String() string {
	parts := []string{"bytes=" + strconv.FormatInt(r.Bytes, 10), "ms=" + strconv.FormatInt(r.Ms, 10)}
	if t := r.TCP; t != nil {
		parts = append(parts,
			fmt.Sprintf("rtt_us=%d", t.RTTus), fmt.Sprintf("rttvar_us=%d", t.RTTVarus), fmt.Sprintf("min_rtt_us=%d", t.MinRTTus),
			fmt.Sprintf("retrans=%d", t.Retrans), fmt.Sprintf("delivery_bps=%d", t.DeliveryBps),
			fmt.Sprintf("cwnd=%d", t.Cwnd), fmt.Sprintf("pmtu=%d", t.PMTU))
	}
	return strings.Join(parts, "; ")
}

// UDPSession is the answer to starting a UDP echo.
type UDPSession struct {
	Token   string `json:"token"` // base64url, the first 16 bytes of every datagram
	Port    int    `json:"port"`
	Seconds int    `json:"seconds"`
	MaxRate int    `json:"max_rate"`
	Budget  int64  `json:"budget"` // bytes, both directions
}

// UDPSummary is the server's count of a UDP echo.
type UDPSummary struct {
	Received int64 `json:"received"` // datagrams of the session from its address
	Echoed   int64 `json:"echoed"`
	Dropped  int64 `json:"dropped"` // over the rate or the budget
	Bytes    int64 `json:"bytes"`   // both directions
}

// Server serves probes. Auth names the device of a request (the
// subscription's check) or fails; the rest of the server's answers are
// plain 404s, as the subscription's.
type Server struct {
	Auth    func(*http.Request) (string, error)
	Daily   int64 // bytes per device and UTC day; 0 means DefaultDaily
	UDPPort int   // where the echo listens, told to clients
	// LinkPorts are the node's ports whose connections link reports: the
	// tunnels' TCP 443 when empty.
	LinkPorts []uint16
	// Hysteria lists the Hysteria2 services' stats sockets by service ID,
	// for link; nil leaves Hysteria2 out.
	Hysteria func() map[string]string
	// Account names the device's user as the Hysteria2 backends know it, so
	// that link gives that user's own sessions one by one (niko-server
	// v0.7); nil, or an error, leaves the aggregates alone.
	Account func(ctx context.Context, device string) (string, error)
	Log     *slog.Logger
	now     func() time.Time

	mu       sync.Mutex
	day      int64
	used     map[string]int64
	busy     map[string]bool
	sessions map[[tokenSize]byte]*session
	lastLink map[string]time.Time
}

type session struct {
	device   string
	reserved int64
	day      int64
	expires  time.Time
	ended    bool
	addr     string
	window   time.Time
	inWindow int
	sum      UDPSummary
	purge    *time.Timer
}

var (
	errBusy  = errors.New("a probe of this device is running")
	errQuota = errors.New("the device's daily probe volume is used up")
)

func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Server) daily() int64 {
	if s.Daily > 0 {
		return s.Daily
	}
	return DefaultDaily
}

// acquire marks the device busy and reserves want bytes of its day.
func (s *Server) acquire(device string, want int64) (day int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.clock().Unix() / 86400; d != s.day || s.used == nil {
		s.day, s.used = d, map[string]int64{}
	}
	if s.busy == nil {
		s.busy = map[string]bool{}
	}
	if s.busy[device] {
		return 0, errBusy
	}
	if s.daily()-s.used[device] < want {
		return 0, errQuota
	}
	s.used[device] += want
	s.busy[device] = true
	return s.day, nil
}

// release frees the device and gives back what it did not spend.
func (s *Server) release(device string, day, reserved, spent int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseLocked(device, day, reserved, spent)
}

func (s *Server) releaseLocked(device string, day, reserved, spent int64) {
	delete(s.busy, device)
	if day == s.day && spent < reserved {
		s.used[device] -= reserved - spent
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	device, err := s.Auth(r)
	if err != nil {
		s.Log.Debug("probe refused", "err", err)
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == PathDown && r.Method == http.MethodGet:
		s.down(w, r, device)
	case r.URL.Path == PathUp && r.Method == http.MethodPost:
		s.up(w, r, device)
	case r.URL.Path == PathUDP && r.Method == http.MethodPost:
		s.startUDP(w, device)
	case r.URL.Path == PathUDP && r.Method == http.MethodGet:
		s.endUDP(w, r, device)
	case r.URL.Path == PathLink && r.Method == http.MethodGet:
		s.link(w, r, device)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) refuse(w http.ResponseWriter, err error) {
	w.Header().Set("Retry-After", "30")
	if errors.Is(err, errQuota) {
		w.Header().Set("Retry-After", strconv.FormatInt(86400-s.clock().Unix()%86400, 10))
	}
	http.Error(w, err.Error(), http.StatusTooManyRequests)
}

func size(r *http.Request) (int64, bool) {
	n, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
	return n, err == nil && n >= 1 && n <= MaxBytes
}

// down sends N bytes; the trailer gives what the server sent, in how long,
// and its view of the connection.
func (s *Server) down(w http.ResponseWriter, r *http.Request, device string) {
	n, ok := size(r)
	if !ok {
		http.Error(w, "bytes: 1 to "+strconv.Itoa(MaxBytes), http.StatusBadRequest)
		return
	}
	day, err := s.acquire(device, n)
	if err != nil {
		s.refuse(w, err)
		return
	}
	var sent int64
	defer func() { s.release(device, day, n, sent) }()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(s.clock().Add(MaxTime))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Trailer", ResultTrailer)
	w.WriteHeader(http.StatusOK)
	var seed [32]byte
	_, _ = rand.Read(seed[:])
	rng := mrand.NewChaCha8(seed)
	buf := make([]byte, 32<<10)
	start := time.Now()
	for sent < n && time.Since(start) < MaxTime {
		chunk := buf[:min(int64(len(buf)), n-sent)]
		_, _ = rng.Read(chunk)
		m, err := w.Write(chunk)
		sent += int64(m)
		if err != nil {
			return
		}
	}
	_ = rc.Flush()
	w.Header().Set(ResultTrailer, Result{Bytes: sent, Ms: time.Since(start).Milliseconds(), TCP: tcpInfo(r.Context())}.String())
}

// up takes up to N bytes; the answer gives what arrived and in how long,
// from the first byte to the last.
func (s *Server) up(w http.ResponseWriter, r *http.Request, device string) {
	n, ok := size(r)
	if !ok {
		http.Error(w, "bytes: 1 to "+strconv.Itoa(MaxBytes), http.StatusBadRequest)
		return
	}
	day, err := s.acquire(device, n)
	if err != nil {
		s.refuse(w, err)
		return
	}
	var got int64
	defer func() { s.release(device, day, n, got) }()
	rc := http.NewResponseController(w)
	deadline := s.clock().Add(MaxTime)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline.Add(5 * time.Second))
	body := io.LimitReader(r.Body, n)
	buf := make([]byte, 32<<10)
	var first, last time.Time
	for {
		m, err := body.Read(buf)
		if m > 0 {
			if got == 0 {
				first = time.Now()
			}
			got += int64(m)
			last = time.Now()
		}
		if err != nil {
			break
		}
	}
	res := Result{Bytes: got, TCP: tcpInfo(r.Context())}
	if got > 0 {
		res.Ms = last.Sub(first).Milliseconds()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) startUDP(w http.ResponseWriter, device string) {
	s.mu.Lock()
	remaining := s.daily() - s.used[device]
	if s.day != s.clock().Unix()/86400 {
		remaining = s.daily()
	}
	s.mu.Unlock()
	budget := min(int64(UDPBudget), remaining)
	if budget < 1<<20 {
		s.refuse(w, errQuota)
		return
	}
	day, err := s.acquire(device, budget)
	if err != nil {
		s.refuse(w, err)
		return
	}
	var token [tokenSize]byte
	_, _ = rand.Read(token[:])
	sess := &session{device: device, reserved: budget, day: day, expires: s.clock().Add(MaxTime)}
	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = map[[tokenSize]byte]*session{}
	}
	s.sessions[token] = sess
	// The session ends at its time even if the client never asks for the
	// count; the count stays a minute longer.
	time.AfterFunc(MaxTime, func() { s.end(token) })
	sess.purge = time.AfterFunc(MaxTime+time.Minute, func() {
		s.mu.Lock()
		delete(s.sessions, token)
		s.mu.Unlock()
	})
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(UDPSession{Token: base64.RawURLEncoding.EncodeToString(token[:]), Port: s.UDPPort,
		Seconds: int(MaxTime / time.Second), MaxRate: MaxRate, Budget: budget})
}

// end stops a session's echo and frees its device.
func (s *Server) end(token [tokenSize]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[token]
	if sess == nil || sess.ended {
		return
	}
	sess.ended = true
	s.releaseLocked(sess.device, sess.day, sess.reserved, sess.sum.Bytes)
}

func (s *Server) endUDP(w http.ResponseWriter, r *http.Request, device string) {
	raw, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("token"))
	if err != nil || len(raw) != tokenSize {
		http.NotFound(w, r)
		return
	}
	token := [tokenSize]byte(raw)
	s.mu.Lock()
	sess := s.sessions[token]
	s.mu.Unlock()
	if sess == nil || sess.device != device {
		http.NotFound(w, r)
		return
	}
	s.end(token)
	s.mu.Lock()
	sum := sess.sum
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sum)
}

// ServeUDP echoes the datagrams of open sessions until pc closes: the same
// datagram back to its sender, with the server's time of arrival (Unix
// nanoseconds) in bytes 28 to 35. Anything else gets nothing.
func (s *Server) ServeUDP(pc net.PacketConn) error {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if n < HeaderSize {
			continue
		}
		at := s.clock()
		if s.admit([tokenSize]byte(buf[:tokenSize]), addr.String(), n, at) {
			binary.BigEndian.PutUint64(buf[tokenSize+12:], uint64(at.UnixNano()))
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}
}

func (s *Server) admit(token [tokenSize]byte, addr string, n int, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[token]
	if sess == nil || sess.ended || at.After(sess.expires) {
		return false
	}
	// The first sender holds the session: an echo goes back to it only.
	if sess.addr == "" {
		sess.addr = addr
	} else if sess.addr != addr {
		return false
	}
	sess.sum.Received++
	if at.Sub(sess.window) >= time.Second {
		sess.window, sess.inWindow = at, 0
	}
	if sess.inWindow >= MaxRate || sess.sum.Bytes+2*int64(n) > sess.reserved {
		sess.sum.Dropped++
		return false
	}
	sess.inWindow++
	sess.sum.Echoed++
	sess.sum.Bytes += 2 * int64(n)
	return true
}

type connKey struct{}

// ConnContext keeps the connection of a request, for its TCP_INFO; it is
// the http.Server's ConnContext.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

func tcpInfo(ctx context.Context) *TCPInfo {
	c, _ := ctx.Value(connKey{}).(net.Conn)
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return nil
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return nil
	}
	var info *unix.TCPInfo
	_ = raw.Control(func(fd uintptr) {
		info, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	if err != nil || info == nil {
		return nil
	}
	return &TCPInfo{RTTus: info.Rtt, RTTVarus: info.Rttvar, MinRTTus: info.Min_rtt, Retrans: info.Total_retrans,
		DeliveryBps: info.Delivery_rate * 8, Cwnd: info.Snd_cwnd, PMTU: info.Pmtu}
}
