// Package naive serves NaiveProxy over HTTP/2 for the node's clients
// (docs/08-decisions.md, R2-14): an authenticated CONNECT with naive's
// padding opens a tunnel; anything else gets the site's answer, never 407.
// TLS (1.3, X25519MLKEM768 only) is the caller's.
package naive

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Server handles the requests of one naive service.
type Server struct {
	Users *Users
	// Answer serves whatever is not an authenticated naive CONNECT: the
	// site's answer (an empty 404 by default).
	Answer http.Handler
	// Dial reaches the destination; PublicDialer when nil.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Log  *slog.Logger
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.ProtoMajor != 2 || r.Header.Get("Padding") == "" || !s.authorized(r) {
		s.Answer.ServeHTTP(w, r)
		return
	}
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		s.Answer.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Padding", paddingHeader())
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	flusher.Flush()

	dial := s.Dial
	if dial == nil {
		dial = PublicDialer().DialContext
	}
	dctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	out, err := dial(dctx, "tcp", target)
	cancel()
	if err != nil {
		s.Log.Debug("naive: destination unreachable", "err", err)
		return
	}
	defer out.Close()

	in := &paddedStream{r: r.Body, w: w, f: flusher}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(out, in)
		if cw, ok := out.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(in, out)
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-r.Context().Done():
	}
}

// authorized checks Proxy-Authorization: Basic, any user name, the password
// being one of the users' credentials.
func (s *Server) authorized(r *http.Request) bool {
	h := r.Header.Get("Proxy-Authorization")
	scheme, b64, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return false
	}
	_, password, ok := strings.Cut(string(raw), ":")
	return ok && s.Users.Accepts(password)
}

// Users are the accepted passwords, as SHA-256 hashes in a JSON file that
// rayd rewrites when credentials rotate; the file is read again when it
// changes, without a restart.
type Users struct {
	Path string

	mu      sync.Mutex
	checked time.Time
	mtime   time.Time
	hashes  map[[32]byte]bool
}

// HashPassword is how the users file names a password.
func HashPassword(p string) string {
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// Accepts reports whether the password is a current credential.
func (u *Users) Accepts(password string) bool {
	if password == "" {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if time.Since(u.checked) > 5*time.Second || u.hashes == nil {
		u.checked = time.Now()
		if st, err := os.Stat(u.Path); err == nil && !st.ModTime().Equal(u.mtime) {
			if h, err := readUsers(u.Path); err == nil {
				u.hashes, u.mtime = h, st.ModTime()
			}
		}
	}
	return u.hashes[sha256.Sum256([]byte(password))]
}

func readUsers(path string) (map[[32]byte]bool, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the unit's own file
	if err != nil {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	out := make(map[[32]byte]bool, len(list))
	for _, h := range list {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("naive: bad hash in the users file")
		}
		out[[32]byte(raw)] = true
	}
	return out, nil
}

// PublicDialer reaches public unicast addresses only: not the node itself,
// not loopback, private, link-local, CGNAT or multicast ranges. A client
// may not use naive to get at what only the node's own address reaches.
func PublicDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if !Public(ap.Addr()) {
			return errors.New("naive: destination not public")
		}
		return nil
	}}
}

var (
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
	local struct {
		once  sync.Once
		addrs map[netip.Addr]bool
	}
)

// Public reports whether an address is a public unicast address and not one
// of the node's own.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || cgnat.Contains(a) {
		return false
	}
	local.once.Do(func() {
		local.addrs = map[netip.Addr]bool{}
		addrs, _ := net.InterfaceAddrs()
		for _, x := range addrs {
			if p, err := netip.ParsePrefix(x.String()); err == nil {
				local.addrs[p.Addr().Unmap()] = true
			}
		}
	})
	return !local.addrs[a]
}

// The padding of naive's first frames each way (as NaiveProxy and the
// sing-box inbound do): [length 2][padding length 1][data][zeros].
const paddingFrames = 8

// randByte draws padding sizes: an observer must not predict them.
func randByte() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}

func paddingHeader() string {
	b := make([]byte, 30+int(randByte()%32))
	for i := range b {
		if i < 16 {
			b[i] = "!#$()+<>?@[]^`{}"[randByte()%16]
		} else {
			b[i] = '~'
		}
	}
	return string(b)
}

// ClientStream is the client's side of the tunnel: what it writes into the
// CONNECT request body and reads from the response, padded the same way.
func ClientStream(response io.Reader, request io.Writer) io.ReadWriter {
	return &paddedStream{r: response, w: request}
}

// PaddingHeader is a value for the Padding header of a CONNECT.
func PaddingHeader() string { return paddingHeader() }

// paddedStream is the tunnel inside the CONNECT stream.
type paddedStream struct {
	r io.Reader
	w io.Writer
	f http.Flusher

	readFrames, writeFrames int
	remaining, skip         int
	mu                      sync.Mutex // writes
}

func (p *paddedStream) Read(b []byte) (int, error) {
	for {
		if p.remaining > 0 {
			if len(b) > p.remaining {
				b = b[:p.remaining]
			}
			n, err := p.r.Read(b)
			p.remaining -= n
			return n, err
		}
		if p.skip > 0 {
			if _, err := io.CopyN(io.Discard, p.r, int64(p.skip)); err != nil {
				return 0, err
			}
			p.skip = 0
		}
		if p.readFrames >= paddingFrames {
			return p.r.Read(b)
		}
		var h [3]byte
		if _, err := io.ReadFull(p.r, h[:]); err != nil {
			return 0, err
		}
		p.readFrames++
		p.remaining, p.skip = int(binary.BigEndian.Uint16(h[:2])), int(h[2])
	}
}

func (p *paddedStream) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	written := 0
	for len(b) > 0 {
		chunk := b
		if p.writeFrames < paddingFrames && len(chunk) > 65535 {
			chunk = chunk[:65535]
		}
		var err error
		if p.writeFrames < paddingFrames {
			pad := int(randByte())
			frame := make([]byte, 3+len(chunk)+pad)
			binary.BigEndian.PutUint16(frame, uint16(len(chunk)))
			frame[2] = byte(pad)
			copy(frame[3:], chunk)
			_, err = p.w.Write(frame)
			p.writeFrames++
		} else {
			_, err = p.w.Write(chunk)
		}
		if err != nil {
			return written, err
		}
		if p.f != nil {
			p.f.Flush()
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}
