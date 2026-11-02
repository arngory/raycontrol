package site

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Routes send TLS connections for a server name, still encrypted, to
// another unix socket (R2-13): REALITY hands the site everything that is not
// its own client, so the site is where TCP 443 is shared until a tcpmux
// exists. Names not listed get the site itself.
type Routes map[string]string // server name -> unix socket

// LoadRoutes reads routes from a JSON file; a missing file means none.
func LoadRoutes(path string) (Routes, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the unit's own file
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Routes
	return r, json.Unmarshal(b, &r)
}

// helloTimeout bounds how long a connection may take to send its
// ClientHello.
const helloTimeout = 10 * time.Second

// errPeeked stops a handshake once the ClientHello has been read.
var errPeeked = errors.New("client hello read")

// recorder keeps every byte read through it.
type recorder struct {
	net.Conn
	buf bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.buf.Write(p[:n])
	return n, err
}

// Write drops what the peeking handshake would send (its alert): the
// client must see nothing but the real server.
func (r *recorder) Write(p []byte) (int, error) { return len(p), nil }

// replayed reads the recorded bytes first, then the connection.
type replayed struct {
	net.Conn
	r io.Reader
}

func (c *replayed) Read(p []byte) (int, error) { return c.r.Read(p) }

// peek reads the ClientHello and returns its server name and the bytes read.
func peek(c net.Conn) (string, []byte, error) {
	rec := &recorder{Conn: c}
	name := ""
	// Never completes: it only reads the ClientHello (no versions to pin).
	err := tls.Server(rec, &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		name = strings.ToLower(h.ServerName)
		return nil, errPeeked
	}}).Handshake()
	if !errors.Is(err, errPeeked) {
		if err == nil {
			err = errors.New("no client hello")
		}
		return "", rec.buf.Bytes(), err
	}
	return name, rec.buf.Bytes(), nil
}

// Routed wraps the site's listener: connections for a routed name go to
// their socket, the rest come out of Accept as if untouched.
func Routed(ln net.Listener, routes Routes, log *slog.Logger) net.Listener {
	if len(routes) == 0 {
		return ln
	}
	r := &routed{Listener: ln, routes: routes, log: log, conns: make(chan net.Conn), done: make(chan struct{})}
	go r.loop()
	return r
}

type routed struct {
	net.Listener
	routes Routes
	log    *slog.Logger
	conns  chan net.Conn
	done   chan struct{}
	once   sync.Once
	err    error
}

func (r *routed) loop() {
	for {
		c, err := r.Listener.Accept()
		if err != nil {
			r.err = err
			r.once.Do(func() { close(r.done) })
			return
		}
		go r.handle(c)
	}
}

func (r *routed) handle(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	name, raw, err := peek(c)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		_ = c.Close()
		return
	}
	if dst, ok := r.routes[name]; ok {
		r.splice(c, raw, dst)
		return
	}
	select {
	case r.conns <- &replayed{Conn: c, r: io.MultiReader(bytes.NewReader(raw), c)}:
	case <-r.done:
		_ = c.Close()
	}
}

// splice passes the connection, ClientHello first, to the route's socket.
func (r *routed) splice(c net.Conn, raw []byte, dst string) {
	defer c.Close()
	b, err := net.DialTimeout("unix", dst, 5*time.Second)
	if err != nil {
		r.log.Debug("route unreachable", "err", err)
		return
	}
	defer b.Close()
	if _, err := b.Write(raw); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, c); closeWrite(b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, b); closeWrite(c); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func (r *routed) Accept() (net.Conn, error) {
	select {
	case c := <-r.conns:
		return c, nil
	case <-r.done:
		return nil, r.err
	}
}

func (r *routed) Close() error {
	err := r.Listener.Close()
	r.once.Do(func() { close(r.done) })
	return err
}
