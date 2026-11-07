package appmirror

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Handler serves GET and HEAD /app/v1/<app>/<tag>/<name> to the devices
// auth takes (app-update-v1 §2): what else, and anything while the mirror
// is off, gets the subscription's plain 404.
func (m *Mirror) Handler(auth func(*http.Request) (string, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		dev, err := auth(r)
		if err != nil {
			m.log().Debug("app file refused", "remote", r.RemoteAddr, "err", err)
			http.NotFound(w, r)
			return
		}
		if !Enabled(r.Context(), m.Store) {
			http.NotFound(w, r)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, Path), "/")
		if len(parts) != 3 || parts[0] != App {
			http.NotFound(w, r)
			return
		}
		rel, ok := m.heldRelease(parts[1])
		if !ok {
			http.NotFound(w, r)
			return
		}
		file, ok := rel.file(parts[2])
		if !ok {
			http.NotFound(w, r)
			return
		}
		// A body takes a place: HEAD does not (nor does it wait for one).
		if r.Method == http.MethodGet {
			conn := m.tcpConn(r.Context())
			d, ok := m.begin(r.Context(), dev, conn)
			if !ok {
				w.Header().Set("Retry-After", strconv.Itoa(RetryAfter))
				http.Error(w, "busy", http.StatusTooManyRequests)
				return
			}
			defer m.end(dev, d)
			defer paced(conn)()
		}
		// One range (app-update-v1 §2): several get the whole file.
		if strings.Contains(r.Header.Get("Range"), ",") {
			r.Header.Del("Range")
		}
		// No 304: the subscription's port answers no 3xx (a 404 in its
		// place would read as "not on the node").
		r.Header.Del("If-None-Match")
		f, err := os.Open(filepath.Join(m.appDir(), rel.Tag, file.Name))
		if err != nil {
			// The release went (turned off, or a newer one in its place)
			// between the lookup and the open.
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		if st, err := f.Stat(); err != nil || st.Size() != file.Size {
			m.log().Warn("a mirrored file is not as verified", "tag", rel.Tag, "file", file.Name)
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("ETag", `"`+file.SHA256+`"`)
		h.Set("Content-Type", contentType(file.Name))
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		// ServeContent: one range or the whole file, If-Range by the ETag,
		// 416 with the size, Content-Length always.
		sw := &stallWriter{ResponseWriter: w, rc: http.NewResponseController(w), stall: cmp.Or(m.Stall, Stall), until: time.Now().Add(MaxDownload)}
		http.ServeContent(sw, r, "", time.Time{}, f)
		if sw.err != nil {
			// Cut, not ended: HTTP/1.1 closes the connection, HTTP/2
			// resets the stream. A clean end short of Content-Length
			// would leave a client that does not count with a torn file.
			panic(http.ErrAbortHandler)
		}
	})
}

func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".apk"):
		return "application/vnd.android.package-archive"
	case name == sumsName || name == sigName:
		return "text/plain; charset=utf-8"
	}
	return "application/octet-stream"
}

// download is a device's download under way.
type download struct {
	conn net.Conn      // its TCP connection; nil when not known
	done chan struct{} // closed when it ends
}

// takeover is how long a device's new download waits for the one it
// cuts to end.
const takeover = 5 * time.Second

// begin takes a place for a device's download: one a device, PerNode in
// all. A device's download still under way on another connection is dead
// or left (a phone changed networks and resumes at once; the old
// connection would hold the place until Stall): its connection is closed
// and the place passes on. On the same connection it is a second
// download at once: 429.
func (m *Mirror) begin(ctx context.Context, dev string, conn net.Conn) (*download, bool) {
	for try := 0; ; try++ {
		d, old := m.take(dev, conn)
		if d != nil {
			return d, true
		}
		if old == nil || try > 0 || conn == nil || old.conn == nil || old.conn == conn {
			return nil, false
		}
		m.log().Debug("a device's download cut by its next", "device", dev)
		_ = old.conn.Close()
		select {
		case <-old.done:
		case <-time.After(takeover):
			return nil, false
		case <-ctx.Done():
			return nil, false
		}
	}
}

// take takes the device's place if it is free and the node has one: the
// download, or the device's download under way.
func (m *Mirror) take(dev string, conn net.Conn) (d, old *download) {
	m.dl.Lock()
	defer m.dl.Unlock()
	if a := m.active[dev]; a != nil {
		return nil, a
	}
	if m.total >= PerNode {
		return nil, nil
	}
	if m.active == nil {
		m.active = map[string]*download{}
	}
	d = &download{conn: conn, done: make(chan struct{})}
	m.active[dev] = d
	m.total++
	return d, nil
}

func (m *Mirror) end(dev string, d *download) {
	m.dl.Lock()
	if m.active[dev] == d {
		delete(m.active, dev)
	}
	m.total--
	m.dl.Unlock()
	close(d.done)
}

// stallWriter moves the write deadline on with every write: a download
// that goes on is not cut by the server's WriteTimeout, one whose next
// piece does not leave within stall ends, and none lasts past until (the
// client resumes it with a range: a place does not stay with one device).
type stallWriter struct {
	http.ResponseWriter
	rc    *http.ResponseController
	stall time.Duration
	until time.Time
	err   error // the first write that failed
}

var errTooLong = errors.New("download longer than MaxDownload")

func (s *stallWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if time.Now().After(s.until) {
		s.err = errTooLong
		return 0, s.err
	}
	if err := s.rc.SetWriteDeadline(time.Now().Add(s.stall)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.err = err
		return 0, err
	}
	n, err := s.ResponseWriter.Write(p)
	if err != nil {
		s.err = err
	}
	return n, err
}

// tcpConn is a request's TCP connection, under its TLS.
func (m *Mirror) tcpConn(ctx context.Context) net.Conn {
	if m.Conn == nil {
		return nil
	}
	c := m.Conn(ctx)
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	return c
}

// paced makes a download's writes wait on its client: with
// TCP_NOTSENT_LOWAT a write waits until most of what was not yet sent has
// gone, so a client that takes nothing misses Stall while a slow live one
// (from ~2 KB/s) keeps up. The kernel's buffer stays autotuned (the probes
// measure over the same connections); the returned func puts the
// connection back as it was.
func paced(conn net.Conn) func() {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return func() {}
	}
	set := func(v int) {
		if rc, err := tcp.SyscallConn(); err == nil {
			_ = rc.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, v)
			})
		}
	}
	set(notSentLowat)
	return func() { set(0) } // 0: the system's
}
