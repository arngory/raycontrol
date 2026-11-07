package appmirror

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
		if !m.begin(dev) {
			w.Header().Set("Retry-After", strconv.Itoa(RetryAfter))
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		defer m.end(dev)
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
		http.ServeContent(&stallWriter{ResponseWriter: w, rc: http.NewResponseController(w)}, r, "", time.Time{}, f)
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

// begin takes a place for a device's download: one a device, PerNode in
// all.
func (m *Mirror) begin(dev string) bool {
	m.dl.Lock()
	defer m.dl.Unlock()
	if m.active == nil {
		m.active = map[string]bool{}
	}
	if m.active[dev] || m.total >= PerNode {
		return false
	}
	m.active[dev] = true
	m.total++
	return true
}

func (m *Mirror) end(dev string) {
	m.dl.Lock()
	defer m.dl.Unlock()
	delete(m.active, dev)
	m.total--
}

// stallWriter moves the write deadline on with every write: a download
// that goes on, however slowly, is not cut by the server's WriteTimeout,
// and one that takes nothing for Stall ends.
type stallWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
}

func (s *stallWriter) Write(p []byte) (int, error) {
	if err := s.rc.SetWriteDeadline(time.Now().Add(Stall)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return 0, err
	}
	return s.ResponseWriter.Write(p)
}
