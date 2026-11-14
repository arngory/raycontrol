package roots

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// Trust is a process's outbound trust: its Pool, rebuilt when the
// settings file or the extra file changes, and the count of connections
// refused by it. Node is the process's own.
type Trust struct {
	// Path is the settings file (SettingsFile when empty).
	Path string
	// Fixed, when set, replaces the settings file (tests, rayd -tls-roots
	// with a file of a stand's).
	Fixed *Settings
	// System is the image's store (x509.SystemCertPool when nil).
	System func() (*x509.CertPool, error)
	// Report, when set, is called with the trust's state at each change
	// of the pool and each refused connection (rayd: rayctl status).
	Report func(Status)

	mu            sync.Mutex
	settings      Settings // as read at settingsStamp
	settingsErr   error
	settingsStamp string
	stamp         string
	pool          *Pool
	refused       uint64
	lastHost      string
	lastErr       string
	lastAt        time.Time
}

// Node is the trust of this process's own connections.
var Node = &Trust{}

// Status is what Report gets.
type Status struct {
	Pool     *Pool
	Refused  uint64 // connections refused since start
	LastHost string // the host of the last one
	LastErr  string // why, on one line
	LastAt   time.Time
}

// Pool is the current pool.
func (t *Trust) Pool() *Pool {
	p := t.current()
	return p
}

// Status is the trust's state now.
func (t *Trust) Status() Status {
	p := t.Pool()
	t.mu.Lock()
	defer t.mu.Unlock()
	return Status{Pool: p, Refused: t.refused, LastHost: t.lastHost, LastErr: t.lastErr, LastAt: t.lastAt}
}

func (t *Trust) path() string {
	if t.Path == "" {
		return SettingsFile
	}
	return t.Path
}

// fileStamp tells a file's versions apart: its size and time, or its absence.
func fileStamp(path string) string {
	if path == "" {
		return "-"
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "none"
	}
	return fmt.Sprintf("%d/%d", fi.Size(), fi.ModTime().UnixNano())
}

// current is the pool, rebuilt when a file changed: two stats a call.
func (t *Trust) current() *Pool {
	t.mu.Lock()
	s, err := t.settings, t.settingsErr
	stamp := "fixed"
	if t.Fixed != nil {
		s, err = *t.Fixed, nil
	} else if stamp = fileStamp(t.path()); t.pool == nil || stamp != t.settingsStamp {
		s, err = ReadSettings(t.path())
		t.settings, t.settingsErr, t.settingsStamp = s, err, stamp
	}
	stamp += " " + fileStamp(s.File)
	if t.pool != nil && stamp == t.stamp {
		p := t.pool
		t.mu.Unlock()
		return p
	}
	p := Build(s, t.System)
	if err != nil {
		p.Err = err
	}
	t.pool, t.stamp = p, stamp
	t.mu.Unlock()
	t.report()
	return p
}

func (t *Trust) report() {
	if t.Report != nil {
		t.Report(t.Status())
	}
}

// Verification reports whether err is a refused certificate.
func Verification(err error) bool {
	var v *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	var hn x509.HostnameError
	return errors.As(err, &v) || errors.As(err, &ua) || errors.As(err, &ci) || errors.As(err, &hn)
}

// verifyReason is the refusal's x509 error, without the TLS wrapping.
func verifyReason(err error) string {
	var v *tls.CertificateVerificationError
	if errors.As(err, &v) && v.Err != nil {
		return v.Err.Error()
	}
	return err.Error()
}

// Refused counts a connection to host refused by this trust. Only the
// node's peer is kept: never anything of a user's.
func (t *Trust) Refused(host string, err error) {
	t.mu.Lock()
	t.refused++
	t.lastHost, t.lastErr, t.lastAt = host, verifyReason(err), time.Now()
	t.mu.Unlock()
	t.report()
}

// TLSConfig is a client configuration with the current pool.
func (t *Trust) TLSConfig() *tls.Config {
	return &tls.Config{RootCAs: t.Pool().CertPool(), MinVersion: tls.VersionTLS12}
}

// Option changes a Transport.
type Option func(*transport)

// SystemFallback lets a connection the pool refuses be tried again with
// the system store added, warn told first. Only for downloads whose
// content a signature protects anyway (the releases: minisign), so that a
// stale embedded list never stops an update, which brings the next list.
func SystemFallback(warn func(host string, err error)) Option {
	return func(x *transport) { x.fallback, x.warn = true, warn }
}

// Client is an HTTP client trusting t.
func (t *Trust) Client(timeout time.Duration, opts ...Option) *http.Client {
	return &http.Client{Timeout: timeout, Transport: t.Transport(nil, opts...)}
}

// Transport is a RoundTripper trusting t, made from base (a clone of
// http.DefaultTransport when nil; its TLSClientConfig is replaced but for
// its other fields).
func (t *Trust) Transport(base *http.Transport, opts ...Option) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	x := &transport{t: t, base: base.Clone()}
	for _, o := range opts {
		o(x)
	}
	return x
}

type transport struct {
	t        *Trust
	base     *http.Transport
	fallback bool
	warn     func(host string, err error)

	mu   sync.Mutex
	pool *Pool
	tr   *http.Transport
	sys  *http.Transport // the fallback's, for this pool
}

// with is a transport of base trusting pool.
func (x *transport) with(pool *x509.CertPool) *http.Transport {
	tr := x.base.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tr.TLSClientConfig.RootCAs = pool
	tr.TLSClientConfig.InsecureSkipVerify = false
	return tr
}

func (x *transport) current() (*Pool, *http.Transport) {
	p := x.t.current()
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.pool != p {
		if x.tr != nil {
			x.tr.CloseIdleConnections()
		}
		if x.sys != nil {
			x.sys.CloseIdleConnections()
			x.sys = nil
		}
		x.pool, x.tr = p, x.with(p.CertPool())
	}
	return p, x.tr
}

// system is the fallback's transport: the system store and the pool.
func (x *transport) system(p *Pool) (*http.Transport, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.sys != nil && x.pool == p {
		return x.sys, nil
	}
	sysf := x.t.System
	if sysf == nil {
		sysf = x509.SystemCertPool
	}
	sp, err := sysf()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if sp != nil {
		pool = sp.Clone()
	}
	for _, c := range Embedded() {
		pool.AddCert(c)
	}
	x.sys = x.with(pool)
	return x.sys, nil
}

func (x *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	p, tr := x.current()
	resp, err := tr.RoundTrip(req)
	if err == nil || !Verification(err) {
		return resp, err
	}
	host := req.URL.Hostname()
	x.t.Refused(host, err)
	// The system store adds nothing when it is in the pool already.
	hasSystem := p.Settings.System && p.Err == nil
	if x.fallback && !hasSystem && (req.Body == nil || req.Body == http.NoBody || req.GetBody != nil) {
		if x.warn != nil {
			x.warn(host, err)
		}
		if sys, serr := x.system(p); serr == nil {
			r2 := req.Clone(req.Context())
			if req.GetBody != nil {
				body, berr := req.GetBody()
				if berr != nil {
					return nil, berr
				}
				r2.Body = body
			}
			return sys.RoundTrip(r2)
		}
	}
	return nil, fmt.Errorf("%w (the node trusts its embedded root list: rayctl roots)", err)
}

// CloseIdleConnections is http.Client's.
func (x *transport) CloseIdleConnections() {
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, tr := range []*http.Transport{x.tr, x.sys} {
		if tr != nil {
			tr.CloseIdleConnections()
		}
	}
}
