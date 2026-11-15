package roots

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// RefusalWindow is how long a refused connection keeps the trust failing
// (rayd: the loop tls-roots) when nothing else clears it: twice the
// longest period of the node's own periodic connections (the update check,
// the app mirror and the certificates look every 6 h), so a refusal stays
// shown until its peer has been tried again, and that try decides. A
// connection to the same host the pool lets through clears it at once,
// and so does a new pool (the settings or the extra file changed).
const RefusalWindow = 12 * time.Hour

// CheckEvery is how often, at most, the settings file and the extra file
// are looked at for a change, by default.
const CheckEvery = time.Second

// firstWait bounds the first build: settings on a mount that does not
// answer leave the embedded list in force until they do.
const firstWait = 2 * time.Second

// Trust is a process's outbound trust: its Pool, rebuilt when the
// settings file or the extra file changes, and the connections it
// refused. Node is the process's own.
//
// Asking for the pool costs an atomic load and a clock read: the files
// are looked at by a goroutine of their own, at most every Every, and a
// settings file on a hung mount, or a FIFO, holds that goroutine only;
// every connection meanwhile goes on with the pool it had.
type Trust struct {
	// Path is the settings file (SettingsFile when empty).
	Path string
	// Fixed, when set, replaces the settings file (tests, rayd -tls-roots
	// with a file of a stand's).
	Fixed *Settings
	// System is the image's store (x509.SystemCertPool when nil).
	System func() (*x509.CertPool, error)
	// Report, when set, is called with the trust's state at each change
	// of the pool, each refused connection and each one that clears a
	// refusal (rayd: rayctl status and the log).
	Report func(Status)
	// Every is how often the files are looked at (CheckEvery when 0).
	Every time.Duration
	// Now is the clock of the refusals (time.Now when nil).
	Now func() time.Time

	cur      atomic.Pointer[built]
	checked  atomic.Int64 // UnixNano of the last look at the files
	checking atomic.Bool  // a look under way
	firstMu  sync.Mutex

	open    atomic.Int64 // len(refused)+len(rescued): a success takes no lock while 0
	mu      sync.Mutex
	refused map[string]*refusal // by host, under cur's pool
	rescued map[string]*refusal
	total   uint64
}

// built is a pool and what it was built from.
type built struct {
	pool          *Pool
	settings      Settings
	settingsErr   error
	settingsStamp string
	stamp         string
}

type refusal struct {
	n   uint64
	err string
	at  time.Time
}

// Node is the trust of this process's own connections.
var Node = &Trust{}

// Status is what Report gets.
type Status struct {
	Pool *Pool
	// Refused is the connections the pool refused in the last
	// RefusalWindow, to hosts it has not let through since; LastHost,
	// LastErr and LastAt are the last of them (the host is one of the
	// node's own peers: never anything of a user's).
	Refused  uint64
	LastHost string
	LastErr  string // why, on one line
	LastAt   time.Time
	// Rescued is the connections the pool refused, in the same window,
	// that the system store then let through (SystemFallback: a signed
	// download), the last to RescuedHost: a warning, not a failure.
	Rescued     uint64
	RescuedHost string
	// Total is every connection refused since start.
	Total uint64
	// Event is the refusal this report is about; nil for other reports.
	Event *Refusal
}

// Refusal is one refused connection.
type Refusal struct {
	Host, Err string
	// Rescued: the system store then let it through.
	Rescued bool
}

// Pool is the current pool.
func (t *Trust) Pool() *Pool { return t.current() }

// Status is the trust's state now: refusals older than RefusalWindow are
// dropped.
func (t *Trust) Status() Status {
	p := t.current()
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.statusLocked(p, t.now())
}

func (t *Trust) statusLocked(p *Pool, now time.Time) Status {
	s := Status{Pool: p, Total: t.total}
	for _, m := range []map[string]*refusal{t.refused, t.rescued} {
		for h, r := range m {
			if now.Sub(r.at) > RefusalWindow {
				delete(m, h)
			}
		}
	}
	for h, r := range t.refused {
		s.Refused += r.n
		if r.at.After(s.LastAt) || r.at.Equal(s.LastAt) && h < s.LastHost {
			s.LastHost, s.LastErr, s.LastAt = h, r.err, r.at
		}
	}
	var at time.Time
	for h, r := range t.rescued {
		s.Rescued += r.n
		if r.at.After(at) || r.at.Equal(at) && h < s.RescuedHost {
			s.RescuedHost, at = h, r.at
		}
	}
	t.open.Store(int64(len(t.refused) + len(t.rescued)))
	return s
}

func (t *Trust) path() string {
	if t.Path == "" {
		return SettingsFile
	}
	return t.Path
}

func (t *Trust) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Trust) every() time.Duration {
	if t.Every > 0 {
		return t.Every
	}
	return CheckEvery
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

// current is the pool: lock-free; once Every has passed, one goroutine
// looks at the files.
func (t *Trust) current() *Pool {
	b := t.cur.Load()
	if b == nil {
		return t.first()
	}
	if now := time.Now().UnixNano(); now-t.checked.Load() >= int64(t.every()) && t.checking.CompareAndSwap(false, true) {
		t.checked.Store(now)
		go t.look()
	}
	return b.pool
}

// first builds the first pool, waiting firstWait at most: then the
// embedded list, said so, until the files answer.
func (t *Trust) first() *Pool {
	t.firstMu.Lock()
	defer t.firstMu.Unlock()
	if b := t.cur.Load(); b != nil {
		return b.pool
	}
	for !t.checking.CompareAndSwap(false, true) {
		time.Sleep(time.Millisecond) // a look started by another first: it ends
	}
	t.checked.Store(time.Now().UnixNano())
	done := make(chan struct{})
	go func() { t.look(); close(done) }()
	select {
	case <-done:
	case <-time.After(firstWait):
		p := Build(Settings{}, t.System)
		p.Err = fmt.Errorf("the settings (%s) did not answer in %v", t.path(), firstWait)
		if t.cur.CompareAndSwap(nil, &built{pool: p, stamp: "unanswered"}) {
			t.report(nil)
		}
	}
	return t.cur.Load().pool
}

// look reads the files when they changed and builds the new pool.
func (t *Trust) look() {
	defer t.checking.Store(false)
	old := t.cur.Load()
	var b built
	if old != nil {
		b = *old
	}
	stamp := "fixed"
	if t.Fixed != nil {
		b.settings, b.settingsErr = *t.Fixed, nil
	} else if stamp = fileStamp(t.path()); old == nil || stamp != b.settingsStamp {
		b.settings, b.settingsErr = ReadSettings(t.path())
		b.settingsStamp = stamp
	}
	stamp += " " + fileStamp(b.settings.File)
	if old != nil && stamp == old.stamp {
		return
	}
	p := Build(b.settings, t.System)
	if b.settingsErr != nil {
		p.Err = b.settingsErr
	}
	b.pool, b.stamp = p, stamp
	t.cur.Store(&b)
	// Refusals count under the pool that made them.
	t.mu.Lock()
	t.refused, t.rescued = nil, nil
	t.open.Store(0)
	t.mu.Unlock()
	t.report(nil)
}

// report calls Report with the state now and the refusal it is about.
func (t *Trust) report(ev *Refusal) {
	if t.Report != nil {
		s := t.Status()
		s.Event = ev
		t.Report(s)
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
// node's peer is kept, by its host name: never anything of a user's (a
// request's path or query, a DoH question).
func (t *Trust) Refused(host string, err error) { t.refusedBy(t.current(), host, err, false) }

func (t *Trust) refusedBy(p *Pool, host string, err error, rescued bool) {
	ev := &Refusal{Host: host, Err: verifyReason(err), Rescued: rescued}
	t.mu.Lock()
	t.total++
	if b := t.cur.Load(); b != nil && b.pool == p {
		m := &t.refused
		if rescued {
			m = &t.rescued
		}
		if *m == nil {
			*m = map[string]*refusal{}
		}
		r := (*m)[host]
		if r == nil {
			r = &refusal{}
			(*m)[host] = r
		}
		r.n++
		r.err, r.at = ev.Err, t.now()
		if rescued {
			// Went through: no longer refused outright.
			delete(t.refused, host)
		}
		t.open.Store(int64(len(t.refused) + len(t.rescued)))
	}
	t.mu.Unlock()
	t.report(ev)
}

// reached clears the refusals of host: the pool p let a connection to it
// through. Lock-free while nothing is refused.
func (t *Trust) reached(p *Pool, host string) {
	if t.open.Load() == 0 {
		return
	}
	t.mu.Lock()
	_, a := t.refused[host]
	_, b := t.rescued[host]
	cleared := (a || b) && t.cur.Load().pool == p
	if cleared {
		delete(t.refused, host)
		delete(t.rescued, host)
		t.open.Store(int64(len(t.refused) + len(t.rescued)))
	}
	t.mu.Unlock()
	if cleared {
		t.report(nil)
	}
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

	cur atomic.Pointer[poolTransport]
	mu  sync.Mutex      // a new pool's transport, the fallback's
	sys *http.Transport // the fallback's, for the pool sp
	sp  *Pool
}

// poolTransport is the transport of one pool.
type poolTransport struct {
	pool *Pool
	tr   *http.Transport
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
	if c := x.cur.Load(); c != nil && c.pool == p {
		return p, c.tr
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	c := x.cur.Load()
	if c != nil && c.pool == p {
		return p, c.tr
	}
	if c != nil {
		c.tr.CloseIdleConnections()
	}
	if x.sys != nil {
		x.sys.CloseIdleConnections()
		x.sys, x.sp = nil, nil
	}
	c = &poolTransport{pool: p, tr: x.with(p.CertPool())}
	x.cur.Store(c)
	return p, c.tr
}

// system is the fallback's transport: the system store and the pool.
func (x *transport) system(p *Pool) (*http.Transport, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.sys != nil && x.sp == p {
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
	if x.sys != nil {
		x.sys.CloseIdleConnections()
	}
	x.sys, x.sp = x.with(pool), p
	return x.sys, nil
}

func (x *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	p, tr := x.current()
	resp, err := tr.RoundTrip(req)
	host := req.URL.Hostname()
	if err == nil {
		x.t.reached(p, host)
		return resp, nil
	}
	if !Verification(err) {
		return resp, err
	}
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
					x.t.refusedBy(p, host, err, false)
					return nil, berr
				}
				r2.Body = body
			}
			resp2, err2 := sys.RoundTrip(r2)
			x.t.refusedBy(p, host, err, err2 == nil)
			if err2 == nil || !Verification(err2) {
				return resp2, err2
			}
			return nil, fmt.Errorf("%w (the node trusts its embedded root list: rayctl roots)", err2)
		}
	}
	x.t.refusedBy(p, host, err, false)
	return nil, fmt.Errorf("%w (the node trusts its embedded root list: rayctl roots)", err)
}

// CloseIdleConnections is http.Client's.
func (x *transport) CloseIdleConnections() {
	x.mu.Lock()
	defer x.mu.Unlock()
	if c := x.cur.Load(); c != nil {
		c.tr.CloseIdleConnections()
	}
	if x.sys != nil {
		x.sys.CloseIdleConnections()
	}
}
