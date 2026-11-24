package site

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// LoadCertificate reads the chain (PEM, leaf first) and key and completes
// the chain with its root (from roots; nil is the system pool) when the
// chain is shorter than minChain bytes: REALITY pads its own certificate
// (with the ML-DSA-65 signature) to the target's chain and fails on a
// shorter one. Sending the root is allowed by TLS and common.
func LoadCertificate(chainPEM, keyPEM []byte, minChain int, roots *x509.CertPool) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return cert, err
	}
	if chainLen(cert.Certificate) >= minChain {
		return cert, nil
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return cert, err
	}
	inter := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Intermediates: inter, Roots: roots})
	if err == nil && len(chains) > 0 {
		root := chains[0][len(chains[0])-1]
		if !root.Equal(leaf) {
			cert.Certificate = append(cert.Certificate, root.Raw)
		}
	}
	if n := chainLen(cert.Certificate); n < minChain {
		return cert, fmt.Errorf("certificate chain of %d bytes, REALITY needs %d", n, minChain)
	}
	return cert, nil
}

func chainLen(chain [][]byte) int {
	n := 0
	for _, c := range chain {
		n += len(c) + 5
	}
	return n
}

// TLSConfig is what the site offers: TLS 1.3 with X25519MLKEM768 first
// (Go's default) and HTTP/2, as REALITY needs from its target, and TLS 1.2
// with modern suites for the rest: a probe that REALITY hands to the site
// meets a server like most others, not one that refuses TLS 1.2. naive and
// DoH on the same address offer the same (cmd/rayd, v0.36.1): a probe
// cannot tell their names from the site's by what their handshakes take;
// what they serve is for PostQuantum requests only.
func TLSConfig(cert tls.Certificate) *tls.Config {
	return TLSConfigFor(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil })
}

// TLSConfigFor is TLSConfig with the certificate get gives at each
// handshake: one that changes under the running site, when it is renewed
// (certfile.Loader).
func TLSConfigFor(get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: get,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

// PostQuantum reports whether r came over TLS whose key exchange was
// X25519MLKEM768 (TLS 1.3, Go 1.25's ConnectionState.CurveID, set on a
// resumption too, which Go's server makes with a key share only). naive's
// tunnels and DoH's answers go over such connections alone: the handshake
// takes what the site's does, so that a probe without ML-KEM meets the
// site's answer on every name of the address, and the users' traffic stays
// post-quantum. No TLS at all (r.TLS nil) is not.
func PostQuantum(r *http.Request) bool {
	return r.TLS != nil && r.TLS.CurveID == tls.X25519MLKEM768
}

// What the site answers to whoever REALITY hands it: a TLS handshake with
// a real certificate always (REALITY needs it), then by default nothing a
// prober can use (docs/decisions.md, R4-8).
const (
	Answer404    = "404"    // every request: 404, no body (the default)
	Answer403    = "403"    // every request: 403, no body
	AnswerSilent = "silent" // no answer at all: held, then the connection drops
	AnswerPages  = "pages"  // the generated site, served from root
)

// Answers lists the modes.
var Answers = []string{Answer404, Answer403, AnswerSilent, AnswerPages}

// SilentHold is how long a silent site holds a request before it drops the
// connection, about what an idle proxy or load balancer waits.
var SilentHold = 60 * time.Second

// silentMax bounds the requests held at once; beyond it they drop at once.
const silentMax = 256

// Responder returns the handler of a mode. Only "pages" reads files; the
// others parse nothing past the request line and headers.
func Responder(mode, root string) (http.Handler, error) {
	switch mode {
	case "", Answer404, Answer403:
		code := http.StatusNotFound
		if mode == Answer403 {
			code = http.StatusForbidden
		}
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(code)
		}), nil
	case AnswerSilent:
		held := make(chan struct{}, silentMax)
		return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			giveUpBody(r)
			select {
			case held <- struct{}{}:
				defer func() { <-held }()
				t := time.NewTimer(SilentHold)
				defer t.Stop()
				select {
				case <-r.Context().Done():
				case <-t.C:
				}
			default:
			}
			// Closes the connection (HTTP/1) or resets the stream (h2)
			// without a response.
			panic(http.ErrAbortHandler)
		}), nil
	case AnswerPages:
		if root == "" {
			return nil, errors.New("site pages need a content directory")
		}
		return Handler(root), nil
	}
	return nil, fmt.Errorf("site answer %q: want one of %s", mode, strings.Join(Answers, ", "))
}

// giveUpBody lets go of a request's body before the request is held: an
// answer of the site's never reads one, and one it holds unread is the
// client's flow-control window of the process's memory (ConnWindow a
// connection over HTTP/2, for SilentHold) at no cost to a client without a
// password. The other answers return at once, which lets go of it too.
//
// Over HTTP/2 what came is dropped and what comes is not kept: the
// connection's window goes back as it comes, the stream's does not, so the
// client can send a stream's window and no more. Over HTTP/3 the client is
// told to stop sending. An HTTP/1 body is not read at all: it waits in the
// socket, and closing it would read it.
func giveUpBody(r *http.Request) {
	if r.ProtoMajor >= 2 && r.Body != nil {
		_ = r.Body.Close()
	}
}

// Handler serves the site's files: no directory listings, its own 404 page
// and the headers a static site usually sends.
func Handler(root string) http.Handler {
	files := http.FileServer(http.Dir(root))
	notFound := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		if b, err := os.ReadFile(path.Join(root, "404.html")); err == nil { //nolint:gosec // G304: inside the site root
			_, _ = w.Write(b)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/") {
			p = path.Join(p, "index.html")
		}
		st, err := os.Stat(path.Join(root, p)) //nolint:gosec // G304: cleaned, inside the site root
		if err == nil && st.IsDir() {
			if _, err := os.Stat(path.Join(root, p, "index.html")); err == nil { //nolint:gosec // G304: as above
				// The site's own directory, escaped: a path on this host
				// whatever its name holds (a backslash, which browsers read
				// as "/", a "?", a "%").
				to := (&url.URL{Path: p + "/"}).EscapedPath()
				http.Redirect(w, r, to, http.StatusMovedPermanently) //nolint:gosec // G710: an existing directory of the site, escaped: a path on this host
				return
			}
		}
		if err != nil || st.IsDir() {
			notFound(w)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		files.ServeHTTP(w, r)
	})
}

// Serve serves the site with TLS on ln until ctx ends.
func Serve(ctx context.Context, ln net.Listener, h http.Handler, cert tls.Certificate, log *slog.Logger) error {
	return ServeCertificates(ctx, ln, h, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, log)
}

// ServeCertificates is Serve with the certificate get gives at each
// handshake (TLSConfigFor).
func ServeCertificates(ctx context.Context, ln net.Listener, h http.Handler, get func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	log *slog.Logger) error {
	srv := HTTPServer(h, IdleTimeout)
	srv.TLSConfig = TLSConfigFor(get)
	srv.ErrorLog = slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
