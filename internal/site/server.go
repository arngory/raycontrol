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
// meets a server like most others, not one that refuses TLS 1.2.
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

// What the site answers to whoever REALITY hands it: a TLS handshake with
// a real certificate always (REALITY needs it), then by default nothing a
// prober can use (docs/08-decisions.md, R4-8).
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
				http.Redirect(w, r, p+"/", http.StatusMovedPermanently)
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
	srv := &http.Server{
		Handler:           h,
		TLSConfig:         TLSConfigFor(get),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
