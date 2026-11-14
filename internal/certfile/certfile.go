// Package certfile serves a TLS certificate that may change under a
// running process (spec/cert-pin-v1.md §6): a renewed chain reaches the
// next handshake without a restart, and the connections that are open go
// on with the one they began with.
//
// rayd naive and rayd site read their chain from a rendered file, which
// rayd replaces at every renewal. Before, the unit restarted for it, and
// every user's tunnels were cut once per renewal.
package certfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// Holder serves the certificate last given to Set.
type Holder struct {
	cur atomic.Pointer[tls.Certificate]
}

// Set makes cert the certificate of the handshakes from now on.
func (h *Holder) Set(cert tls.Certificate) { h.cur.Store(&cert) }

// Current is the certificate in use, nil before the first Set.
func (h *Holder) Current() *tls.Certificate { return h.cur.Load() }

// GetCertificate is tls.Config.GetCertificate: the certificate in use,
// whatever name the client asks for (the front passes one name here).
func (h *Holder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := h.cur.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("no certificate")
}

// DefaultEvery is how often Loader.Watch looks at the files, as naive
// looks at its users file and its conn-limit switch.
const DefaultEvery = 5 * time.Second

// maxFile bounds a chain or key file: a chain is a few kilobytes.
const maxFile = 1 << 20

// Loader is a Holder fed from a chain file and a key file. A change of
// either is taken when both are whole PEM, parse and pair; otherwise the
// certificate in use stays and the reason is logged, once for each new
// content. The files are written whole (rayd renames a finished file over
// the old one), but a truncated or foreign file must never replace a
// certificate that works.
type Loader struct {
	Holder
	Chain string // PEM, leaf first
	Key   string // PEM
	// Parse makes the certificate of the files' contents; nil is
	// tls.X509KeyPair.
	Parse func(chainPEM, keyPEM []byte) (tls.Certificate, error)
	Log   *slog.Logger
	// Every is the interval of Watch; 0 is DefaultEvery.
	Every time.Duration

	seen    [sha256.Size]byte // the contents last tried
	lastErr string            // the read error last logged
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the unit's own file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("%s is too large for a certificate file", path)
	}
	return b, nil
}

// read reads both files and names their contents.
func (l *Loader) read() (chain, key []byte, sum [sha256.Size]byte, err error) {
	if chain, err = readFile(l.Chain); err != nil {
		return nil, nil, sum, err
	}
	if key, err = readFile(l.Key); err != nil {
		return nil, nil, sum, err
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d\n", len(chain))
	h.Write(chain)
	h.Write(key)
	return chain, key, [sha256.Size]byte(h.Sum(nil)), nil
}

// whole refuses a PEM file that does not end with a finished block.
// tls.X509KeyPair skips what it cannot decode: a chain cut off in its
// second certificate would pass as the leaf alone, which no client can
// verify.
func whole(what string, b []byte) error {
	blocks := 0
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			break
		}
		blocks, b = blocks+1, rest
	}
	if blocks == 0 {
		return fmt.Errorf("no PEM block in the %s file", what)
	}
	if len(bytes.TrimSpace(b)) != 0 {
		return fmt.Errorf("the %s file does not end with a whole PEM block", what)
	}
	return nil
}

func (l *Loader) parse(chain, key []byte) (tls.Certificate, error) {
	if err := errors.Join(whole("chain", chain), whole("key", key)); err != nil {
		return tls.Certificate{}, err
	}
	if l.Parse != nil {
		return l.Parse(chain, key)
	}
	return tls.X509KeyPair(chain, key)
}

// Load reads the files for the first time; without a certificate the
// process has nothing to serve, so the error is the caller's to stop on.
func (l *Loader) Load() error {
	chain, key, sum, err := l.read()
	if err != nil {
		return err
	}
	cert, err := l.parse(chain, key)
	if err != nil {
		return err
	}
	l.seen = sum
	l.Set(cert)
	return nil
}

// Reload reads the files again and reports whether a new certificate is in
// use. Unchanged contents are not parsed again; contents that do not make
// a certificate leave the one in use and return the reason once.
func (l *Loader) Reload() (bool, error) {
	chain, key, sum, err := l.read()
	if err != nil {
		// A file that is not there or not readable: said once, until it
		// reads again or fails differently.
		if err.Error() == l.lastErr {
			return false, nil
		}
		l.lastErr = err.Error()
		return false, err
	}
	l.lastErr = ""
	if sum == l.seen {
		return false, nil
	}
	l.seen = sum
	cert, err := l.parse(chain, key)
	if err != nil {
		return false, err
	}
	l.Set(cert)
	return true, nil
}

// Watch reloads every Every until ctx ends. Load comes first.
func (l *Loader) Watch(ctx context.Context) {
	every := l.Every
	if every <= 0 {
		every = DefaultEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		changed, err := l.Reload()
		if l.Log == nil {
			continue
		}
		switch {
		case err != nil:
			// The error of the TLS or X.509 parser, or of the file system:
			// neither holds the files' contents. A chain for a new key is
			// such a case: the key comes with a restart of the unit.
			l.Log.Warn("certificate not reloaded; the one in use stays", "chain", l.Chain, "err", err)
		case changed:
			l.Log.Info("certificate reloaded", "chain", l.Chain, "not_after", notAfter(l.Current()))
		}
	}
}

// notAfter is the end of a certificate's leaf, for the log.
func notAfter(c *tls.Certificate) string {
	if c == nil || len(c.Certificate) == 0 {
		return ""
	}
	leaf := c.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return ""
		}
	}
	return leaf.NotAfter.UTC().Format(time.RFC3339)
}
