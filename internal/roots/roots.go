// Package roots decides which certificate roots the node's own outbound
// TLS trusts (docs/08-decisions.md, R4-41): ACME, the release downloads
// and the update check, the Cloudflare API, IPinfo, the client's releases
// for the app mirror, the DoH upstreams. It is the only place that decides.
//
// By default the node trusts the embedded list only (roots.pem): the
// intersection of Chrome's and Mozilla's lists without the CAs based in
// China, the same list the client's core uses. The image's system store
// is not trusted: a VPS image with a tampered, outdated or missing store
// neither breaks the node nor lets a root planted there read its
// connections. Root may add the system store, a PEM file of its own (a
// TLS-intercepting proxy, a private ACME CA), or both (Settings,
// rayctl roots).
package roots

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"

	"crypto/x509"
)

//go:embed roots.pem
var embeddedPEM []byte

// SettingsFile holds root's choice; rayd (through -tls-roots) and rayctl
// read it. It is in /etc, root's, and world-readable: rayd reads it
// without being able to change it.
const SettingsFile = "/etc/raycontrol/tls-roots.json"

// ExtraFile is where rayctl roots file puts the PEM it was given, so that
// rayd reads it whatever its sandbox.
const ExtraFile = "/etc/raycontrol/tls-roots.pem"

// Settings is what the node trusts besides the embedded list. The zero
// value is the default: the embedded list only.
type Settings struct {
	// System adds the image's store (SSL_CERT_FILE and SSL_CERT_DIR count
	// there, as Go reads them).
	System bool `json:"system,omitempty"`
	// File adds the roots of a PEM file.
	File string `json:"file,omitempty"`
}

// ReadSettings reads a settings file; a missing file is the default.
func ReadSettings(path string) (Settings, error) {
	var s Settings
	b, err := readRegular(path, 1<<16)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// readRegular reads a regular file of at most limit bytes. A FIFO, a
// device or a directory is refused without being read: opened without
// waiting for a writer, then checked.
func readRegular(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: root's file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is no regular file (%v)", path, fi.Mode().Type())
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, err
}

// WriteSettings writes a settings file (0644, by rename); the default
// removes it.
func WriteSettings(path string, s Settings) error {
	if s == (Settings{}) {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(b, '\n'))
}

// WriteExtra writes roots to a PEM file (ExtraFile), readable by all.
func WriteExtra(path string, cs []*x509.Certificate) error {
	var b bytes.Buffer
	for _, c := range cs {
		fmt.Fprintf(&b, "# %s\n", c.Subject)
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return writeFile(path, b.Bytes())
}

// writeFile writes a file of root's by rename, mode 0644 whatever root's
// umask (027 would leave it 0640 root:root, which rayd, user rayd, cannot
// read: it would stay on the embedded list while rayctl said done). The
// files hold public certificates and two settings, nothing secret.
func writeFile(path string, b []byte) error {
	if err := openDir(filepath.Dir(path)); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec // G302,G304: roots, no secret; rayd reads them
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Chmod(0o644); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// openDir makes dir 0755 whatever the umask, or, when it exists, gives it
// the search bits rayd needs (0o011) and nothing else: an existing
// /etc/raycontrol may hold a relay's bundle (0600 itself, so the bundle
// does not rely on the directory), and a listing root closed stays closed.
func openDir(dir string) error {
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: /etc/raycontrol, read by rayd
			return err
		}
		return os.Chmod(dir, 0o755) //nolint:gosec // G302: as above
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	case fi.Mode().Perm()&0o011 != 0o011:
		return os.Chmod(dir, fi.Mode().Perm()|0o011)
	}
	return nil
}

// Embedded is the embedded list.
var Embedded = sync.OnceValue(func() []*x509.Certificate {
	cs, err := ParsePEM(embeddedPEM)
	if err != nil {
		panic("roots: the embedded list: " + err.Error()) // TestEmbedded
	}
	return cs
})

var headerRe = regexp.MustCompile(`(?m)^# (date|count|source): (.+)$`)

func header(key string) string {
	for _, m := range headerRe.FindAllSubmatch(embeddedPEM, 3) {
		if string(m[1]) == key {
			return string(m[2])
		}
	}
	return ""
}

// Date is the date of the embedded list (YYYY-MM-DD).
func Date() string { return header("date") }

// Source says where the embedded list comes from.
func Source() string { return header("source") }

// ParsePEM reads every CERTIFICATE block of b, whatever is around them;
// none is an error.
func ParsePEM(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates")
	}
	return out, nil
}

// ReadExtra reads the roots of a PEM file: CA certificates only.
func ReadExtra(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: root's file
	if err != nil {
		return nil, err
	}
	return extraOf(path, b)
}

// extraOf is ReadExtra's check of a file's content.
func extraOf(path string, b []byte) ([]*x509.Certificate, error) {
	cs, err := ParsePEM(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, c := range cs {
		if !c.IsCA {
			return nil, fmt.Errorf("%s: %s is no CA certificate", path, c.Subject)
		}
	}
	return cs, nil
}

// Pool is a choice of roots, built.
type Pool struct {
	Settings Settings
	// Extra is the number of roots from Settings.File.
	Extra int
	// Err is why the settings could not be followed; the pool is then
	// the embedded list only (never more than root asked for).
	Err error

	pool *x509.CertPool
}

// CertPool is the pool to verify with.
func (p *Pool) CertPool() *x509.CertPool { return p.pool }

// Build makes the pool of s; system is the image's store
// (x509.SystemCertPool when nil). When s cannot be followed (the store
// does not load, the file is missing or has no CA), the pool is the
// embedded list with Err set.
func Build(s Settings, system func() (*x509.CertPool, error)) *Pool {
	if system == nil {
		system = x509.SystemCertPool
	}
	p := &Pool{Settings: s}
	pool := x509.NewCertPool()
	if s.System {
		sp, err := system()
		switch {
		case err != nil:
			p.Err = fmt.Errorf("the system store: %w", err)
		case sp != nil:
			pool = sp.Clone()
		}
	}
	if s.File != "" && p.Err == nil {
		// A regular file only: a FIFO there must not hold the build.
		b, err := readRegular(s.File, 4<<20)
		var cs []*x509.Certificate
		if err == nil {
			cs, err = extraOf(s.File, b)
		}
		if err != nil {
			p.Err = err
		}
		for _, c := range cs {
			pool.AddCert(c)
		}
		p.Extra = len(cs)
	}
	if p.Err != nil {
		pool, p.Extra = x509.NewCertPool(), 0
	}
	for _, c := range Embedded() {
		pool.AddCert(c)
	}
	p.pool = pool
	return p
}

// String says which roots the pool has, on one line: "embedded 91 roots
// of 2026-11-14; system store not added; no extra file".
func (p *Pool) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "embedded %d roots of %s", len(Embedded()), Date())
	if p.Settings.System && p.Err == nil {
		b.WriteString("; system store added")
	} else {
		b.WriteString("; system store not added")
	}
	switch {
	case p.Settings.File == "":
		b.WriteString("; no extra file")
	case p.Err == nil:
		fmt.Fprintf(&b, "; extra file %s (%s)", p.Settings.File, plural(p.Extra, "root"))
	}
	if p.Err != nil {
		fmt.Fprintf(&b, "; the settings are not followed: %v", p.Err)
	}
	return b.String()
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return strconv.Itoa(n) + " " + what + "s"
}
