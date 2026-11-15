package roots_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/roots"
	"github.com/arngory/raycontrol/internal/roots/rootstest"
	"github.com/arngory/raycontrol/internal/testca"
)

// embeddedSHA256 pins roots.pem: a list rebuilt by scripts/roots sets it
// to `sha256sum internal/roots/roots.pem` in the same commit, with the
// count and the roots TestEmbedded names; a change by any other way fails.
const embeddedSHA256 = "ec8cd2f776598555c23e9492c7c8cae6f3aa86de624a30e9bb17b7cb4fb7fb7b"

// TestEmbedded: the file is the one pinned, the list parses, has the count
// its header says, and holds the roots the node's peers chain to today;
// the CAs based in China and Hong Kong that Chromium's list has are not in
// it.
func TestEmbedded(t *testing.T) {
	b, err := os.ReadFile("roots.pem")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != embeddedSHA256 {
		t.Fatalf("roots.pem has SHA-256 %x, want %s: rebuilt by scripts/roots? then update embeddedSHA256", sum, embeddedSHA256)
	}
	cs := roots.Embedded()
	if len(cs) != 91 {
		t.Fatalf("%d roots, want 91", len(cs))
	}
	if roots.Date() != "2026-11-14" || !strings.Contains(roots.Source(), "34eaa8c9c5a9") {
		t.Fatalf("header: date %q, source %q", roots.Date(), roots.Source())
	}
	keys := map[string]bool{}
	names := map[string]bool{}
	for _, c := range cs {
		if !c.IsCA {
			t.Errorf("%s is no CA", c.Subject)
		}
		s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		k := hex.EncodeToString(s[:])
		if keys[k] {
			t.Errorf("%s twice", c.Subject)
		}
		keys[k] = true
		names[c.Subject.CommonName] = true
	}
	// Where the chains of the node's peers end (openssl s_client and
	// crt.sh, 2026-11-14). gh-proxy.com, the second mirror: the chain as
	// an egress proxy that re-terminates TLS handed it on (leaf, YE2,
	// Root YE cross-signed by ISRG Root X2 to 2032-09-02), not seen end
	// to end; Root YE and Root YR themselves are in neither list yet
	// (R4-41: when the list must be rebuilt).
	for _, want := range []string{
		"ISRG Root X1", // Let's Encrypt; *.githubusercontent.com (YR1), api.ipinfo.io
		"ISRG Root X2", // acme-v02.api.letsencrypt.org (YE1, Root YE); gh-proxy.com (YE2, Root YE), see below
		"Sectigo Public Server Authentication Root E46", // github.com (Sectigo DV E36)
		"Sectigo Public Server Authentication Root R46", // github.com (Sectigo DV R36), ghfast.top
		"USERTrust ECC Certification Authority",         // their cross-signs
		"USERTrust RSA Certification Authority",
		"GTS Root R4",                              // api.cloudflare.com (WE1)
		"SSL.com Root Certification Authority ECC", // 1.1.1.1 (DoH)
		"DigiCert Global Root G3",                  // 9.9.9.9 (DoH)
		"DigiCert Global Root G2",
	} {
		if !names[want] {
			t.Errorf("%s missing", want)
		}
	}
	for _, not := range []string{"UCA Global G2 Root", "UCA Extended Validation Root", "vTrus Root CA", "vTrus ECC Root CA",
		"GDCA TrustAUTH R5 ROOT", "CFCA EV ROOT", "TrustAsia TLS RSA Root CA", "TrustAsia TLS ECC Root CA", "Hongkong Post Root CA 3"} {
		if names[not] {
			t.Errorf("%s is in the list", not)
		}
	}
}

func tlsServer(t *testing.T) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(srv.Close)
	return srv, srv.Certificate()
}

func get(c *http.Client, url string) error {
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// TestBuild: the embedded list alone by default, the system store and a
// file only when asked, and the embedded list alone when the settings
// cannot be followed.
func TestBuild(t *testing.T) {
	_, cert := tlsServer(t)
	system := func() (*x509.CertPool, error) { p := x509.NewCertPool(); p.AddCert(cert); return p, nil }
	verifies := func(p *roots.Pool) bool {
		_, err := cert.Verify(x509.VerifyOptions{Roots: p.CertPool()})
		return err == nil
	}
	file := rootstest.File(t, cert)
	leafDir := t.TempDir()
	notCA := filepath.Join(leafDir, "leaf.pem")
	empty := filepath.Join(leafDir, "empty.pem")
	_ = os.WriteFile(empty, []byte("nothing\n"), 0o600)
	for _, tc := range []struct {
		name string
		s    roots.Settings
		ok   bool
		err  bool
		str  string
	}{
		{"default", roots.Settings{}, false, false, "embedded 91 roots of 2026-11-14; system store not added; no extra file"},
		{"system", roots.Settings{System: true}, true, false, "embedded 91 roots of 2026-11-14; system store added; no extra file"},
		{"file", roots.Settings{File: file}, true, false, "embedded 91 roots of 2026-11-14; system store not added; extra file " + file + " (1 root)"},
		{"missing", roots.Settings{File: filepath.Join(leafDir, "none.pem")}, false, true, "the settings are not followed"},
		{"empty", roots.Settings{File: empty}, false, true, "no certificates"},
		{"system and missing file", roots.Settings{System: true, File: notCA}, false, true, "system store not added"},
	} {
		p := roots.Build(tc.s, system)
		if verifies(p) != tc.ok || (p.Err != nil) != tc.err || !strings.Contains(p.String(), tc.str) {
			t.Errorf("%s: verifies %v, err %v, %q", tc.name, verifies(p), p.Err, p)
		}
	}
	// A system store that does not load: the embedded list.
	p := roots.Build(roots.Settings{System: true}, func() (*x509.CertPool, error) { return nil, errors.New("no store") })
	if p.Err == nil || verifies(p) {
		t.Fatalf("no store: %v", p)
	}
	// A leaf is no root.
	ch, err := testca.New([]string{"leaf.example.test"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := pem.Decode(ch.ChainPEM)
	_ = os.WriteFile(notCA, pem.EncodeToMemory(leaf), 0o600)
	if p := roots.Build(roots.Settings{File: notCA}, system); p.Err == nil || !strings.Contains(p.Err.Error(), "no CA") {
		t.Fatalf("leaf as root: %v", p.Err)
	}
}

// waitPool waits for the trust's pool to be one ok says yes to: the files
// are looked at by a goroutine of their own, every tr.Every.
func waitPool(t *testing.T, tr *roots.Trust, what string, ok func(*roots.Pool) bool) *roots.Pool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p := tr.Pool()
		if ok(p) {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the pool stays %v", what, p)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTransport: a server under a root not in the list is refused, and
// counted with its host; the extra file lets it through; the settings
// file is read again when it changes, and a new pool starts with no
// refusal.
func TestTransport(t *testing.T) {
	srv, cert := tlsServer(t)
	dir := t.TempDir()
	settings := filepath.Join(dir, "tls-roots.json")
	var mu sync.Mutex
	var seen []roots.Status
	tr := &roots.Trust{Path: settings, Every: 5 * time.Millisecond, Report: func(s roots.Status) { mu.Lock(); seen = append(seen, s); mu.Unlock() }}
	c := tr.Client(0)
	err := get(c, srv.URL+"/dns-query?dns=a-users-question")
	if err == nil || !roots.Verification(err) || !strings.Contains(err.Error(), "rayctl roots") {
		t.Fatalf("refused: %v", err)
	}
	st := tr.Status()
	if st.Refused != 1 || st.Total != 1 || st.LastHost != "127.0.0.1" || !strings.Contains(st.LastErr, "unknown authority") {
		t.Fatalf("status %+v", st)
	}
	// The peer's host only: nothing of the request.
	mu.Lock()
	for _, s := range seen {
		if s.Event != nil && (s.Event.Host != "127.0.0.1" || strings.Contains(s.Event.Err, "question") || strings.Contains(s.Event.Err, "dns-query")) {
			t.Errorf("event %+v", s.Event)
		}
	}
	mu.Unlock()
	if strings.Contains(fmt.Sprintf("%+v", st), "question") {
		t.Errorf("the request in the status: %+v", st)
	}
	if err := roots.WriteSettings(settings, roots.Settings{File: rootstest.File(t, cert)}); err != nil {
		t.Fatal(err)
	}
	waitPool(t, tr, "with the file", func(p *roots.Pool) bool { return p.Extra == 1 })
	if st := tr.Status(); st.Refused != 0 || st.Total != 1 {
		t.Fatalf("a new pool keeps the old one's refusals: %+v", st)
	}
	if err := get(c, srv.URL); err != nil {
		t.Fatalf("with the file: %v", err)
	}
	if err := roots.WriteSettings(settings, roots.Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Fatalf("the default is no file: %v", err)
	}
	waitPool(t, tr, "back to the default", func(p *roots.Pool) bool { return p.Settings.File == "" })
	c.CloseIdleConnections()
	if err := get(c, srv.URL); err == nil {
		t.Fatal("back to the default: accepted")
	}
	mu.Lock()
	n, last := len(seen), seen[len(seen)-1]
	mu.Unlock()
	if n < 4 || last.Refused != 1 || last.Total != 2 {
		t.Fatalf("%d reports, the last %+v", n, last)
	}
	// A settings file that does not parse: the embedded list, said so.
	_ = os.WriteFile(settings, []byte("{"), 0o600)
	waitPool(t, tr, "bad settings", func(p *roots.Pool) bool { return p.Err != nil && strings.Contains(p.String(), "not followed") })
}

// TestRefusalsClear: a refusal keeps the trust failing for RefusalWindow
// at most; a connection the pool lets through to the same host clears it
// at once, one to another host does not.
func TestRefusalsClear(t *testing.T) {
	srv, cert := tlsServer(t)
	now := time.Now()
	tr := &roots.Trust{Fixed: &roots.Settings{}, Now: func() time.Time { return now }}
	other := errors.New("x509: certificate signed by unknown authority")
	tr.Refused("api.cloudflare.com", other)
	tr.Refused("127.0.0.1", other)
	if st := tr.Status(); st.Refused != 2 {
		t.Fatalf("two refusals: %+v", st)
	}
	now = now.Add(time.Minute)
	tr.Refused("127.0.0.1", other)
	if st := tr.Status(); st.Refused != 3 || st.LastHost != "127.0.0.1" {
		t.Fatalf("again: %+v", st)
	}
	// The server's root is now trusted (the system store of a pool that
	// has it): the same host is reached.
	ok := &roots.Trust{Fixed: &roots.Settings{System: true}, System: func() (*x509.CertPool, error) {
		p := x509.NewCertPool()
		p.AddCert(cert)
		return p, nil
	}, Now: tr.Now}
	ok.Refused("127.0.0.1", other)
	ok.Refused("api.cloudflare.com", other)
	if err := get(ok.Client(0), srv.URL); err != nil {
		t.Fatal(err)
	}
	if st := ok.Status(); st.Refused != 1 || st.LastHost != "api.cloudflare.com" || st.Total != 2 {
		t.Fatalf("reached 127.0.0.1: %+v", st)
	}
	// Aged out.
	now = now.Add(roots.RefusalWindow - time.Minute + time.Second)
	if st := tr.Status(); st.Refused != 2 || st.LastHost != "127.0.0.1" {
		t.Fatalf("the first two aged out, not the third: %+v", st)
	}
	now = now.Add(time.Minute)
	if st := tr.Status(); st.Refused != 0 || st.Total != 3 {
		t.Fatalf("all aged out: %+v", st)
	}
}

// TestSystemFallback: a download whose content is signed may go on with
// the system store when the embedded list refuses its host, with a
// warning, and counted as rescued, not refused; without the option, or
// for any other client, it may not.
func TestSystemFallback(t *testing.T) {
	srv, cert := tlsServer(t)
	tr := rootstest.Use(t, roots.Settings{}, cert)
	if err := get(roots.Node.Client(0), srv.URL); err == nil {
		t.Fatal("no fallback: accepted through the system store")
	}
	var warned []string
	c := roots.Node.Client(0, roots.SystemFallback(func(host string, err error) { warned = append(warned, host+": "+err.Error()) }))
	if err := get(c, srv.URL); err != nil {
		t.Fatalf("fallback: %v", err)
	}
	st := tr.Status()
	if len(warned) != 1 || !strings.HasPrefix(warned[0], "127.0.0.1: ") || st.Refused != 0 || st.Rescued != 1 || st.RescuedHost != "127.0.0.1" || st.Total != 2 {
		t.Fatalf("warned %q, status %+v", warned, st)
	}
	// A fallback that does not help either is still refused.
	tr = rootstest.Use(t, roots.Settings{})
	c = roots.Node.Client(0, roots.SystemFallback(nil))
	if err := get(c, srv.URL); err == nil || !roots.Verification(err) {
		t.Fatalf("fallback without the root: %v", err)
	}
	if st := tr.Status(); st.Refused != 1 || st.Rescued != 0 {
		t.Fatalf("not rescued: %+v", st)
	}
}

// TestHungSettings: settings that do not answer (a hung mount; here the
// system store) leave the embedded list in force, said so, and hold no
// caller: the first one waits 2 s, the next none; once they answer, the
// pool follows them.
func TestHungSettings(t *testing.T) {
	release := make(chan struct{})
	tr := &roots.Trust{Fixed: &roots.Settings{System: true}, Every: time.Millisecond, System: func() (*x509.CertPool, error) {
		<-release
		return x509.NewCertPool(), nil
	}}
	start := time.Now()
	p := tr.Pool()
	if p.Err == nil || !strings.Contains(p.Err.Error(), "did not answer") || time.Since(start) > 4*time.Second {
		t.Fatalf("first pool %v after %v", p, time.Since(start))
	}
	time.Sleep(5 * time.Millisecond)
	start = time.Now()
	for range 1000 {
		tr.Pool()
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("1000 pools in %v, the look hung", d)
	}
	close(release)
	waitPool(t, tr, "answered", func(p *roots.Pool) bool { return p.Err == nil && p.Settings.System })
}

// TestSettingsNotAFile: a settings file or extra file that is a FIFO
// (or anything but a regular file) is refused, not waited on: the
// embedded list, said so, and no connection held.
func TestSettingsNotAFile(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "tls-roots.json")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip(err)
	}
	done := make(chan *roots.Pool, 1)
	go func() { done <- (&roots.Trust{Path: fifo}).Pool() }()
	select {
	case p := <-done:
		if p.Err == nil || !strings.Contains(p.Err.Error(), "no regular file") {
			t.Fatalf("a FIFO as settings: %v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pool waits for the FIFO")
	}
	if p := roots.Build(roots.Settings{File: fifo}, nil); p.Err == nil || !strings.Contains(p.Err.Error(), "no regular file") {
		t.Fatalf("a FIFO as extra file: %v", p)
	}
}

// TestSettingsFile: what rayctl roots writes, ReadSettings reads; the
// files are 0644 and a new directory 0755 under root's umask of 027, and
// an existing closed directory gets the search bits only.
func TestSettingsFile(t *testing.T) {
	old := syscall.Umask(0o027)
	t.Cleanup(func() { syscall.Umask(old) })
	p := filepath.Join(t.TempDir(), "sub", "tls-roots.json")
	if s, err := roots.ReadSettings(p); err != nil || s != (roots.Settings{}) {
		t.Fatalf("missing: %+v %v", s, err)
	}
	want := roots.Settings{System: true, File: "/etc/raycontrol/tls-roots.pem"}
	if err := roots.WriteSettings(p, want); err != nil {
		t.Fatal(err)
	}
	if s, err := roots.ReadSettings(p); err != nil || s != want {
		t.Fatalf("read %+v %v", s, err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v: rayd reads it", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Dir(p)); fi.Mode().Perm() != 0o755 {
		t.Fatalf("directory mode %v: rayd goes through it", fi.Mode())
	}
	extra := filepath.Join(filepath.Dir(p), "tls-roots.pem")
	if err := roots.WriteExtra(extra, roots.Embedded()[:1]); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(extra); fi.Mode().Perm() != 0o644 {
		t.Fatalf("extra file mode %v", fi.Mode())
	}
	// A directory root closed: entered, not listed.
	_ = os.Chmod(filepath.Dir(p), 0o700)
	if err := roots.WriteSettings(p, want); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Dir(p)); fi.Mode().Perm() != 0o711 {
		t.Fatalf("closed directory now %v, want 0711", fi.Mode())
	}
}

// TestSettingsFileNoLink: a link put at the name the temporary file had
// before (path.tmp) is not written through, nor a file there truncated;
// the settings are written beside it, and no temporary file is left.
func TestSettingsFileNoLink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "tls-roots.json")
	if err := os.Symlink(victim, p+".tmp"); err != nil {
		t.Fatal(err)
	}
	want := roots.Settings{System: true}
	if err := roots.WriteSettings(p, want); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("written through the link: %q", b)
	}
	if s, err := roots.ReadSettings(p); err != nil || s != want {
		t.Fatalf("read %+v %v", s, err)
	}
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Fatalf("%v %v", fi, err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "tls-roots.json.*.tmp"))
	if len(left) != 0 {
		t.Fatalf("left: %v", left)
	}
}

// TestUnreadable: the modes a user other than the owner needs, file and
// directories above it.
func TestUnreadable(t *testing.T) {
	top := t.TempDir()
	_ = os.Chmod(top, 0o755)
	_ = os.Chmod(filepath.Dir(top), 0o755)
	dir := filepath.Join(top, "etc")
	_ = os.Mkdir(dir, 0o755)
	f := filepath.Join(dir, "tls-roots.json")
	_ = os.WriteFile(f, []byte("{}"), 0o644)
	_ = os.Chmod(f, 0o644)
	const other = 4242
	if err := roots.Unreadable(f, other, []int{other}); err != nil {
		t.Fatalf("0644 in 0755: %v", err)
	}
	_ = os.Chmod(f, 0o640)
	if err := roots.Unreadable(f, other, []int{other}); err == nil || !strings.Contains(err.Error(), f+" is mode -rw-r-----") || !strings.Contains(err.Error(), "no read for uid 4242") {
		t.Fatalf("0640 root's: %v", err)
	}
	if err := roots.Unreadable(f, other, []int{other, os.Getegid()}); err != nil {
		t.Fatalf("0640, in the group: %v", err)
	}
	if err := roots.Unreadable(f, os.Geteuid(), nil); err != nil {
		t.Fatalf("its owner: %v", err)
	}
	_ = os.Chmod(f, 0o644)
	_ = os.Chmod(dir, 0o750)
	if err := roots.Unreadable(f, other, []int{other}); err == nil || !strings.Contains(err.Error(), dir+" is mode -rwxr-x---") || !strings.Contains(err.Error(), "no search") {
		t.Fatalf("in a 0750 directory: %v", err)
	}
	_ = os.Chmod(dir, 0o711)
	if err := roots.Unreadable(f, other, []int{other}); err != nil {
		t.Fatalf("0711 directory: %v", err)
	}
}
