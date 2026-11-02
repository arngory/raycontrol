package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// testKey is a minisign key pair made the way minisign makes one.
type testKey struct {
	pub  string
	priv ed25519.PrivateKey
	id   []byte
}

func newKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	return testKey{pub: base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), id...), pub...)), priv: priv, id: id}
}

// sign makes a minisign signature file; legacy signs the file itself.
func (k testKey) sign(msg []byte, trusted string, legacy bool) []byte {
	alg, signed := "ED", msg
	if legacy {
		alg = "Ed"
	} else {
		h := blake2b.Sum512(msg)
		signed = h[:]
	}
	sig := ed25519.Sign(k.priv, signed)
	global := ed25519.Sign(k.priv, append(slices.Clone(sig), trusted...))
	raw := append(append([]byte(alg), k.id...), sig...)
	return []byte(fmt.Sprintf("untrusted comment: test\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(raw), trusted, base64.StdEncoding.EncodeToString(global)))
}

func TestVerify(t *testing.T) {
	k, other := newKey(t), newKey(t)
	msg := []byte("abc  raycontrol-linux-amd64.tar.gz\n")
	sig := k.sign(msg, "raycontrol v0.2.0", false)
	if trusted, err := Verify(msg, sig, k.pub); err != nil || trusted != "raycontrol v0.2.0" {
		t.Fatalf("prehashed: %q %v", trusted, err)
	}
	if _, err := Verify(msg, k.sign(msg, "raycontrol v0.2.0", true), k.pub); err != nil {
		t.Fatalf("legacy: %v", err)
	}
	changedComment := bytes.Replace(sig, []byte("v0.2.0"), []byte("v9.9.9"), 1)
	for name, c := range map[string]struct {
		msg, sig []byte
		key      string
	}{
		"other key":       {msg, sig, other.pub},
		"changed file":    {append(slices.Clone(msg), 'x'), sig, k.pub},
		"changed comment": {msg, changedComment, k.pub},
		"empty signature": {msg, nil, k.pub},
		"garbage key":     {msg, sig, "bm90IGEga2V5"},
		"signed by other": {msg, other.sign(msg, "raycontrol v0.2.0", false), k.pub},
		"truncated":       {msg, sig[:40], k.pub},
	} {
		if _, err := Verify(c.msg, c.sig, c.key); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	if PubKey == "" || !strings.Contains(readFile(t, "../../install/bootstrap.sh"), `PUBKEY="`+PubKey+`"`) {
		t.Fatal("bootstrap.sh and the release package must check with the same key")
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The key and signatures minisign itself made (test/install/minisig.sh
// sets MINISIGN_TEST_DIR in CI).
func TestVerifyMinisign(t *testing.T) {
	dir := os.Getenv("MINISIGN_TEST_DIR")
	if dir == "" {
		t.Skip("set MINISIGN_TEST_DIR (test/install/minisig.sh does)")
	}
	key := strings.Split(readFile(t, filepath.Join(dir, "k.pub")), "\n")[1]
	for _, f := range []string{"SHA256SUMS", "legacy"} {
		if _, err := Verify([]byte(readFile(t, filepath.Join(dir, f))), []byte(readFile(t, filepath.Join(dir, f+".minisig"))), key); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v0.2.0", "v0.1.9", true}, {"v0.10.0", "v0.9.0", true}, {"v1.0.0", "v1.0.0", false},
		{"v0.1.0", "v0.2.0", false}, {"v0.2.0", "dev", true}, {"dev", "v0.1.0", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func archive(t *testing.T, files map[string]string, extra ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for n := range files {
			if !yield(n) {
				return
			}
		}
	}) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(files[name])), Typeflag: tar.TypeReg})
		tw.Write([]byte(files[name]))
	}
	for _, h := range extra {
		tw.WriteHeader(h)
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestExtract(t *testing.T) {
	good := archive(t, map[string]string{"rayd": "1", "rayctl": "2", "VERSIONS": "raycontrol v0.2.0\n"})
	dir := t.TempDir()
	names, err := Extract(good, dir)
	if err != nil || len(names) != 3 {
		t.Fatalf("%v %v", names, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "rayctl")); string(b) != "2" {
		t.Fatalf("rayctl %q", b)
	}
	for name, a := range map[string][]byte{
		"outside":  archive(t, map[string]string{"../rayd": "x"}),
		"unknown":  archive(t, map[string]string{"evil": "x"}),
		"symlink":  archive(t, nil, &tar.Header{Name: "xray", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}),
		"twice":    archive(t, map[string]string{"rayd": "1"}, &tar.Header{Name: "rayd", Typeflag: tar.TypeReg}),
		"not gzip": []byte("plain"),
	} {
		if _, err := Extract(a, t.TempDir()); err == nil {
			t.Errorf("%s: extracted", name)
		}
	}
}

// release serves a signed release, optionally behind a broken GitHub.
func serveRelease(t *testing.T, k testKey, version string, arc []byte, brokenGitHub bool) (*Fetcher, *[]string) {
	t.Helper()
	sum := sha256.Sum256(arc)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + Archive("amd64") + "\n")
	sig := k.sign(sums, "raycontrol "+version, false)
	var hits []string
	files := map[string][]byte{"SHA256SUMS": sums, "SHA256SUMS.minisig": sig, Archive("amd64"): arc}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		path := r.URL.Path
		mirrored := strings.HasPrefix(path, "/mirror/")
		if brokenGitHub && !mirrored {
			http.Error(w, "unreachable", http.StatusBadGateway)
			return
		}
		name := path[strings.LastIndex(path, "/")+1:]
		b, ok := files[name]
		if !ok || (!strings.Contains(path, "/latest/download/") && !strings.Contains(path, "/download/"+version+"/")) {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return &Fetcher{Base: srv.URL, Mirrors: []string{srv.URL + "/mirror/"}}, &hits
}

func TestFetch(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	arc := archive(t, map[string]string{"rayd": "new"})
	f, _ := serveRelease(t, k, "v0.3.0", arc, false)
	// The mirror prefix is a full URL in production; here it points at the
	// same test server.
	f.Mirrors = nil
	r, err := f.Fetch(ctx, "latest", "amd64", k.pub)
	if err != nil || r.Version != "v0.3.0" || !bytes.Equal(r.Archive, arc) {
		t.Fatalf("latest: %v %v", r.Version, err)
	}
	if _, err := f.Fetch(ctx, "v0.2.0", "amd64", k.pub); err == nil {
		t.Fatal("a release asked for by another version")
	}
	if _, err := f.Fetch(ctx, "latest", "amd64", newKey(t).pub); err == nil {
		t.Fatal("a release signed with another key")
	}

	// GitHub down: the mirror serves, the signature still decides.
	f, hits := serveRelease(t, k, "v0.3.0", arc, true)
	f.Mirrors = []string{f.Base + "/mirror/"}
	if r, err = f.Fetch(ctx, "latest", "amd64", k.pub); err != nil || r.Version != "v0.3.0" {
		t.Fatalf("through the mirror: %v %v", r.Version, err)
	}
	if !slices.ContainsFunc(*hits, func(p string) bool { return strings.HasPrefix(p, "/mirror/") }) {
		t.Fatalf("mirror not used: %v", *hits)
	}
}

func TestLocal(t *testing.T) {
	k := newKey(t)
	arc := archive(t, map[string]string{"rayd": "new"})
	sum := sha256.Sum256(arc)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + Archive("arm64") + "\n")
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), sums, 0o644)
	os.WriteFile(filepath.Join(dir, "SHA256SUMS.minisig"), k.sign(sums, "raycontrol v0.4.0", false), 0o644)
	os.WriteFile(filepath.Join(dir, Archive("arm64")), arc, 0o644)
	if r, err := Local(dir, "arm64", k.pub); err != nil || r.Version != "v0.4.0" {
		t.Fatalf("%v %v", r.Version, err)
	}
	os.WriteFile(filepath.Join(dir, Archive("arm64")), append(arc, 0), 0o644)
	if _, err := Local(dir, "arm64", k.pub); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("changed archive: %v", err)
	}
}
