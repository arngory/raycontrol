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

	"github.com/arngory/raycontrol/internal/roots"
	"github.com/arngory/raycontrol/internal/roots/rootstest"
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
	// A file a later release brings: written for its own rayctl to install.
	later := archive(t, map[string]string{"rayd": "1", "slipstream-server": "3"})
	dir = t.TempDir()
	if names, err := Extract(later, dir); err != nil || len(names) != 2 {
		t.Fatalf("a later release's file: %v %v", names, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "slipstream-server")); string(b) != "3" {
		t.Fatalf("slipstream-server %q", b)
	}
	many := map[string]string{}
	for i := range maxArchiveFiles + 1 {
		many[fmt.Sprintf("f%d", i)] = "x"
	}
	for name, a := range map[string][]byte{
		"outside":  archive(t, map[string]string{"../rayd": "x"}),
		"in a dir": archive(t, map[string]string{"lib/x": "x"}),
		"hidden":   archive(t, map[string]string{".profile": "x"}),
		"odd name": archive(t, map[string]string{"a b": "x"}),
		"too many": archive(t, many),
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

// TestFetchRoots: over HTTPS the release comes through the node's roots.
// A host whose root is not among them is tried again with the system
// store, with a warning: the signature protects the files, and a stale
// list must not stop the update that brings the next one. The extra file
// lets it through without one.
func TestFetchRoots(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	arc := archive(t, map[string]string{"rayd": "new"})
	sum := sha256.Sum256(arc)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + Archive("amd64") + "\n")
	files := map[string][]byte{"SHA256SUMS": sums, "SHA256SUMS.minisig": k.sign(sums, "raycontrol v0.3.0", false), Archive("amd64"): arc}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(files[r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]])
	}))
	defer srv.Close()
	var logged []string
	f := &Fetcher{Base: srv.URL, Log: func(format string, a ...any) { logged = append(logged, fmt.Sprintf(format, a...)) }}

	rootstest.Use(t, roots.Settings{})
	if _, err := f.Fetch(ctx, "latest", "amd64", k.pub); err == nil || !roots.Verification(err) {
		t.Fatalf("a root in neither: %v", err)
	}
	logged = nil
	tr := rootstest.Use(t, roots.Settings{}, srv.Certificate())
	if r, err := f.Fetch(ctx, "latest", "amd64", k.pub); err != nil || r.Version != "v0.3.0" {
		t.Fatalf("through the system store: %v", err)
	}
	if st := tr.Status(); len(logged) == 0 || !strings.Contains(logged[0], "warning: 127.0.0.1: ") || st.Rescued == 0 || st.Refused != 0 {
		t.Fatalf("logged %q, status %+v", logged, tr.Status())
	}
	logged = nil
	rootstest.Use(t, roots.Settings{File: rootstest.File(t, srv.Certificate())})
	if _, err := f.Latest(ctx, k.pub); err != nil || len(logged) != 0 {
		t.Fatalf("with the extra file: %v, logged %q", err, logged)
	}
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

// Latest reads the version off the signed SHA256SUMS of the latest release,
// with no archive; another key's signature is refused.
func TestLatest(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	f, hits := serveRelease(t, k, "v0.14.0", []byte("archive"), false)
	f.Mirrors = nil
	if v, err := f.Latest(ctx, k.pub); err != nil || v != "v0.14.0" {
		t.Fatalf("latest %q %v", v, err)
	}
	if slices.ContainsFunc(*hits, func(p string) bool { return strings.HasSuffix(p, Archive("amd64")) }) {
		t.Fatalf("an archive fetched: %v", *hits)
	}
	if _, err := f.Latest(ctx, newKey(t).pub); err == nil {
		t.Fatal("another key's signature taken")
	}
}

// The release workflow packs the files of Files. A file a release before
// v0.15.0 would refuse is in FilesSince, and the notes of the release that
// added it tell those nodes to update through v0.15.0 first: they have no
// other way but a new install.
func TestArchiveFiles(t *testing.T) {
	wf, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	// The node's archive: the workflow packs rayctl alone for other systems
	// too (rayctl-<os>-<arch>.tar.gz), which no node takes.
	var packed []string
	for _, line := range strings.Split(string(wf), "\n") {
		if _, rest, ok := strings.Cut(line, `tar -czf "raycontrol-linux-`); ok {
			f := strings.Fields(rest)
			for i, w := range f {
				if w == "-C" && i+2 < len(f) {
					packed = f[i+2:]
				}
			}
		}
	}
	if len(packed) == 0 {
		t.Fatal("no tar -czf \"raycontrol-linux-...\" -C dist <files> in release.yml")
	}
	for _, name := range packed {
		if !slices.Contains(Files, name) {
			t.Errorf("release.yml packs %s, which Files lacks", name)
		}
		if slices.Contains(FilesBeforeV015, name) {
			continue
		}
		since, ok := FilesSince[name]
		if !ok {
			t.Errorf("release.yml packs %s: releases before v0.15.0 refuse it, and FilesSince lacks it", name)
			continue
		}
		notes, err := os.ReadFile("../../.github/release-notes/" + since + ".md")
		if err != nil {
			t.Errorf("%s, added in %s: %v", name, since, err)
			continue
		}
		if !strings.Contains(string(notes), "v0.15.0 first") {
			t.Errorf("the notes of %s do not say that nodes before v0.15.0 update to it first (%s is new in the archive)", since, name)
		}
	}
}

// The update's handoff reads only rayctl from an archive, whatever else
// it holds: directories, names nobody knows yet, more files than Extract
// takes.
func TestExtractFile(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	add := func(h *tar.Header, body string) {
		h.Size = int64(len(body))
		if h.Typeflag == tar.TypeDir {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeDir {
			tw.Write([]byte(body))
		}
	}
	add(&tar.Header{Name: "bin/", Typeflag: tar.TypeDir, Mode: 0o755}, "")
	add(&tar.Header{Name: "bin/rayctl", Typeflag: tar.TypeReg, Mode: 0o755}, "not this one")
	for i := range 80 {
		add(&tar.Header{Name: fmt.Sprintf("transport-%d", i), Typeflag: tar.TypeReg, Mode: 0o755}, "x")
	}
	add(&tar.Header{Name: "rayctl-link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}, "")
	add(&tar.Header{Name: "./rayctl", Typeflag: tar.TypeReg, Mode: 0o755}, "the new rayctl")
	tw.Close()
	zw.Close()

	if _, err := Extract(buf.Bytes(), t.TempDir()); err == nil {
		t.Fatal("Extract took a layout of the future")
	}
	dst := filepath.Join(t.TempDir(), "rayctl")
	if err := ExtractFile(buf.Bytes(), "rayctl", dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "the new rayctl" {
		t.Fatalf("got %q", b)
	}
	if err := ExtractFile(buf.Bytes(), "rayd", filepath.Join(t.TempDir(), "rayd")); err == nil || !strings.Contains(err.Error(), "no rayd") {
		t.Fatalf("a missing file: %v", err)
	}
	if err := ExtractFile([]byte("not gzip"), "rayctl", filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("garbage taken")
	}
}

// releaseArchives are the archives of a release as the Release workflow
// names them (ARCHIVES), in the order of its SHA256SUMS.
func releaseArchives(t *testing.T) []string {
	t.Helper()
	wf := readFile(t, "../../.github/workflows/release.yml")
	_, rest, ok := strings.Cut(wf, "\n      ARCHIVES: >-\n")
	if !ok {
		t.Fatal("no ARCHIVES in release.yml")
	}
	var names []string
	for _, line := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(line, "        ") {
			break
		}
		names = append(names, strings.Fields(line)...)
	}
	// The checksums and the upload are of that list, not of a pattern that
	// would leave one out or take one more.
	for _, want := range []string{`sha256sum "${archives[@]}" > SHA256SUMS`, `"${archives[@]}" SHA256SUMS SHA256SUMS.minisig`} {
		if !strings.Contains(wf, want) {
			t.Errorf("release.yml lacks %q", want)
		}
	}
	if n := strings.Count(wf, `read -ra archives <<< "$ARCHIVES"`); n != 2 {
		t.Errorf("release.yml reads ARCHIVES %d times, want 2 (the checksums, the upload)", n)
	}
	return names
}

// A release lists more than a node takes: the other architecture's archive
// and rayctl for other systems (rayctl-darwin-*, rayctl-freebsd-*), all in
// the one signed SHA256SUMS. A node reads its own line by its whole name,
// wherever it stands; the other lines are nothing to it. sumOf has not
// changed since v0.2.0 (nor has the 64 KiB bound on SHA256SUMS), so what
// holds here holds for the rayctl of every release; bootstrap.sh's line is
// test/install/minisig.sh's.
func TestSumsOfOtherArchives(t *testing.T) {
	names := releaseArchives(t)
	for _, want := range []string{Archive("amd64"), Archive("arm64"), "rayctl-darwin-arm64.tar.gz", "rayctl-darwin-amd64.tar.gz", "rayctl-freebsd-amd64.tar.gz"} {
		if !slices.Contains(names, want) {
			t.Errorf("release.yml's ARCHIVES lacks %s: %v", want, names)
		}
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "raycontrol-linux-") && !strings.HasPrefix(n, "rayctl-") {
			t.Errorf("release.yml's ARCHIVES has %s", n)
		}
	}
	k := newKey(t)
	archives := map[string][]byte{}
	for _, n := range names {
		archives[n] = archive(t, map[string]string{"rayctl": n})
	}
	sums := func(order []string, mark string) []byte {
		var b []byte
		for _, n := range order {
			sum := sha256.Sum256(archives[n])
			b = append(b, hex.EncodeToString(sum[:])+" "+mark+n+"\n"...)
		}
		return b
	}
	local := func(sums []byte, arch string, files map[string][]byte) (Release, error) {
		dir := t.TempDir()
		for n, b := range files {
			os.WriteFile(filepath.Join(dir, n), b, 0o644)
		}
		os.WriteFile(filepath.Join(dir, "SHA256SUMS"), sums, 0o644)
		os.WriteFile(filepath.Join(dir, "SHA256SUMS.minisig"), k.sign(sums, "raycontrol v0.26.0", false), 0o644)
		return Local(dir, arch, k.pub)
	}
	reversed := slices.Clone(names)
	slices.Reverse(reversed)
	for name, s := range map[string][]byte{
		"as the workflow writes it": sums(names, " "),
		"rayctl's lines first":      sums(reversed, " "),
		"binary mode":               sums(names, "*"),
	} {
		if len(s) > 1<<16 {
			t.Fatalf("%s: SHA256SUMS of %d bytes, over what rayctl update reads", name, len(s))
		}
		for _, arch := range []string{"amd64", "arm64"} {
			// As a node has them (rayctl update -from DIR): the three files.
			r, err := local(s, arch, map[string][]byte{Archive(arch): archives[Archive(arch)]})
			if err != nil || r.Version != "v0.26.0" || !bytes.Equal(r.Archive, archives[Archive(arch)]) {
				t.Errorf("%s, %s: %v %v", name, arch, r.Version, err)
			}
			for _, n := range names {
				want, err := sumOf(s, n)
				if got := sha256.Sum256(archives[n]); err != nil || want != hex.EncodeToString(got[:]) {
					t.Errorf("%s: the line of %s: %q, %v", name, n, want, err)
				}
			}
		}
	}
	// A node's archive is checked against its own line, not another's: a
	// rayctl archive in its place fails, and so does a release without it.
	s := sums(names, " ")
	if _, err := local(s, "amd64", map[string][]byte{Archive("amd64"): archives["rayctl-darwin-amd64.tar.gz"]}); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("another archive under the node's name: %v", err)
	}
	var clients []string
	for _, n := range names {
		if strings.HasPrefix(n, "rayctl-") {
			clients = append(clients, n)
		}
	}
	if _, err := local(sums(clients, " "), "amd64", map[string][]byte{Archive("amd64"): archives[Archive("amd64")]}); err == nil ||
		!strings.Contains(err.Error(), "SHA256SUMS has no "+Archive("amd64")) {
		t.Errorf("no line for the node: %v", err)
	}
	for _, n := range []string{"rayctl-linux-amd64.tar.gz", "linux-amd64.tar.gz", "raycontrol-linux-amd64.tar.gz.sig", "rayctl-darwin-arm64"} {
		if got, err := sumOf(s, n); err == nil {
			t.Errorf("a line for %s: %s", n, got)
		}
	}

	// And fetched, as rayctl update takes the latest release.
	files := map[string][]byte{"SHA256SUMS": s, "SHA256SUMS.minisig": k.sign(s, "raycontrol v0.26.0", false)}
	for n, b := range archives {
		files[n] = b
	}
	var fetched []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		fetched = append(fetched, name)
		if b, ok := files[name]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	f := &Fetcher{Base: srv.URL}
	for _, arch := range []string{"amd64", "arm64"} {
		r, err := f.Fetch(context.Background(), "latest", arch, k.pub)
		if err != nil || r.Version != "v0.26.0" || !bytes.Equal(r.Archive, archives[Archive(arch)]) {
			t.Fatalf("fetched, %s: %v %v", arch, r.Version, err)
		}
	}
	if slices.ContainsFunc(fetched, func(n string) bool { return strings.HasPrefix(n, "rayctl-") }) {
		t.Errorf("a node fetched rayctl's archives: %v", fetched)
	}
}
