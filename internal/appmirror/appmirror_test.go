package appmirror

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/arngory/raycontrol/internal/store"
)

// testKey signs as minisign does (prehashed, ED).
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

func (k testKey) sign(msg []byte, trusted string) []byte {
	h := blake2b.Sum512(msg)
	sig := ed25519.Sign(k.priv, h[:])
	global := ed25519.Sign(k.priv, append(slices.Clone(sig), trusted...))
	raw := append(append([]byte("ED"), k.id...), sig...)
	return []byte(fmt.Sprintf("untrusted comment: test\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(raw), trusted, base64.StdEncoding.EncodeToString(global)))
}

// fakeGitHub serves the releases API and the assets, as GitHub does.
type fakeGitHub struct {
	srv  *httptest.Server
	mu   sync.Mutex
	rels []ghRelease
	blob map[string][]byte // asset path -> bytes
	hits map[string]int
}

func newGitHub(t *testing.T) *fakeGitHub {
	g := &fakeGitHub{blob: map[string][]byte{}, hits: map[string]int{}}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.hits[r.URL.Path]++
		if r.URL.Path == "/repos/"+Repo+"/releases" {
			_ = json.NewEncoder(w).Encode(g.rels)
			return
		}
		b, ok := g.blob[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

// release publishes a release: its files, SHA256SUMS signed with
// trusted, and the assets; mutate may spoil it before it goes up.
func (g *fakeGitHub) release(k testKey, tag string, files map[string][]byte, trusted string, mutate func(sums []byte, assets map[string][]byte) []byte) {
	names := slices.Sorted(func(yield func(string) bool) {
		for n := range files {
			if !yield(n) {
				return
			}
		}
	})
	var sums strings.Builder
	assets := map[string][]byte{}
	for _, n := range names {
		h := sha256.Sum256(files[n])
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), n)
		assets[n] = files[n]
	}
	sb := []byte(sums.String())
	if mutate != nil {
		sb = mutate(sb, assets)
	}
	if trusted == "" {
		trusted = "niko " + tag
	}
	assets[sumsName] = sb
	assets[sigName] = k.sign(sb, trusted)
	g.mu.Lock()
	defer g.mu.Unlock()
	rel := ghRelease{Tag: tag}
	for n, b := range assets {
		p := "/dl/" + tag + "/" + n
		g.blob[p] = b
		rel.Assets = append(rel.Assets, ghAsset{Name: n, Size: int64(len(b)), URL: g.srv.URL + p})
	}
	g.rels = append(g.rels, rel)
}

// hit counts the requests for an asset.
func (g *fakeGitHub) hit(tag, name string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hits["/dl/"+tag+"/"+name]
}

// unlist takes releases off the listing (deleted, or hidden from it).
func (g *fakeGitHub) unlist(tags ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rels = slices.DeleteFunc(g.rels, func(r ghRelease) bool { return slices.Contains(tags, r.Tag) })
}

// upload adds an asset to a listed release, as its workflow does after
// creating it.
func (g *fakeGitHub) upload(tag, name string, b []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := "/dl/" + tag + "/" + name
	g.blob[p] = b
	for i := range g.rels {
		if g.rels[i].Tag == tag {
			g.rels[i].Assets = append(g.rels[i].Assets, ghAsset{Name: name, Size: int64(len(b)), URL: g.srv.URL + p})
		}
	}
}

func newMirror(t *testing.T, g *fakeGitHub, k testKey) *Mirror {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Mirror{Store: st, Dir: filepath.Join(t.TempDir(), "app"), API: g.srv.URL, HTTP: g.srv.Client(), PubKey: k.pub}
}

func apks(tag string) map[string][]byte {
	return map[string][]byte{
		"niko-" + tag + "-arm64-v8a.apk":   []byte("arm64 " + tag + strings.Repeat("x", 3000)),
		"niko-" + tag + "-armeabi-v7a.apk": []byte("arm " + tag),
	}
}

func tags(rs []Release) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Tag)
	}
	return out
}

func TestSync(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	g := newGitHub(t)
	g.release(k, "v1.37.0", apks("v1.37.0"), "", nil)
	g.release(k, "v1.38.0", apks("v1.38.0"), "", nil)
	g.release(k, "v1.39.0-rc1", apks("v1.39.0-rc1"), "", nil)
	g.release(k, "v1.38.0-rc2", apks("v1.38.0-rc2"), "", nil) // older than the stable
	g.mu.Lock()
	g.rels = append(g.rels, ghRelease{Tag: "v1.40.0", Draft: true}, ghRelease{Tag: "nightly"})
	g.mu.Unlock()
	m := newMirror(t, g, k)

	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	st := m.Status(ctx)
	if got := tags(st.Releases); !slices.Equal(got, []string{"v1.38.0", "v1.39.0-rc1"}) || st.Err != "" || st.Checked.IsZero() {
		t.Fatalf("held %v, err %q", got, st.Err)
	}
	r := st.Releases[0]
	if r.Prerelease || len(r.Files) != 4 || r.Files[0].Name != sumsName || r.Files[1].Name != sigName {
		t.Errorf("release %+v", r)
	}
	for _, f := range r.Files {
		b, err := os.ReadFile(filepath.Join(m.Dir, App, r.Tag, f.Name))
		h := sha256.Sum256(b)
		if err != nil || int64(len(b)) != f.Size || hex.EncodeToString(h[:]) != f.SHA256 {
			t.Errorf("file %s on disk: %v", f.Name, err)
		}
	}
	// Off: no hint. On: the two, the stable first.
	if h := m.Hint(ctx); h != nil {
		t.Errorf("hint while off: %+v", h)
	}
	if err := m.Store.SetSetting(ctx, settingEnabled, []byte("on")); err != nil {
		t.Fatal(err)
	}
	if h := m.Hint(ctx); h == nil || len(h.Niko) != 2 || h.Niko[0] != (HintRelease{"v1.38.0", false}) || h.Niko[1] != (HintRelease{"v1.39.0-rc1", true}) {
		t.Errorf("hint %+v", h)
	}

	// Nothing new: nothing downloaded again.
	g.mu.Lock()
	before := g.hits["/dl/v1.38.0/"+sumsName]
	g.mu.Unlock()
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	again := g.hits["/dl/v1.38.0/"+sumsName]
	g.mu.Unlock()
	if again != before {
		t.Errorf("a held release fetched again")
	}

	// A stable release newer than the pre-release: the pre-release goes,
	// its directory too; another rayd finds the new set on the disk.
	g.release(k, "v1.39.0", apks("v1.39.0"), "", nil)
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := tags(m.Status(ctx).Releases); !slices.Equal(got, []string{"v1.39.0"}) {
		t.Fatalf("held %v", got)
	}
	entries, _ := os.ReadDir(filepath.Join(m.Dir, App))
	if len(entries) != 1 || entries[0].Name() != "v1.39.0" {
		t.Errorf("on disk: %v", entries)
	}
	m2 := &Mirror{Store: m.Store, Dir: m.Dir, PubKey: k.pub}
	m2.load()
	if got := tags(m2.Status(ctx).Releases); !slices.Equal(got, []string{"v1.39.0"}) {
		t.Errorf("loaded %v", got)
	}

	// Off: the files go.
	m.clear()
	if _, err := os.Stat(filepath.Join(m.Dir, App)); !errors.Is(err, os.ErrNotExist) || len(m.Status(ctx).Releases) != 0 {
		t.Errorf("after clear: %v", err)
	}
}

// A release that does not verify is not taken, and the one it was to
// replace stays.
func TestSyncRefuses(t *testing.T) {
	ctx := context.Background()
	k, other := newKey(t), newKey(t)
	cases := []struct {
		name string
		pub  func(g *fakeGitHub)
		want string
	}{
		{"other key", func(g *fakeGitHub) { g.release(other, "v2.0.0", apks("v2.0.0"), "", nil) }, "another key"},
		{"trusted comment of another tag", func(g *fakeGitHub) {
			g.release(k, "v2.0.0", apks("v2.0.0"), "niko v1.0.0", nil)
		}, "trusted comment"},
		{"a file changed after signing", func(g *fakeGitHub) {
			g.release(k, "v2.0.0", apks("v2.0.0"), "", func(sums []byte, assets map[string][]byte) []byte {
				assets["niko-v2.0.0-armeabi-v7a.apk"] = []byte("arm v2.0.0 changed")
				return sums
			})
		}, "SHA-256"},
		{"a name that walks out", func(g *fakeGitHub) {
			g.release(k, "v2.0.0", apks("v2.0.0"), "", func(sums []byte, assets map[string][]byte) []byte {
				return append(sums, []byte(strings.Repeat("ab", 32)+"  ../../rayd.db\n")...)
			})
		}, "name"},
		{"listed but not in the release", func(g *fakeGitHub) {
			g.release(k, "v2.0.0", apks("v2.0.0"), "", func(sums []byte, assets map[string][]byte) []byte {
				return append(sums, []byte(strings.Repeat("ab", 32)+"  niko-x86.apk\n")...)
			})
		}, "not in the release"},
		{"too large", func(g *fakeGitHub) {
			g.release(k, "v2.0.0", apks("v2.0.0"), "", nil)
			g.mu.Lock()
			for i := range g.rels {
				for j := range g.rels[i].Assets {
					if strings.HasSuffix(g.rels[i].Assets[j].Name, "v8a.apk") && g.rels[i].Tag == "v2.0.0" {
						g.rels[i].Assets[j].Size = MaxFile + 1
					}
				}
			}
			g.mu.Unlock()
		}, "at most"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGitHub(t)
			g.release(k, "v1.0.0", apks("v1.0.0"), "", nil)
			m := newMirror(t, g, k)
			if err := m.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			c.pub(g)
			err := m.Sync(ctx)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			st := m.Status(ctx)
			if got := tags(st.Releases); !slices.Equal(got, []string{"v1.0.0"}) || !strings.Contains(st.Err, c.want) {
				t.Errorf("held %v, status err %q", got, st.Err)
			}
			entries, _ := os.ReadDir(filepath.Join(m.Dir, App))
			if len(entries) != 1 || entries[0].Name() != "v1.0.0" {
				t.Errorf("on disk: %v", entries)
			}
		})
	}
}

// What a check keeps (app-update-v1 §3): a newer release only once it
// verifies, and then the newest that does; never an older one in place of
// what is held; a tag that did not verify is not fetched again for a while,
// one whose assets are not all up yet is.
func TestSyncSelection(t *testing.T) {
	ctx := context.Background()
	k, other := newKey(t), newKey(t)
	g := newGitHub(t)
	g.release(k, "v1.38.0", apks("v1.38.0"), "", nil)
	g.release(k, "v1.39.0-rc1", apks("v1.39.0-rc1"), "", nil)
	m := newMirror(t, g, k)
	check := func(wantErr string, want ...string) {
		t.Helper()
		err := m.Sync(ctx)
		if wantErr == "" && err != nil || wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)) {
			t.Fatalf("err %v, want %q", err, wantErr)
		}
		if got := tags(m.Status(ctx).Releases); !slices.Equal(got, want) {
			t.Fatalf("held %v, want %v", got, want)
		}
		entries, _ := os.ReadDir(filepath.Join(m.Dir, App))
		var dirs []string
		for _, e := range entries {
			dirs = append(dirs, e.Name())
		}
		if !slices.Equal(dirs, want) {
			t.Fatalf("on disk %v, want %v", dirs, want)
		}
	}
	check("", "v1.38.0", "v1.39.0-rc1")

	// A newer stable release that does not verify: both stay, and it is
	// not fetched again.
	g.release(other, "v1.39.0", apks("v1.39.0"), "", nil)
	check("v1.39.0: does not verify", "v1.38.0", "v1.39.0-rc1")
	sigs := g.hit("v1.39.0", sigName)
	check("", "v1.38.0", "v1.39.0-rc1")
	if g.hit("v1.39.0", sigName) != sigs {
		t.Error("a release that did not verify fetched again")
	}

	// A tag far ahead that does not verify does not hold the mirror: the
	// newest that does is taken (and the pre-release older than it goes).
	g.release(other, "v99.0.0", apks("v99.0.0"), "", nil)
	g.release(k, "v1.40.0", apks("v1.40.0"), "", nil)
	check("v99.0.0", "v1.40.0")

	// GitHub lists only older releases (the newest deleted or hidden), or
	// none: what is held stays.
	g.unlist("v1.40.0", "v99.0.0")
	check("", "v1.40.0")
	g.unlist("v1.38.0", "v1.39.0", "v1.39.0-rc1")
	check("", "v1.40.0")

	// A release whose assets are still going up: taken on the next check.
	g.release(k, "v1.41.0", apks("v1.41.0"), "", func(sums []byte, assets map[string][]byte) []byte {
		delete(assets, "niko-v1.41.0-armeabi-v7a.apk")
		return sums
	})
	check("not in the release", "v1.40.0")
	g.upload("v1.41.0", "niko-v1.41.0-armeabi-v7a.apk", apks("v1.41.0")["niko-v1.41.0-armeabi-v7a.apk"])
	check("", "v1.41.0")

	// At most maxTries newer releases a check: a host that fails them all
	// costs a bounded check, and the older one waits for the next.
	for _, tag := range []string{"v2.0.0", "v2.1.0", "v2.2.0"} {
		g.release(k, tag, apks(tag), "", nil)
		g.mu.Lock()
		delete(g.blob, "/dl/"+tag+"/"+sumsName)
		g.mu.Unlock()
	}
	g.release(k, "v1.42.0", apks("v1.42.0"), "", nil)
	check("404", "v1.41.0")
	if n := g.hit("v1.42.0", sumsName); n != 0 {
		t.Errorf("a fourth release fetched in one check: %d", n)
	}
}

// A release a previous rayd left is taken only whole and as signed: a file
// a crash tore, a manifest that is not SHA256SUMS's, and it goes; the other
// release stays.
func TestLoad(t *testing.T) {
	ctx := context.Background()
	apk := "niko-v1.38.0-armeabi-v7a.apk"
	manifest := func(t *testing.T, dir string, edit func(r *Release)) {
		t.Helper()
		p := filepath.Join(dir, manifestName)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var r Release
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		edit(&r)
		if b, err = json.Marshal(r); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name  string
		spoil func(t *testing.T, dir string)
	}{
		{"nothing", func(*testing.T, string) {}},
		{"a torn file", func(t *testing.T, dir string) {
			if err := os.Truncate(filepath.Join(dir, apk), 3); err != nil {
				t.Fatal(err)
			}
		}},
		{"a file the manifest vouches for, not SHA256SUMS", func(t *testing.T, dir string) {
			b := []byte("arm v1.38.0 changed")
			if err := os.WriteFile(filepath.Join(dir, apk), b, 0o600); err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(b)
			manifest(t, dir, func(r *Release) {
				for i := range r.Files {
					if r.Files[i].Name == apk {
						r.Files[i].Size, r.Files[i].SHA256 = int64(len(b)), hex.EncodeToString(h[:])
					}
				}
			})
		}},
		{"a file more in the manifest", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "x.apk"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256([]byte("x"))
			manifest(t, dir, func(r *Release) {
				r.Files = append(r.Files, File{Name: "x.apk", Size: 1, SHA256: hex.EncodeToString(h[:])})
			})
		}},
		{"a stable release called a pre-release", func(t *testing.T, dir string) {
			manifest(t, dir, func(r *Release) { r.Prerelease = true })
		}},
		{"the signature gone", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, sigName)); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := newKey(t)
			g := newGitHub(t)
			g.release(k, "v1.38.0", apks("v1.38.0"), "", nil)
			g.release(k, "v1.39.0-rc1", apks("v1.39.0-rc1"), "", nil)
			m := newMirror(t, g, k)
			if err := m.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(m.Dir, App, "v1.38.0")
			c.spoil(t, dir)
			m2 := &Mirror{Store: m.Store, Dir: m.Dir, PubKey: k.pub}
			m2.load()
			want := []string{"v1.39.0-rc1"}
			if c.name == "nothing" {
				want = []string{"v1.38.0", "v1.39.0-rc1"}
			}
			if got := tags(m2.Status(ctx).Releases); !slices.Equal(got, want) {
				t.Fatalf("loaded %v, want %v", got, want)
			}
			if _, err := os.Stat(dir); (err == nil) != (len(want) == 2) {
				t.Errorf("v1.38.0 on disk: %v", err)
			}
		})
	}
}

func TestSemver(t *testing.T) {
	order := []string{"v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-alpha.beta", "v1.0.0-beta", "v1.0.0-beta.2",
		"v1.0.0-beta.11", "v1.0.0-rc.1", "v1.0.0", "v1.0.1", "v1.2.0", "v1.10.0", "v2.0.0-rc1", "v2.0.0"}
	for i := range order {
		if !semverValid(order[i]) {
			t.Fatalf("%s not valid", order[i])
		}
		for j := range order {
			want := cmpInt(i, j)
			if got := semverCompare(order[i], order[j]); got != want {
				t.Errorf("compare(%s, %s) = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
	if semverCompare("v1.0.0+b1", "v1.0.0+b2") != 0 {
		t.Error("build metadata ordered")
	}
	for _, bad := range []string{"1.0.0", "v1.0", "v01.0.0", "v1.0.0-", "v1.0.0/../x", "nightly", "v1.0.0-a..b"} {
		if semverValid(bad) || validTag(bad) {
			t.Errorf("%q valid", bad)
		}
	}
}

func TestParseSums(t *testing.T) {
	h := strings.Repeat("0a", 32)
	ok, err := parseSums([]byte(h + "  a.apk\n" + strings.ToUpper(h) + " *b.apk\n\n"))
	if err != nil || len(ok) != 2 || ok[0].Name != "a.apk" || ok[1].Name != "b.apk" || ok[1].SHA256 != h {
		t.Fatalf("%+v %v", ok, err)
	}
	for _, bad := range []string{"", h + "  a.apk\n" + h + "  a.apk\n", h + "  ../a\n", h + "  a/b\n", h + "  SHA256SUMS\n",
		h + "  release.json\n", "abc  a.apk\n", h + "\n", h + "  .\n"} {
		if _, err := parseSums([]byte(bad)); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

// Served: to authenticated devices only, while on, one range, the ETag for
// If-Range, a device's one download at a time.
func TestHandler(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	g := newGitHub(t)
	g.release(k, "v1.38.0", apks("v1.38.0"), "", nil)
	m := newMirror(t, g, k)
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	auth := func(r *http.Request) (string, error) {
		if d := r.Header.Get("X-Dev"); d != "" {
			return d, nil
		}
		return "", errors.New("auth")
	}
	srv := httptest.NewServer(m.Handler(auth))
	defer srv.Close()
	name := "niko-v1.38.0-arm64-v8a.apk"
	body := apks("v1.38.0")[name]
	sum := sha256.Sum256(body)
	get := func(method, path, dev string, hdr map[string]string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		if dev != "" {
			req.Header.Set("X-Dev", dev)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	path := Path + "niko/v1.38.0/" + name
	if resp, _ := get("GET", path, "d1", nil); resp.StatusCode != 404 {
		t.Errorf("while off: %d", resp.StatusCode)
	}
	if err := m.Store.SetSetting(ctx, settingEnabled, []byte("on")); err != nil {
		t.Fatal(err)
	}
	if resp, _ := get("GET", path, "", nil); resp.StatusCode != 404 {
		t.Errorf("without auth: %d", resp.StatusCode)
	}
	resp, b := get("GET", path, "d1", nil)
	if resp.StatusCode != 200 || string(b) != string(body) || resp.Header.Get("ETag") != `"`+hex.EncodeToString(sum[:])+`"` ||
		resp.ContentLength != int64(len(body)) || resp.Header.Get("Content-Type") != "application/vnd.android.package-archive" {
		t.Errorf("GET: %d %q %d", resp.StatusCode, resp.Header.Get("ETag"), resp.ContentLength)
	}
	resp, b = get("GET", path, "d1", map[string]string{"Range": "bytes=100-"})
	if resp.StatusCode != 206 || string(b) != string(body[100:]) || resp.Header.Get("Content-Range") != fmt.Sprintf("bytes 100-%d/%d", len(body)-1, len(body)) {
		t.Errorf("range: %d %q", resp.StatusCode, resp.Header.Get("Content-Range"))
	}
	etag := resp.Header.Get("ETag")
	if resp, b = get("GET", path, "d1", map[string]string{"Range": "bytes=10-19", "If-Range": etag}); resp.StatusCode != 206 || string(b) != string(body[10:20]) {
		t.Errorf("If-Range, same file: %d", resp.StatusCode)
	}
	if resp, b = get("GET", path, "d1", map[string]string{"Range": "bytes=10-19", "If-Range": `"other"`}); resp.StatusCode != 200 || len(b) != len(body) {
		t.Errorf("If-Range, another file: %d", resp.StatusCode)
	}
	if resp, _ = get("GET", path, "d1", map[string]string{"Range": fmt.Sprintf("bytes=%d-", len(body)+5)}); resp.StatusCode != 416 ||
		resp.Header.Get("Content-Range") != fmt.Sprintf("bytes */%d", len(body)) {
		t.Errorf("past the end: %d %q", resp.StatusCode, resp.Header.Get("Content-Range"))
	}
	if resp, b = get("HEAD", path, "d1", nil); resp.StatusCode != 200 || len(b) != 0 || resp.ContentLength != int64(len(body)) {
		t.Errorf("HEAD: %d %d", resp.StatusCode, resp.ContentLength)
	}
	// Several ranges: the whole file (one range a response, §2).
	if resp, b = get("GET", path, "d1", map[string]string{"Range": "bytes=0-1,5-6"}); resp.StatusCode != 200 || string(b) != string(body) {
		t.Errorf("two ranges: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	for _, p := range []string{Path + "niko/v1.38.0/" + sumsName, Path + "niko/v1.38.0/" + sigName} {
		if resp, _ := get("GET", p, "d1", nil); resp.StatusCode != 200 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	for _, p := range []string{Path + "niko/v1.38.0/" + manifestName, Path + "niko/v1.37.0/" + name, Path + "other/v1.38.0/" + name,
		Path + "niko/v1.38.0/../v1.38.0/" + name, Path + "niko/v1.38.0", Path + "niko/v1.38.0/" + name + "/x"} {
		if resp, _ := get("GET", p, "d1", nil); resp.StatusCode != 404 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := get("POST", path, "d1", nil); resp.StatusCode != 404 {
		t.Errorf("POST: %d", resp.StatusCode)
	}
	// A device's second download, and the node's seventeenth: 429.
	if !m.begin("d1") {
		t.Fatal("begin")
	}
	if resp, _ := get("GET", path, "d1", nil); resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Errorf("second of a device: %d", resp.StatusCode)
	}
	// HEAD takes no place.
	if resp, _ := get("HEAD", path, "d1", nil); resp.StatusCode != 200 {
		t.Errorf("HEAD during a download: %d", resp.StatusCode)
	}
	if resp, _ := get("GET", path, "d2", nil); resp.StatusCode != 200 {
		t.Errorf("another device: %d", resp.StatusCode)
	}
	for i := 1; i < PerNode; i++ {
		m.begin(fmt.Sprintf("x%d", i))
	}
	if resp, _ := get("GET", path, "d2", nil); resp.StatusCode != 429 {
		t.Errorf("over the node's: %d", resp.StatusCode)
	}
	if resp, _ := get("HEAD", path, "d2", nil); resp.StatusCode != 200 {
		t.Errorf("HEAD with the node's places taken: %d", resp.StatusCode)
	}
	m.end("d1")
	if resp, _ := get("GET", path, "d2", nil); resp.StatusCode != 200 {
		t.Errorf("after one ended: %d", resp.StatusCode)
	}
}

// No download lasts past MaxDownload: the client resumes it with a range.
func TestStallWriterUntil(t *testing.T) {
	rec := httptest.NewRecorder()
	s := &stallWriter{ResponseWriter: rec, rc: http.NewResponseController(rec), stall: Stall, until: time.Now().Add(time.Hour)}
	if n, err := s.Write([]byte("ab")); n != 2 || err != nil {
		t.Fatalf("before: %d %v", n, err)
	}
	s.until = time.Now().Add(-time.Second)
	if _, err := s.Write([]byte("c")); !errors.Is(err, errTooLong) || rec.Body.String() != "ab" {
		t.Fatalf("after: %v, body %q", err, rec.Body.String())
	}
}

func TestSetEnabled(t *testing.T) {
	ctx := context.Background()
	g := newGitHub(t)
	m := newMirror(t, g, newKey(t))
	if Enabled(ctx, m.Store) {
		t.Fatal("on by default")
	}
	free, err := freeBytes(m.Dir)
	if err != nil {
		t.Fatal(err)
	}
	err = m.SetEnabled(ctx, true)
	if free >= MinFree && (err != nil || !Enabled(ctx, m.Store)) || free < MinFree && err == nil {
		t.Fatalf("on with %d MiB free: %v", free>>20, err)
	}
	if err := m.SetEnabled(ctx, false); err != nil || Enabled(ctx, m.Store) {
		t.Fatalf("off: %v", err)
	}
}

// A plain-HTTP source (the client's interop, RAYCONTROL_UNSAFE_APP_MIRROR_API)
// only with AllowHTTP; GitHub's assets are HTTPS.
func TestAllowHTTP(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	g := newGitHub(t)
	plain := httptest.NewServer(g.srv.Config.Handler)
	t.Cleanup(plain.Close)
	g.release(k, "v1.0.0", apks("v1.0.0"), "", nil)
	g.mu.Lock()
	for i := range g.rels {
		for j := range g.rels[i].Assets {
			g.rels[i].Assets[j].URL = strings.Replace(g.rels[i].Assets[j].URL, g.srv.URL, plain.URL, 1)
		}
	}
	g.mu.Unlock()
	m := newMirror(t, g, k)
	m.API, m.HTTP = plain.URL, plain.Client()
	if err := m.Sync(ctx); err == nil || !strings.Contains(err.Error(), "asset URL") {
		t.Fatalf("plain HTTP taken: %v", err)
	}
	m.AllowHTTP = true
	if err := m.Sync(ctx); err != nil || len(m.Status(ctx).Releases) != 1 {
		t.Fatalf("with AllowHTTP: %v", err)
	}
}
