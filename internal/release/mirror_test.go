package release

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// releaseSet serves the signed SHA256SUMS of versions, latest under
// /releases/latest/, whatever the path's prefix (a mirror's path holds
// GitHub's URL), and counts the requests.
type releaseSet struct {
	k        testKey
	versions []string
	latest   string
	status   int // when not 0, every request gets it

	mu   sync.Mutex
	hits int
}

func (s *releaseSet) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func (s *releaseSet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits++
	s.mu.Unlock()
	if s.status != 0 {
		http.Error(w, "blocked", s.status)
		return
	}
	sums := []byte("0000  " + Archive("amd64") + "\n")
	for _, v := range append([]string{"latest"}, s.versions...) {
		as := v
		if v == "latest" {
			if s.latest == "" {
				continue
			}
			as = s.latest
		}
		dir := "/" + Repo + "/releases/download/" + v + "/"
		if v == "latest" {
			dir = "/" + Repo + "/releases/latest/download/"
		}
		switch {
		case strings.HasSuffix(r.URL.Path, dir+"SHA256SUMS"):
			_, _ = w.Write(sums)
			return
		case strings.HasSuffix(r.URL.Path, dir+"SHA256SUMS.minisig"):
			_, _ = w.Write(s.k.sign(sums, "raycontrol "+as, false))
			return
		}
	}
	http.NotFound(w, r)
}

// withMirror is a fetcher of GitHub gh behind one mirror, and the log.
func withMirror(t *testing.T, gh, mirror *releaseSet, ghDown bool) (*Fetcher, *[]string) {
	t.Helper()
	g := httptest.NewServer(gh)
	t.Cleanup(g.Close)
	m := httptest.NewServer(mirror)
	t.Cleanup(m.Close)
	if ghDown {
		g.Close() // refuses connections
	}
	var logged []string
	var mu sync.Mutex
	return &Fetcher{Base: g.URL, Mirrors: []string{m.URL + "/"}, Log: func(format string, a ...any) {
		mu.Lock()
		logged = append(logged, fmt.Sprintf(format, a...))
		mu.Unlock()
	}}, &logged
}

// TestGetMirrors: a 404 from GitHub is "no such file" at once, no mirror
// asked; GitHub down, a 5xx, a 429 or a block page's 403 go to the
// mirrors, said so.
func TestGetMirrors(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	for _, c := range []struct {
		name     string
		status   int
		down     bool
		mirrored bool
		log      string
	}{
		{"404", 0, false, false, ""},
		{"down", 0, true, true, "did not answer, trying"},
		{"502", http.StatusBadGateway, false, true, "answered 502 Bad Gateway, trying"},
		{"429", http.StatusTooManyRequests, false, true, "answered 429 Too Many Requests"},
		{"403 block page", http.StatusForbidden, false, true, "answered 403 Forbidden"},
		{"451 block page", http.StatusUnavailableForLegalReasons, false, true, "answered 451"},
	} {
		gh := &releaseSet{k: k, status: c.status}
		mirror := &releaseSet{k: k, versions: []string{"v0.26.1"}}
		f, logged := withMirror(t, gh, mirror, c.down)
		_, err := f.Get(ctx, "v0.26.1", "SHA256SUMS", 1<<16)
		if c.mirrored != (err == nil) || c.mirrored != (mirror.count() == 1) {
			t.Errorf("%s: %v, mirror asked %d times", c.name, err, mirror.count())
		}
		if !c.mirrored && !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v, want not found", c.name, err)
		}
		if c.log == "" && len(*logged) != 0 || c.log != "" && (len(*logged) != 1 || !strings.Contains((*logged)[0], c.log)) {
			t.Errorf("%s: logged %q", c.name, *logged)
		}
	}
	// A mirror that has no such file either: not found.
	f, _ := withMirror(t, &releaseSet{k: k, status: http.StatusBadGateway}, &releaseSet{k: k}, false)
	if _, err := f.Get(ctx, "v0.26.9", "SHA256SUMS", 1<<16); !errors.Is(err, ErrNotFound) {
		t.Errorf("GitHub 502, the mirror 404: %v", err)
	}
}

// TestCheckRequests: the requests of one check (Latest, then NewestPatch
// as rayd and rayctl update -check ask for it) with a mirror set, from a
// node running v0.26.0. GitHub answers the missing patch numbers: the
// mirror is asked only when GitHub does not answer.
func TestCheckRequests(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	for _, c := range []struct {
		name            string
		published       []string
		latest          string
		down            bool
		want            string
		github, mirrors int
	}{
		{"no new release", []string{"v0.26.0"}, "v0.26.0", false, "", 2 + 1, 0},
		{"a backport marked latest", []string{"v0.25.5", "v0.26.1"}, "v0.25.5", false, "v0.26.1", 2 + 2 + 1 + 1, 0},
		{"new minor, no patches", []string{"v0.27.0"}, "v0.27.0", false, "", 2 + 1 + 1, 0},
		{"new minor, two patches", []string{"v0.26.1", "v0.26.2", "v0.27.0"}, "v0.27.0", false, "v0.26.2", 2 + 2 + 2 + 1 + 1, 0},
		{"GitHub unreachable", []string{"v0.27.0"}, "v0.27.0", true, "", 0, 2 + 1 + 1},
	} {
		gh := &releaseSet{k: k, versions: c.published, latest: c.latest}
		mirror := &releaseSet{k: k, versions: c.published, latest: c.latest}
		f, _ := withMirror(t, gh, mirror, c.down)
		latest, err := f.Latest(ctx, k.pub)
		if err != nil || latest != c.latest {
			t.Fatalf("%s: latest %q %v", c.name, latest, err)
		}
		got, err := f.NewestPatch(ctx, k.pub, "v0.26.0", latest)
		if err != nil || got != c.want {
			t.Errorf("%s: newest patch %q %v, want %q", c.name, got, err, c.want)
		}
		if gh.count() != c.github || mirror.count() != c.mirrors {
			t.Errorf("%s: %d requests to GitHub, %d to the mirror; want %d, %d", c.name, gh.count(), mirror.count(), c.github, c.mirrors)
		}
	}
}
