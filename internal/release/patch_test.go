package release

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// serveReleases serves the signed SHA256SUMS of each version (signed as
// itself unless signedAs says otherwise) under its tag, and keeps the
// paths asked for.
func serveReleases(t *testing.T, k testKey, versions []string, signedAs map[string]string) (*Fetcher, *[]string) {
	t.Helper()
	sums := []byte("0000  " + Archive("amd64") + "\n")
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		for _, v := range versions {
			as := v
			if s, ok := signedAs[v]; ok {
				as = s
			}
			switch r.URL.Path {
			case "/" + Repo + "/releases/download/" + v + "/SHA256SUMS":
				w.Write(sums)
				return
			case "/" + Repo + "/releases/download/" + v + "/SHA256SUMS.minisig":
				w.Write(k.sign(sums, "raycontrol "+as, false))
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return &Fetcher{Base: srv.URL}, &paths
}

// NewestPatch climbs the patch numbers of the installed minor version: it
// takes the highest, steps over one missing number but not two, never
// leaves the minor version, asks for no tag but vX.Y.Z, and stops at
// MaxPatchProbes. Whatever GitHub's latest is: newer, older (a backport
// marked latest) or the installed one itself, where it asks for the next
// number only.
func TestNewestPatch(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	for _, c := range []struct {
		name      string
		installed string
		latest    string
		published []string
		want      string
		requests  int
	}{
		{"two patches and a minor", "v0.26.0", "v0.27.0", []string{"v0.26.1", "v0.26.2", "v0.27.0"}, "v0.26.2", 2 + 2 + 1 + 1},
		{"a gap of one", "v0.26.0", "v0.27.0", []string{"v0.26.2", "v0.27.0"}, "v0.26.2", 1 + 2 + 1 + 1},
		{"a gap of two", "v0.26.0", "v0.27.0", []string{"v0.26.3", "v0.27.0"}, "", 2},
		{"up to date", "v0.26.2", "v0.27.0", []string{"v0.26.1", "v0.26.2", "v0.27.0"}, "", 2},
		// A pre-release of the next patch is published: its tag is never
		// asked for, the release after it is found.
		{"beside a pre-release", "v0.26.0", "v0.27.0", []string{"v0.26.1-rc1", "v0.26.1", "v0.27.0"}, "v0.26.1", 2 + 1 + 1},
		{"bounded", "v0.26.0", "v0.26.9", []string{"v0.26.1", "v0.26.2", "v0.26.3", "v0.26.4", "v0.26.5", "v0.26.6", "v0.26.7", "v0.26.8", "v0.26.9"},
			"v0.26.8", 2 * MaxPatchProbes},
		// v0.25.5 published after v0.26.1 and marked latest: a node of
		// v0.26.0 still finds v0.26.1.
		{"latest a backport", "v0.26.0", "v0.25.5", []string{"v0.25.5", "v0.26.1"}, "v0.26.1", 2 + 1 + 1},
		{"latest a backport, nothing newer", "v0.26.1", "v0.25.5", []string{"v0.25.5", "v0.26.1"}, "", 1 + 1},
		// Latest is this version: the next number only, one request.
		{"latest is installed", "v0.26.1", "v0.26.1", []string{"v0.26.1"}, "", 1},
		{"latest is installed, a patch not marked", "v0.26.1", "v0.26.1", []string{"v0.26.1", "v0.26.2"}, "v0.26.2", 2 + 1},
		{"latest not known", "v0.26.0", "", []string{"v0.26.1"}, "v0.26.1", 2 + 1 + 1},
	} {
		f, paths := serveReleases(t, k, c.published, nil)
		got, err := f.NewestPatch(ctx, k.pub, c.installed, c.latest)
		if err != nil || got != c.want {
			t.Errorf("%s: %q %v, want %q", c.name, got, err, c.want)
		}
		if len(*paths) != c.requests {
			t.Errorf("%s: %d requests, want %d: %q", c.name, len(*paths), c.requests, *paths)
		}
		if slices.ContainsFunc(*paths, func(p string) bool { return strings.Contains(p, "-rc") || !strings.Contains(p, "/download/v0.26.") }) {
			t.Errorf("%s: asked for %q", c.name, *paths)
		}
	}

	// A release signed as another version, or by another key, is no
	// patch release: the search ends there with what it found. A
	// pre-release's signature uploaded under the final tag is refused.
	f, _ := serveReleases(t, k, []string{"v0.26.1", "v0.26.2"}, map[string]string{"v0.26.2": "v0.27.0"})
	if got, err := f.NewestPatch(ctx, k.pub, "v0.26.0", "v0.27.0"); got != "v0.26.1" || err == nil || !strings.Contains(err.Error(), "signed as v0.27.0") {
		t.Errorf("signed as another version: %q %v", got, err)
	}
	f, _ = serveReleases(t, k, []string{"v0.26.1"}, map[string]string{"v0.26.1": "v0.26.1-rc1"})
	if got, err := f.NewestPatch(ctx, k.pub, "v0.26.0", "v0.27.0"); got != "" || err == nil || !strings.Contains(err.Error(), "not a raycontrol release") {
		t.Errorf("a pre-release's signature: %q %v", got, err)
	}
	f, _ = serveReleases(t, k, []string{"v0.26.1"}, nil)
	if got, err := f.NewestPatch(ctx, newKey(t).pub, "v0.26.0", "v0.27.0"); got != "" || err == nil {
		t.Errorf("another key: %q %v", got, err)
	}
	if _, err := f.NewestPatch(ctx, k.pub, "dev", "v0.27.0"); err == nil {
		t.Error("a dev build searched")
	}
}
