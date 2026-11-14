package release

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveReleases serves the signed SHA256SUMS of each version (signed as
// itself unless signedAs says otherwise) under its tag, and counts the
// requests.
func serveReleases(t *testing.T, k testKey, versions []string, signedAs map[string]string) (*Fetcher, *int) {
	t.Helper()
	sums := []byte("0000  " + Archive("amd64") + "\n")
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
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
	return &Fetcher{Base: srv.URL}, &hits
}

// NewestPatch climbs the patch numbers of the installed minor version: it
// takes the highest, steps over one missing number but not two, never
// leaves the minor version, ignores tags that are not vX.Y.Z, and stops
// at MaxPatchProbes.
func TestNewestPatch(t *testing.T) {
	ctx := context.Background()
	k := newKey(t)
	for _, c := range []struct {
		name      string
		installed string
		published []string
		want      string
		requests  int
	}{
		{"two patches and a minor", "v0.26.0", []string{"v0.26.1", "v0.26.2", "v0.27.0"}, "v0.26.2", 2 + 2 + 1 + 1},
		{"a gap of one", "v0.26.0", []string{"v0.26.2", "v0.27.0"}, "v0.26.2", 1 + 2 + 1 + 1},
		{"a gap of two", "v0.26.0", []string{"v0.26.3", "v0.27.0"}, "", 2},
		{"up to date", "v0.26.2", []string{"v0.26.1", "v0.26.2", "v0.27.0"}, "", 2},
		{"a pre-release", "v0.26.0", []string{"v0.26.1-rc1", "v0.27.0"}, "", 2},
		{"bounded", "v0.26.0", []string{"v0.26.1", "v0.26.2", "v0.26.3", "v0.26.4", "v0.26.5", "v0.26.6", "v0.26.7", "v0.26.8", "v0.26.9"},
			"v0.26.8", 2 * MaxPatchProbes},
	} {
		f, hits := serveReleases(t, k, c.published, nil)
		got, err := f.NewestPatch(ctx, k.pub, c.installed)
		if err != nil || got != c.want {
			t.Errorf("%s: %q %v, want %q", c.name, got, err, c.want)
		}
		if *hits != c.requests {
			t.Errorf("%s: %d requests, want %d", c.name, *hits, c.requests)
		}
	}

	// A release signed as another version, or by another key, is no
	// patch release: the search ends there with what it found.
	f, _ := serveReleases(t, k, []string{"v0.26.1", "v0.26.2"}, map[string]string{"v0.26.2": "v0.27.0"})
	if got, err := f.NewestPatch(ctx, k.pub, "v0.26.0"); got != "v0.26.1" || err == nil || !strings.Contains(err.Error(), "signed as v0.27.0") {
		t.Errorf("signed as another version: %q %v", got, err)
	}
	f, _ = serveReleases(t, k, []string{"v0.26.1"}, nil)
	if got, err := f.NewestPatch(ctx, newKey(t).pub, "v0.26.0"); got != "" || err == nil {
		t.Errorf("another key: %q %v", got, err)
	}
	if _, err := f.NewestPatch(ctx, k.pub, "dev"); err == nil {
		t.Error("a dev build searched")
	}
}
