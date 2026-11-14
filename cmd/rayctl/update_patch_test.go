package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// rayctl update -check on a node of v0.26.0 with v0.26.1, v0.26.2 and
// v0.27.0 published, v0.27.0 the latest: it names v0.27.0 and the newest
// patch release of v0.26, signed as such; a v0.26 that has none gets the
// one line it always had.
func TestStageCheckPatch(t *testing.T) {
	k := newSigner(t)
	saved := releaseKey
	releaseKey = k.pub
	t.Cleanup(func() { releaseKey = saved })
	t.Setenv(handoffEnv, "")
	t.Setenv("RAYCONTROL_MIRRORS", "")
	out := filepath.Join(t.TempDir(), "handed")
	published := map[string]map[string][]byte{}
	for _, v := range []string{"v0.26.1", "v0.26.2", "v0.27.0"} {
		published[v] = signedRelease(t, k, v, out)
	}
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		dir, name := filepath.Split(r.URL.Path)
		v := filepath.Base(dir)
		if strings.HasSuffix(dir, "/latest/download/") {
			v = "v0.27.0"
		}
		if b, ok := published[v][name]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	releaseBase = srv.URL
	t.Cleanup(func() { releaseBase = "" })
	check := func(installed string) string {
		t.Helper()
		text, err := captureStdout(t, func() error {
			s, err := (&cli{}).stageRelease(context.Background(), updateOpts{want: "latest", check: true}, t.TempDir(), installed, nodeBinaries,
				func(string) error { return nil })
			if err == nil && !s.done {
				t.Errorf("%s: -check went on: %+v", installed, s)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return text
	}
	want := "installed v0.26.0, release v0.27.0 available: rayctl update\n" +
		"release v0.26.2, the newest patch release of v0.26.0, available: rayctl update -version v0.26.2\n"
	if text := check("v0.26.0"); text != want {
		t.Errorf("v0.26.0:\n%s\nwant\n%s", text, want)
	}
	for _, p := range hits {
		if strings.HasSuffix(p, ".tar.gz") {
			t.Errorf("-check downloaded %s", p)
		}
	}
	if text := check("v0.26.2"); text != "installed v0.26.2, release v0.27.0 available: rayctl update\n" {
		t.Errorf("v0.26.2:\n%s", text)
	}
}
