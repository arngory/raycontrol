package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/roots"
	"github.com/arngory/raycontrol/internal/roots/rootstest"
)

// TestRootsCmd: rayctl roots shows the default, root adds the system store
// and a file of its own, and takes them back; a file without a CA is
// refused, a user other than root changes nothing.
func TestRootsCmd(t *testing.T) {
	saved := needRoot
	t.Cleanup(func() { needRoot = saved })
	needRoot = func() error { return nil }
	dir := t.TempDir()
	settings, extra := filepath.Join(dir, "etc", "tls-roots.json"), filepath.Join(dir, "etc", "tls-roots.pem")
	run := func(args ...string) (string, error) {
		var b bytes.Buffer
		err := rootsCmd(&b, settings, extra, args)
		return b.String(), err
	}
	out, err := run()
	if err != nil || !strings.Contains(out, "91 roots of 2026-11-14") || !strings.Contains(out, "not trusted (rayctl roots system on)") ||
		!strings.Contains(out, "none (rayctl roots file PEM") {
		t.Fatalf("show: %v\n%s", err, out)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	src := rootstest.File(t, srv.Certificate())
	if out, err = run("file", src); err != nil || !strings.Contains(out, "extra file "+extra+" (1 root)") {
		t.Fatalf("file: %v\n%s", err, out)
	}
	_ = os.Remove(src) // the copy counts
	if s, _ := roots.ReadSettings(settings); s.File != extra {
		t.Fatalf("settings %+v", s)
	}
	tr := &roots.Trust{Path: settings}
	if _, err := tr.Client(0).Get(srv.URL); err != nil {
		t.Fatalf("through the file: %v", err)
	}
	if out, err = run("system", "on"); err != nil || !strings.Contains(out, "system store added") || !strings.Contains(out, "may read") {
		t.Fatalf("system on: %v\n%s", err, out)
	}
	if out, _ = run("show"); !strings.Contains(out, "added (rayctl roots system off)") || !strings.Contains(out, extra+" (rayctl roots file none), its roots:") {
		t.Fatalf("show: %s", out)
	}
	if _, err = run("system", "off"); err != nil {
		t.Fatal(err)
	}
	if _, err = run("file", "none"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Fatalf("the default is no settings file: %v", err)
	}
	if _, err := os.Stat(extra); !os.IsNotExist(err) {
		t.Fatalf("the copy stays: %v", err)
	}
	leaf := filepath.Join(dir, "leaf.pem")
	_ = os.WriteFile(leaf, []byte("no pem\n"), 0o600)
	if _, err = run("file", leaf); err == nil {
		t.Fatal("a file without certificates")
	}
	if _, err = run("system", "maybe"); !errors.Is(err, errUsage) {
		t.Fatalf("usage: %v", err)
	}
	needRoot = func() error { return errors.New("must run as root") }
	if _, err = run("system", "on"); err == nil {
		t.Fatal("not root")
	}
}
