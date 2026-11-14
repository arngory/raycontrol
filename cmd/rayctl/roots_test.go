package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/arngory/raycontrol/internal/roots"
	"github.com/arngory/raycontrol/internal/roots/rootstest"
)

// TestRootsCmd: rayctl roots shows the default, root adds the system store
// and a file of its own, and takes them back; a file without a CA is
// refused, a user other than root changes nothing.
func TestRootsCmd(t *testing.T) {
	saved, savedAccount := needRoot, raydAccount
	t.Cleanup(func() { needRoot, raydAccount = saved, savedAccount })
	needRoot = func() error { return nil }
	raydAccount = func() (int, []int, bool) { return 0, nil, false }
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
	// The settings cannot be written: the file they name stays.
	_ = os.Mkdir(settings+".tmp", 0o700)
	if _, err = run("file", "none"); err == nil {
		t.Fatal("file none: the settings were not written")
	}
	if _, err := os.Stat(extra); err != nil {
		t.Fatalf("the file the settings name went: %v", err)
	}
	_ = os.Remove(settings + ".tmp")
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

// TestRootsCmdRaydReads: under root's umask of 027 what rayctl roots
// writes is still rayd's to read; a file rayd cannot read is said, in
// show and when set, not passed off as followed.
func TestRootsCmdRaydReads(t *testing.T) {
	savedRoot, savedAccount := needRoot, raydAccount
	t.Cleanup(func() { needRoot, raydAccount = savedRoot, savedAccount })
	needRoot = func() error { return nil }
	raydAccount = func() (int, []int, bool) { return 4242, []int{4242}, true }
	old := syscall.Umask(0o027)
	t.Cleanup(func() { syscall.Umask(old) })
	dir := t.TempDir()
	for _, d := range []string{filepath.Dir(dir), dir} {
		_ = os.Chmod(d, 0o755) // a test's directories are 0700
	}
	settings, extra := filepath.Join(dir, "etc", "tls-roots.json"), filepath.Join(dir, "etc", "tls-roots.pem")
	run := func(args ...string) (string, error) {
		var b bytes.Buffer
		err := rootsCmd(&b, settings, extra, args)
		return b.String(), err
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	if out, err := run("file", rootstest.File(t, srv.Certificate())); err != nil || strings.Contains(out, "cannot read") {
		t.Fatalf("file under umask 027: %v\n%s", err, out)
	}
	for _, f := range []string{settings, extra} {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o644 {
			t.Errorf("%s is %v", f, fi.Mode())
		}
	}
	if out, _ := run(); strings.Contains(out, "WARNING") {
		t.Fatalf("show: %s", out)
	}
	_ = os.Chmod(extra, 0o600)
	if out, _ := run(); !strings.Contains(out, "WARNING") || !strings.Contains(out, "rayd (user rayd) cannot read "+extra+" ("+extra+" is mode -rw-------") {
		t.Fatalf("show, the extra file closed: %s", out)
	}
	// A directory above closed to rayd: the set says so.
	_ = os.Chmod(extra, 0o644)
	_ = os.Chmod(dir, 0o750)
	if _, err := run("system", "on"); err == nil || !strings.Contains(err.Error(), "written, but rayd (user rayd) cannot read "+settings) {
		t.Fatalf("set, a directory closed: %v", err)
	}
	// /etc/raycontrol itself closed: rayctl opens it to rayd, and says so.
	_ = os.Chmod(dir, 0o755)
	_ = os.Chmod(filepath.Dir(settings), 0o750)
	if out, err := run("system", "off"); err != nil || !strings.Contains(out, "was mode -rwxr-x---, closed to rayd: now -rwxr-x--x") {
		t.Fatalf("closed /etc/raycontrol: %v\n%s", err, out)
	}
}
