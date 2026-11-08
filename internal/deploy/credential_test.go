package deploy_test

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/arngory/raycontrol/internal/deploy"
)

// credHost is a node's layout for CopyCredential: anchor (root's, as
// /var/lib), rayd's state directory with a rendered key in it, and the
// runtime directories (run, root's, as /run/niko; run/svc, the service's).
type credHost struct {
	anchor, rel, src, run, dst string
}

func newCredHost(t *testing.T) credHost {
	t.Helper()
	anchor := t.TempDir()
	rel := "raycontrol/rendered/svc/key.pem"
	src := filepath.Join(anchor, rel)
	if err := os.MkdirAll(filepath.Dir(src), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := t.TempDir()
	if err := os.Mkdir(filepath.Join(run, "svc"), 0o710); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(run, "svc"), 0o710)
	return credHost{anchor: anchor, rel: rel, src: src, run: run, dst: filepath.Join(run, "svc", "key.pem")}
}

func (h credHost) copy() error {
	return deploy.CopyCredential(h.anchor, h.rel, h.dst, os.Getuid(), os.Getgid())
}

// copied checks the copy at dst, and that no temporary file is left.
func (h credHost) copied(t *testing.T, want string) {
	t.Helper()
	fi, err := os.Lstat(h.dst)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(h.dst)
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o400 || int(st.Uid) != os.Getuid() || string(b) != want {
		t.Errorf("copy %v uid %d: %q", fi.Mode(), st.Uid, b)
	}
	h.clean(t)
}

// clean checks that no temporary file is left beside the runtime
// directory.
func (h credHost) clean(t *testing.T) {
	t.Helper()
	left, _ := os.ReadDir(h.run)
	for _, e := range left {
		if e.Name() != "svc" {
			t.Errorf("left in the runtime directory's parent: %s", e.Name())
		}
	}
}

// refused checks that the copy failed, said why, and wrote nothing.
func (h credHost) refused(t *testing.T, name, why string) {
	t.Helper()
	err := h.copy()
	if err == nil || !strings.Contains(err.Error(), why) {
		t.Errorf("%s: %v, want %q", name, err, why)
	}
	if _, err := os.Lstat(h.dst); !os.IsNotExist(err) {
		t.Errorf("%s: something at the destination: %v", name, err)
	}
	h.clean(t)
}

// root copies a credential in for a service without following rayd's
// links, waiting on its FIFOs or reading its devices (spec/apply-plan-v1.md
// §5, §6 decision 3); with openat2 and, where it is missing, one
// component at a time.
func TestCopyCredential(t *testing.T) {
	for _, openat2 := range []bool{true, false} {
		if !openat2 {
			t.Cleanup(deploy.NoOpenat2())
		}
		// As it should: the copy, 0400, the service user's; again on a
		// restart, over the last one.
		h := newCredHost(t)
		if err := h.copy(); err != nil {
			t.Fatal(err)
		}
		h.copied(t, "secret\n")
		os.WriteFile(h.src, []byte("rotated\n"), 0o600)
		if err := h.copy(); err != nil {
			t.Fatal(err)
		}
		h.copied(t, "rotated\n")

		elsewhere := filepath.Join(t.TempDir(), "root-secret")
		os.WriteFile(elsewhere, []byte("root's\n"), 0o600)

		// A link for the file, for its directory, for rendered/ itself
		// (rayd owns the state directory), for the whole state directory.
		for _, at := range []string{"raycontrol/rendered/svc/key.pem", "raycontrol/rendered/svc", "raycontrol/rendered", "raycontrol"} {
			h := newCredHost(t)
			p := filepath.Join(h.anchor, at)
			aside := t.TempDir()
			os.Rename(p, filepath.Join(aside, "moved"))
			target := elsewhere
			if at != "raycontrol/rendered/svc/key.pem" {
				// The same layout under the link, the key root's.
				target = filepath.Join(aside, "moved")
				os.WriteFile(filepath.Join(target, strings.TrimPrefix(h.rel, at+"/")), []byte("root's\n"), 0o600)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
			h.refused(t, "a link at "+at, "")
		}
		// Out of the anchor, by name.
		for _, rel := range []string{"../x", "raycontrol/../../x", "/etc/shadow", "", "raycontrol//rendered/svc/key.pem"} {
			h := newCredHost(t)
			h.rel = rel
			h.refused(t, "rel "+rel, "not a path below")
		}

		// A FIFO: refused at once, not waited on.
		h = newCredHost(t)
		os.Remove(h.src)
		if err := unix.Mkfifo(h.src, 0o600); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { h.refused(t, "a FIFO", "not a regular file"); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("hangs on a FIFO")
		}
		// A socket and a directory are not files either; a device
		// (root only can make one).
		h = newCredHost(t)
		os.Remove(h.src)
		l, err := net.Listen("unix", h.src)
		if err != nil {
			t.Fatal(err)
		}
		h.refused(t, "a socket", "") // ENXIO at the open
		l.Close()
		h = newCredHost(t)
		os.Remove(h.src)
		os.Mkdir(h.src, 0o700)
		h.refused(t, "a directory", "not a regular file")
		if os.Geteuid() == 0 {
			h = newCredHost(t)
			os.Remove(h.src)
			if err := unix.Mknod(h.src, unix.S_IFCHR|0o600, int(unix.Mkdev(1, 3))); err != nil {
				t.Fatal(err)
			}
			h.refused(t, "a device", "not a regular file")
		}
		// A hard link to another file: rayd cannot make one to root's
		// file where links are protected, and nothing is copied where
		// they are not.
		h = newCredHost(t)
		os.Remove(h.src)
		other := filepath.Join(h.anchor, "other")
		os.WriteFile(other, []byte("root's\n"), 0o600)
		if err := os.Link(other, h.src); err != nil {
			t.Fatal(err)
		}
		h.refused(t, "a hard link", "2 links")
		// Too big.
		h = newCredHost(t)
		os.Truncate(h.src, deploy.MaxCredential+1)
		h.refused(t, "too big", "bytes")

		// Directories others may write in: the anchor, the runtime
		// directory's parent (the copy is made there), the runtime
		// directory itself.
		for _, dir := range []func(credHost) string{
			func(h credHost) string { return h.anchor },
			func(h credHost) string { return h.run },
			func(h credHost) string { return filepath.Dir(h.dst) },
		} {
			for _, mode := range []os.FileMode{0o777, 0o770, 0o1777} {
				h := newCredHost(t)
				os.Chmod(dir(h), mode)
				h.refused(t, "a directory "+mode.String(), "others may write")
			}
		}
		if os.Geteuid() == 0 {
			// Another user's: the runtime directory of another service.
			h := newCredHost(t)
			os.Chown(filepath.Dir(h.dst), 65534, 65534)
			h.refused(t, "another user's runtime directory", "owned by UID 65534")
			h = newCredHost(t)
			os.Chown(h.anchor, 65534, 65534)
			h.refused(t, "another user's anchor", "owned by UID 65534")
		}
		// The runtime directory a link: refused, nothing written there.
		h = newCredHost(t)
		aside := t.TempDir()
		os.Remove(filepath.Dir(h.dst))
		os.Symlink(aside, filepath.Dir(h.dst))
		if err := h.copy(); err == nil {
			t.Error("a link for the runtime directory followed")
		}
		if left, _ := os.ReadDir(aside); len(left) != 0 {
			t.Errorf("written through the link: %v", left)
		}
		// A link at the destination (the service put it there before a
		// restart): replaced, never written through.
		h = newCredHost(t)
		os.WriteFile(elsewhere, []byte("root's\n"), 0o600)
		os.Symlink(elsewhere, h.dst)
		if err := h.copy(); err != nil {
			t.Fatal(err)
		}
		h.copied(t, "secret\n")
		if b, _ := os.ReadFile(elsewhere); !bytes.Equal(b, []byte("root's\n")) {
			t.Errorf("written through the link at the destination: %q", b)
		}
	}
}

// The units' lines read back to what supervise copies itself.
func TestCredentialLine(t *testing.T) {
	p := deploy.RelayPlan(deploy.DefaultBinaries)
	for _, pr := range []string{"/etc/systemd/system/rayspa.service", "/etc/systemd/system/" + deploy.RelayProbeUnit} {
		if !strings.Contains(file(p, pr), "ExecStartPre=+/usr/local/bin/rayd credential /etc/raycontrol relay.bundle ") {
			t.Errorf("%s:\n%s", pr, file(p, pr))
		}
	}
}
