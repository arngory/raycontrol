package deploy_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/arngory/raycontrol/internal/deploy"
)

// A file of another's is not copied, whatever its links: rayd's are the
// only files below rendered/ root copies from (the relay's bundle: root's).
func TestCopyCredentialOwner(t *testing.T) {
	h := newCredHost(t)
	h.owner = os.Getuid() + 1
	h.refused(t, "a file of another's", "owned by UID")
	if os.Geteuid() == 0 {
		// As on a node: rayd's file, copied by root; root's file, not.
		h := newCredHost(t)
		os.Chown(h.src, 65534, 65534)
		h.owner = 65534
		if err := h.copy(); err != nil {
			t.Fatal(err)
		}
		h.copied(t, "secret\n")
		os.Chown(h.src, 0, 0)
		os.Remove(h.dst)
		h.refused(t, "root's file below rendered/", "owned by UID 0, not 65534")
	}
}

// The review's race (fs.protected_hardlinks=0): rayd links a file of
// root's into rendered/, waits for root's open (inotify IN_OPEN) and
// unlinks it, so the file has one link again by the time it is looked
// at. It is still not rayd's: never copied. Bounded for CI.
func TestCopyCredentialHardlinkRace(t *testing.T) {
	for _, withOpenat2 := range []bool{true, false} {
		if !withOpenat2 {
			t.Cleanup(deploy.NoOpenat2())
		}
		h := newCredHost(t)
		// The secret is this test's user's; rayd, whose files are copied,
		// is another.
		h.owner = os.Getuid() + 1
		secret := filepath.Join(t.TempDir(), "shadow")
		os.WriteFile(secret, []byte("root:$6$secret\n"), 0o600)
		if os.Geteuid() == 0 {
			// As on a node: rendered/ is rayd's, the secret root's.
			h.owner = 65534
			os.Chown(filepath.Dir(h.src), 65534, 65534)
		}
		ifd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
		if err != nil {
			t.Skip(err)
		}
		if _, err := unix.InotifyAddWatch(ifd, filepath.Dir(h.src), unix.IN_OPEN); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		var stop atomic.Bool
		go func() {
			defer close(done)
			runtime.LockOSThread()
			buf := make([]byte, 4096)
			for {
				n, err := unix.Read(ifd, buf)
				if err != nil || n <= 0 || stop.Load() {
					return
				}
				for off := 0; off < n; {
					ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
					if ev.Mask&unix.IN_OPEN != 0 {
						unix.Unlink(h.src)
					}
					off += unix.SizeofInotifyEvent + int(ev.Len)
				}
			}
		}()
		won := 0
		for range 300 {
			os.Remove(h.src)
			if err := os.Link(secret, h.src); err != nil {
				t.Fatal(err)
			}
			os.Remove(h.dst)
			if h.copy() == nil {
				if b, _ := os.ReadFile(h.dst); string(b) == "root:$6$secret\n" {
					won++
				}
			}
		}
		// The reader ends at its next event (an open), then the watch.
		stop.Store(true)
		os.WriteFile(filepath.Join(filepath.Dir(h.src), "wake"), nil, 0o600)
		<-done
		unix.Close(ifd)
		if won != 0 {
			t.Errorf("openat2 %v: another's file copied %d times of 300", withOpenat2, won)
		}
	}
}

// Where openat2 does not answer (ENOSYS: an older kernel; EPERM: a
// container's seccomp filter, or anything else that is not about the
// path), the copy goes on component by component; a refusal of the path
// stays one.
func TestCopyCredentialOpenat2Errors(t *testing.T) {
	for _, e := range []unix.Errno{unix.ENOSYS, unix.EPERM, unix.EINVAL, unix.EAGAIN} {
		h := newCredHost(t)
		restore := deploy.Openat2Err(e)
		err := h.copy()
		restore()
		if err != nil {
			t.Errorf("openat2 %v: %v", e, err)
		}
		h.copied(t, "secret\n")
	}
	for _, e := range []unix.Errno{unix.ELOOP, unix.EXDEV, unix.ENOENT, unix.ENOTDIR} {
		h := newCredHost(t)
		restore := deploy.Openat2Err(e)
		err := h.copy()
		restore()
		if err == nil || !strings.Contains(err.Error(), e.Error()) {
			t.Errorf("openat2 %v: %v, want that refusal", e, err)
		}
	}
}

// A copy a killed run left in the runtime directory goes at the next run
// of the same unit, a link under its name too (removed, not followed);
// another file's stays.
func TestCopyCredentialSweep(t *testing.T) {
	h := newCredHost(t)
	run := filepath.Dir(h.dst)
	stale := filepath.Join(run, ".key.pem.raycontrol-0123456789abcdef")
	link := filepath.Join(run, ".key.pem.raycontrol-fedcba9876543210")
	other := filepath.Join(run, ".cert.pem.raycontrol-0123456789abcdef")
	for _, p := range []string{stale, other} {
		if err := os.WriteFile(p, []byte("half"), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(t.TempDir(), "target")
	os.WriteFile(target, []byte("kept\n"), 0o600)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := h.copy(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{stale, link} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s stays: %v", filepath.Base(p), err)
		}
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "kept\n" {
		t.Errorf("the link's target: %q, %v", b, err)
	}
	if _, err := os.Lstat(other); err != nil {
		t.Errorf("another file's copy went: %v", err)
	}
	os.Remove(other)
	h.copied(t, "secret\n")
}

// In a systemd unit with ProtectSystem=strict, ExecStartPre=+ runs in the
// unit's mount namespace, where the runtime directory is a bind mount of
// its own: a copy made in /run/niko and renamed into it failed with EXDEV
// (systemd 257, CI). Here the runtime directory is made a mount of its own
// in a private mount namespace; root only.
func TestCopyCredentialRuntimeDirMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: a mount namespace")
	}
	for _, how := range []string{"bind", "tmpfs"} {
		h := newCredHost(t)
		run := filepath.Dir(h.dst)
		errc := make(chan error, 1)
		go func() {
			// The thread is never unlocked: it ends with this goroutine,
			// and its namespace with it.
			runtime.LockOSThread()
			if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
				errc <- errSkip{err}
				return
			}
			if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
				errc <- errSkip{err}
				return
			}
			var err error
			if how == "bind" {
				err = unix.Mount(run, run, "", unix.MS_BIND, "")
			} else {
				err = unix.Mount("tmpfs", run, "tmpfs", 0, "mode=0710")
			}
			if err != nil {
				errc <- errSkip{err}
				return
			}
			if err := h.copy(); err != nil {
				errc <- err
				return
			}
			b, err := os.ReadFile(h.dst)
			if err == nil && string(b) != "secret\n" {
				err = fmt.Errorf("the copy in the mount: %q", b)
			}
			errc <- err
		}()
		err := <-errc
		var skip errSkip
		if errors.As(err, &skip) {
			t.Skip(skip.err)
		}
		if err != nil {
			t.Errorf("%s mount on the runtime directory: %v", how, err)
		}
		// No temporary file beside the runtime directory or under it (the
		// mount is gone with its namespace).
		h.clean(t)
	}
}

// errSkip is a mount namespace this test cannot have.
type errSkip struct{ err error }

func (e errSkip) Error() string { return e.err.Error() }
