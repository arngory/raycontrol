package deploy_test

import (
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

// A copy a killed run left beside the runtime directory goes at the next
// run of the same unit; another unit's stays.
func TestCopyCredentialSweep(t *testing.T) {
	h := newCredHost(t)
	stale := filepath.Join(h.run, ".svc.key.pem.raycontrol-0123456789abcdef")
	other := filepath.Join(h.run, ".other.key.pem.raycontrol-0123456789abcdef")
	for _, p := range []string{stale, other} {
		if err := os.WriteFile(p, []byte("half"), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.copy(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Errorf("the stale copy stays: %v", err)
	}
	if _, err := os.Lstat(other); err != nil {
		t.Errorf("another unit's copy went: %v", err)
	}
}
