package deploy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/arngory/raycontrol/internal/render"
)

// CredentialCommand is rayd's command that copies a credential in for a
// service, run by systemd as root before the service starts
// (ExecStartPre=+): CopyCredential. Not install(1): it follows links, and
// the files and directories it would read are rayd's
// (spec/apply-plan-v1.md §5, §6 decision 3).
const CredentialCommand = "credential"

// MaxCredential bounds a credential: keys and passwords are a few hundred
// bytes, a relay's bundle a few kilobytes.
const MaxCredential = 1 << 20

// The owners of the files credentials are copied from: rendered files are
// rayd's (it writes them), the relay's bundle root's.
const (
	renderedOwner = "rayd"
	bundleOwner   = "root"
)

// copyIn is the unit line that copies the credential src in for user
// before the start: rayd's credential command, as root. anchor is a
// directory rayd cannot change, src a file below it (no link is followed
// from anchor down), owner the user src must belong to.
func copyIn(rayd, anchor, owner, user, src, dst string) string {
	rel, err := filepath.Rel(anchor, src)
	if err != nil {
		rel = src
	}
	return "ExecStartPre=+" + rayd + " " + CredentialCommand + " " + anchor + " " + rel + " " + owner + " " + user + " " + dst
}

// renderedAnchor is the directory a rendered credential is opened from:
// above rayd's StateDirectory (Paths.Rendered is in it), which is rayd's,
// so rayd could turn rendered/ itself into a link.
func renderedAnchor(p render.Paths) string { return path.Dir(path.Dir(p.Rendered)) }

// copyOf reads a copyIn line back: the source and the destination
// (Process.Copies).
func copyOf(line string) (src, dst string, ok bool) {
	f := strings.Fields(line)
	if len(f) != 7 || !strings.HasPrefix(f[0], "+") || f[1] != CredentialCommand {
		return "", "", false
	}
	return path.Join(f[2], f[3]), f[6], true
}

// openat2 is unix.Openat2; tests take it away, as an old kernel or a
// container's seccomp filter does.
var openat2 = unix.Openat2

// CopyCredential copies the file rel below the directory anchor, which
// must belong to owner, to dst, for uid and gid, mode 0400. systemd runs
// it as root before a service starts (rayd credential, ExecStartPre=+).
// rayd writes the files it copies and owns the directories they are in; a
// link there could turn root's read to any file, a FIFO hang the start, a
// device do what opening it does. So:
//
//   - anchor must be root's alone (root's, not writable by its group or
//     others). Below it no link is followed, in any component, and nothing
//     leads out of it (openat2 RESOLVE_NO_SYMLINKS, RESOLVE_BENEATH).
//   - The file is opened O_PATH first, which opens nothing (no FIFO waits,
//     no device acts). Only a regular file of owner's with one link goes
//     on: one rayd linked to a file of root's is root's, whatever its
//     links by the time it is looked at. Then it is opened for reading
//     through that descriptor (/proc/self/fd), the same file, checked
//     again; MaxCredential bytes at most.
//   - dst's directory, the service's runtime directory, must be root's or
//     the service user's, and no one else's to write in. The copy is made
//     in its parent, root's alone, as a new file (O_EXCL, no link
//     followed), given its owner and mode through its descriptor, then
//     renamed over dst: a link put at dst is replaced, never followed. A
//     copy left there by a run that was killed goes at the next.
func CopyCredential(anchor, rel string, owner int, dst string, uid, gid int) error {
	b, err := readCredential(anchor, rel, owner)
	if err != nil {
		return fmt.Errorf("credential %s: %w", path.Join(anchor, rel), err)
	}
	if err := writeCredential(dst, b, uid, gid); err != nil {
		return fmt.Errorf("credential %s: %w", dst, err)
	}
	return nil
}

// readCredential reads rel below anchor, a file of owner's
// (CopyCredential).
func readCredential(anchor, rel string, owner int) ([]byte, error) {
	if !filepath.IsAbs(anchor) || rel == "" || path.IsAbs(rel) || path.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, errors.New("not a path below a directory")
	}
	a, err := unix.Open(anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", anchor, err)
	}
	defer func() { _ = unix.Close(a) }()
	if err := ownedDir(a, 0, os.Geteuid()); err != nil {
		return nil, fmt.Errorf("%s: %w", anchor, err)
	}
	// O_PATH: nothing is opened yet; what it names is looked at first.
	pfd, err := openBeneath(a, rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(pfd) }()
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return nil, err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, fmt.Errorf("not a regular file (mode %o)", st.Mode)
	case int(st.Uid) != owner:
		return nil, fmt.Errorf("owned by UID %d, not %d", st.Uid, owner)
	case st.Nlink != 1:
		return nil, fmt.Errorf("%d links to it", st.Nlink)
	case st.Size > MaxCredential:
		return nil, fmt.Errorf("%d bytes, at most %d", st.Size, MaxCredential)
	}
	// The same file, opened for reading through the descriptor whatever its
	// name is by now.
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", pfd), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("reopening it: %w", err)
	}
	f := os.NewFile(uintptr(fd), rel)
	defer f.Close()
	var again unix.Stat_t
	if err := unix.Fstat(fd, &again); err != nil {
		return nil, err
	}
	if again.Dev != st.Dev || again.Ino != st.Ino || again.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("not the file looked at")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxCredential+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxCredential {
		return nil, fmt.Errorf("more than %d bytes", MaxCredential)
	}
	return b, nil
}

// openBeneath opens rel below the directory dir as an O_PATH descriptor,
// following no link in any component and never leaving dir: openat2
// (Linux 5.6). Where it does not answer (ENOSYS on an older kernel, EPERM
// from a container's seccomp filter, anything but a refusal of the path),
// one component at a time, each opened without following a link.
func openBeneath(dir int, rel string) (int, error) {
	const file = unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := openat2(dir, rel, &unix.OpenHow{Flags: file,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err == nil || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
		return fd, err
	}
	parts := strings.Split(rel, "/")
	at := dir
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			err = unix.EINVAL
		} else {
			flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
			if i == len(parts)-1 {
				flags = file
			}
			fd, err = unix.Openat(at, part, flags, 0)
		}
		if at != dir {
			_ = unix.Close(at)
		}
		if err != nil {
			return -1, err
		}
		at = fd
	}
	return at, nil
}

// writeCredential puts b at dst for uid and gid, mode 0400
// (CopyCredential).
func writeCredential(dst string, b []byte, uid, gid int) error {
	dir, name := filepath.Dir(dst), filepath.Base(dst)
	parent := filepath.Dir(dir)
	if !filepath.IsAbs(dst) || filepath.Clean(dst) != dst || parent == dir {
		return errors.New("not a path in a directory of a directory")
	}
	p, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", parent, err)
	}
	defer func() { _ = unix.Close(p) }()
	if err := ownedDir(p, 0, os.Geteuid()); err != nil {
		return fmt.Errorf("%s: %w", parent, err)
	}
	d, err := unix.Openat(p, filepath.Base(dir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	defer func() { _ = unix.Close(d) }()
	if err := ownedDir(d, 0, os.Geteuid(), uid); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	// The copy's name is this runtime directory's and this file's: one
	// left by a run that was killed half way is this unit's to remove
	// (systemd runs one start of a unit at a time).
	prefix := "." + filepath.Base(dir) + "." + name + ".raycontrol-"
	sweep(p, prefix)
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	tmp := prefix + hex.EncodeToString(r[:])
	fd, err := unix.Openat(p, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o400)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	done := false
	defer func() {
		f.Close()
		if !done {
			_ = unix.Unlinkat(p, tmp, 0)
		}
	}()
	// Written and its mode set while it is root's; the service user's last.
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, 0o400); err != nil {
		return err
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	if err := unix.Renameat(p, tmp, d, name); err != nil {
		return err
	}
	done = true
	return nil
}

// sweep removes the entries of the directory dir (root's alone) whose
// names start with prefix: copies a killed run left.
func sweep(dir int, prefix string) {
	d, err := unix.Dup(dir)
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(d), "")
	names, _ := f.Readdirnames(-1)
	f.Close()
	for _, n := range names {
		if strings.HasPrefix(n, prefix) {
			_ = unix.Unlinkat(dir, n, 0)
		}
	}
}

// ownedDir checks that fd is a directory of one of owners that no one
// else may write in: not its group, not others.
func ownedDir(fd int, owners ...int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return errors.New("not a directory")
	case !slices.Contains(owners, int(st.Uid)):
		return fmt.Errorf("owned by UID %d", st.Uid)
	case st.Mode&0o022 != 0:
		return fmt.Errorf("mode %o: others may write in it", st.Mode&0o7777)
	}
	return nil
}
