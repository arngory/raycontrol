//go:build unix

package roots

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// Unreadable says why the user uid, of groups gids, cannot read the file
// path (nil when it can), by the modes the kernel checks: the read bit of
// the file and the search bit of each directory above it. rayctl roots
// asks it for rayd's user: a file root wrote that rayd cannot read leaves
// rayd on the embedded list. ACLs and a unit's sandbox are not looked at.
func Unreadable(path string, uid int, gids []int) error {
	file, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	file, err = filepath.Abs(file)
	if err != nil {
		return err
	}
	var dirs []string
	for d := filepath.Dir(file); ; d = filepath.Dir(d) {
		dirs = append(dirs, d)
		if d == filepath.Dir(d) {
			break
		}
	}
	slices.Reverse(dirs)
	for _, d := range dirs {
		if err := allows(d, 0o1, uid, gids); err != nil {
			return err
		}
	}
	return allows(file, 0o4, uid, gids)
}

// allows checks one permission bit (4 read, 1 search) of p for uid.
func allows(p string, bit os.FileMode, uid int, gids []int) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || uid == 0 {
		return nil
	}
	mode := fi.Mode().Perm()
	var has bool
	switch {
	case int(st.Uid) == uid:
		has = mode&(bit<<6) != 0
	case slices.Contains(gids, int(st.Gid)):
		has = mode&(bit<<3) != 0
	default:
		has = mode&bit != 0
	}
	if has {
		return nil
	}
	what := "read"
	if bit == 0o1 {
		what = "search"
	}
	return fmt.Errorf("%s is mode %v, owner %d:%d: no %s for uid %d", p, mode, st.Uid, st.Gid, what, uid)
}
