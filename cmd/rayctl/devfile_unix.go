//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// checkDeviceFile refuses a device file that others can read or change,
// or that is another user's: it is the administrator's remote access to
// the node (a private key), and it says which node to trust (the pin).
// rayctl writes it mode 0600; a copy by scp or from a synced folder often
// is not. As rayspa does for a relay's bundle (node.ReadRelayBundle).
func checkDeviceFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return nil // the read says what is wrong with the path, as before
	}
	owner := -1
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		owner = int(st.Uid)
	}
	return deviceFileProblem(path, fi.Mode(), owner, os.Geteuid())
}

// deviceFileProblem is checkDeviceFile's answer for a file of this mode
// and owner (-1: not known) read by the user me.
func deviceFileProblem(path string, mode os.FileMode, owner, me int) error {
	switch {
	case owner >= 0 && owner != me:
		return fmt.Errorf("device file %s belongs to uid %d, not to you (uid %d): it holds a private key and its owner can change the node it trusts; "+
			"use a copy of your own (then chmod 600 it)", path, owner, me)
	case mode.Perm()&0o077 != 0:
		return fmt.Errorf("device file %s is mode %v: it holds a private key, make it 0600: chmod 600 %s", path, mode.Perm(), path)
	}
	return nil
}
