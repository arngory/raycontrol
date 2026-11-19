//go:build unix

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// checkDeviceFile refuses a device file that others can read or change,
// or that is another user's: it is the administrator's remote access to
// the node (a private key), and it says which node to trust (the pin).
// rayctl writes it mode 0600; a copy by scp or from a synced folder often
// is not. As OpenSSH does for a private key: root may use anyone's file
// (sudo rayctl -remote ~/n.rcdev), the mode counts for everyone. As
// rayspa does for a relay's bundle (node.ReadRelayBundle). fi is the
// open file's (readDeviceFile).
func checkDeviceFile(path string, fi os.FileInfo) error {
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
	case owner >= 0 && owner != me && me != 0:
		return fmt.Errorf("device file %s belongs to uid %d, not to you (uid %d): it holds a private key and its owner can change the node it trusts; "+
			"use a copy of your own (then chmod 600 it)", path, owner, me)
	case mode.Perm()&0o077 != 0:
		return fmt.Errorf("device file %s is mode %v: it holds a private key, make it 0600: chmod 600 %s "+
			"(if its filesystem keeps no modes: copy it to your home directory, chmod 600 the copy)", path, mode.Perm(), shellWord(path))
	}
	return nil
}

// shellWord is path as a word of a POSIX shell: as it is when nothing in
// it is special, else in single quotes (a quote in it closes them, is
// escaped with a backslash and opens them again); one that starts with
// "-" gets "./" first, so that chmod does not take it for an option. A
// word that starts with "=" is quoted too: zsh expands =name to a command.
func shellWord(path string) string {
	if strings.HasPrefix(path, "-") {
		path = "./" + path
	}
	if path != "" && !strings.HasPrefix(path, "=") && strings.Trim(path, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./+,:@%=-") == "" {
		return path
	}
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}
