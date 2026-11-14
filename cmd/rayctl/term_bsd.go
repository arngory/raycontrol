//go:build darwin || freebsd

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

const ioctlGetTermios, ioctlSetTermios = unix.TIOCGETA, unix.TIOCSETA

// fread is FREAD of sys/fcntl.h: TIOCFLUSH's "the input queue".
const fread = 1

// flushInput drops what was typed ahead on the terminal f and not yet
// read: tcflush(TCIFLUSH), which these systems' libc makes as TIOCFLUSH
// with FREAD. Nothing happens to a pipe or a file.
func flushInput(f *os.File) {
	_ = unix.IoctlSetPointerInt(int(f.Fd()), unix.TIOCFLUSH, fread)
}
