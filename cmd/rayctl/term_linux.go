package main

import (
	"os"

	"golang.org/x/sys/unix"
)

const ioctlGetTermios, ioctlSetTermios = unix.TCGETS, unix.TCSETS

// flushInput drops what was typed ahead on the terminal f and not yet
// read: tcflush(TCIFLUSH). Nothing happens to a pipe or a file.
func flushInput(f *os.File) {
	_ = unix.IoctlSetInt(int(f.Fd()), unix.TCFLSH, unix.TCIFLUSH)
}
