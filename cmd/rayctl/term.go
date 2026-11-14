//go:build linux || darwin || freebsd

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// The terminal, where rayctl asks for a secret or waits for Enter: termios
// through x/sys/unix, whose requests are named per system (term_linux.go,
// term_bsd.go). No golang.org/x/term: these three calls are all of it.

// tty is a terminal and its settings as they were found.
type tty struct {
	fd  int
	old *unix.Termios
}

// ttyOf is f as a terminal; false when it is not one (a pipe, a file).
func ttyOf(f *os.File) (*tty, bool) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, false
	}
	return &tty{fd: fd, old: old}, true
}

// terminal reports whether f is a terminal.
func terminal(f *os.File) bool {
	_, ok := ttyOf(f)
	return ok
}

// echoOff stops the terminal from showing what is typed, until restore.
func (t *tty) echoOff() error {
	quiet := *t.old
	quiet.Lflag &^= unix.ECHO
	return unix.IoctlSetTermios(t.fd, ioctlSetTermios, &quiet)
}

// restore puts the settings back as ttyOf found them.
func (t *tty) restore() { _ = unix.IoctlSetTermios(t.fd, ioctlSetTermios, t.old) }
