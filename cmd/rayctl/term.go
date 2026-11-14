//go:build linux || darwin || freebsd

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The terminal, where rayctl asks for a secret or waits for Enter: termios
// through x/sys/unix, whose requests are named per system (term_linux.go,
// term_bsd.go). No golang.org/x/term: these three calls are all of it.

// tty is a terminal and its settings as they were found.
type tty struct {
	fd  int
	old *unix.Termios
	// stop ends the watch for signals of echoOff (nil: none).
	stop func()
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
// A signal that ends rayctl meanwhile (Ctrl-C, kill, the terminal closed)
// puts the echo back first: the runtime's own exit on it runs no deferred
// call, and the shell would be left without echo.
func (t *tty) echoOff() error {
	quiet := *t.old
	quiet.Lflag &^= unix.ECHO
	t.stop = onEndSignal(t.reset, dieOf)
	if err := unix.IoctlSetTermios(t.fd, ioctlSetTermios, &quiet); err != nil {
		t.stop()
		t.stop = nil
		return err
	}
	return nil
}

// restore puts the settings back as ttyOf found them, and ends the watch
// of echoOff.
func (t *tty) restore() {
	t.reset()
	if t.stop != nil {
		t.stop()
		t.stop = nil
	}
}

func (t *tty) reset() { _ = unix.IoctlSetTermios(t.fd, ioctlSetTermios, t.old) }

// endSignals end rayctl by default and come from the terminal or its
// user. One that rayctl was started with ignored (nohup) stays ignored.
var endSignals = []os.Signal{unix.SIGINT, unix.SIGTERM, unix.SIGHUP}

// onEndSignal calls undo and then die with the signal when one of
// endSignals comes, until stop.
func onEndSignal(undo func(), die func(os.Signal)) (stop func()) {
	var sigs []os.Signal
	for _, s := range endSignals {
		if !signal.Ignored(s) {
			sigs = append(sigs, s)
		}
	}
	if len(sigs) == 0 {
		return func() {} // Notify of none would be of all
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sigs...)
	done := make(chan struct{})
	go func() {
		select {
		case s := <-ch:
			undo()
			die(s)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// dieOf ends rayctl by the signal s as if it had not been caught: the
// parent sees it killed by s, as before, and not an exit status 128+n,
// which a shell does not take for Ctrl-C (bash then goes on with a loop).
// The exit status is only the fallback, should the signal not end it.
func dieOf(s os.Signal) {
	fmt.Fprintln(os.Stderr) // the prompt's line ends
	signal.Reset(s)
	n, _ := s.(syscall.Signal)
	_ = unix.Kill(os.Getpid(), n)
	time.Sleep(time.Second)
	os.Exit(128 + int(n))
}
