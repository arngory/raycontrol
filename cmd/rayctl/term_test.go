//go:build linux || darwin || freebsd

package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// stdin makes f the process's standard input until the test ends.
func stdin(t *testing.T, f *os.File) {
	t.Helper()
	saved := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = saved })
}

// A pipe and a file are not terminals: rayctl then neither asks twice nor
// waits for a PIN nobody can type.
func TestTerminalNot(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	f, err := os.Create(filepath.Join(t.TempDir(), "file"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for name, f := range map[string]*os.File{"a pipe's read end": r, "a pipe's write end": w, "a file": f} {
		if terminal(f) {
			t.Errorf("%s is a terminal", name)
		}
		if tty, ok := ttyOf(f); ok || tty != nil {
			t.Errorf("%s: ttyOf gave %v, %v", name, tty, ok)
		}
	}
}

// Flushing what was typed ahead is for a terminal: what waits in a pipe
// (rayctl in a script) stays.
func TestFlushInputPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.WriteString("in the pipe\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	flushInput(r)
	b := make([]byte, 64)
	n, err := r.Read(b)
	if err != nil || string(b[:n]) != "in the pipe\n" {
		t.Errorf("after flushInput the pipe gave %q, %v", b[:n], err)
	}
}

// Without a terminal a secret is one line of standard input, asked for
// once and with no prompt; from a file, the file less its line end.
func TestReadSecretNoTerminal(t *testing.T) {
	for in, want := range map[string]string{
		"s3cret\n":            "s3cret",
		"s3cret\r\n":          "s3cret",
		"no line end":         "no line end",
		" spaces are kept \n": " spaces are kept ",
		"first\nsecond\n":     "first",
	} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteString(in); err != nil {
			t.Fatal(err)
		}
		w.Close()
		stdin(t, r)
		got, err := readSecret("never shown: ", "", true)
		r.Close()
		if err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "\n", "\r\n"} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.WriteString(in)
		w.Close()
		stdin(t, r)
		if got, err := readSecret("never shown: ", "", false); err == nil {
			t.Errorf("%q: %q with no error", in, got)
		}
		r.Close()
	}
	file := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(file, []byte(" from a file \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readSecret("never shown: ", file, true); err != nil || got != " from a file " {
		t.Errorf("from a file: %q, %v", got, err)
	}
	if _, err := readSecret("never shown: ", filepath.Join(t.TempDir(), "missing"), false); err == nil {
		t.Error("a missing file: no error")
	}
}

// While the echo is off, a signal that ends rayctl undoes it first and
// then ends it with that signal; after stop, nothing is called. (The real
// end, on a terminal: TestReadSecretSignal, Linux.)
func TestOnEndSignal(t *testing.T) {
	type call struct {
		what string
		sig  os.Signal
	}
	calls := make(chan call, 4)
	stop := onEndSignal(func() { calls <- call{"undo", nil} }, func(s os.Signal) { calls <- call{"die", s} })
	if err := unix.Kill(os.Getpid(), unix.SIGHUP); err != nil {
		t.Fatal(err)
	}
	for _, want := range []call{{"undo", nil}, {"die", unix.SIGHUP}} {
		select {
		case got := <-calls:
			if got != want {
				t.Errorf("%v, want %v", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s within 5 s", want.what)
		}
	}
	stop()
	stop = onEndSignal(func() { calls <- call{"undo", nil} }, func(s os.Signal) { calls <- call{"die", s} })
	stop()
	// Notified elsewhere, so that the signal does not end the test.
	other := make(chan os.Signal, 1)
	signal.Notify(other, unix.SIGHUP)
	defer signal.Stop(other)
	if err := unix.Kill(os.Getpid(), unix.SIGHUP); err != nil {
		t.Fatal(err)
	}
	<-other
	select {
	case got := <-calls:
		t.Errorf("after stop: %v", got)
	case <-time.After(100 * time.Millisecond):
	}
}
