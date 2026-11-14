//go:build linux || darwin || freebsd

package main

import (
	"os"
	"path/filepath"
	"testing"
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
