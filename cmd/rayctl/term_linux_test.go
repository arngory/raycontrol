package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// pty opens a pseudo-terminal: the master (the keyboard and the screen)
// and the slave (what rayctl has as its standard input). Skipped where
// there is no devpts.
func pty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	t.Cleanup(func() { master.Close() })
	fd := int(master.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("no pseudo-terminal here: unlock: %v", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Skipf("no pseudo-terminal here: its number: %v", err)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

// within waits until cond holds.
func within(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("not within 5 s: %s", what)
		}
	}
}

func echoes(t *testing.T, f *os.File) bool {
	t.Helper()
	tio, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	return tio.Lflag&unix.ECHO != 0
}

func waiting(t *testing.T, f *os.File) int {
	t.Helper()
	n, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCINQ)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A terminal is told from a pipe, its echo goes off and comes back as it
// was found.
func TestTTY(t *testing.T) {
	master, slave := pty(t)
	if !terminal(slave) || !terminal(master) {
		t.Fatal("a pseudo-terminal is not a terminal")
	}
	tty, ok := ttyOf(slave)
	if !ok || !echoes(t, slave) {
		t.Fatalf("ttyOf: %v; echo at first: %v", ok, echoes(t, slave))
	}
	if err := tty.echoOff(); err != nil || echoes(t, slave) {
		t.Fatalf("echoOff: %v; echo after: %v", err, echoes(t, slave))
	}
	// Nothing else of the settings changed: the line discipline still
	// gives whole lines.
	now, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	want := *tty.old
	want.Lflag &^= unix.ECHO
	if *now != want {
		t.Errorf("echoOff changed more than ECHO:\n%+v\n%+v", *now, want)
	}
	tty.restore()
	if now, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS); err != nil || *now != *tty.old {
		t.Errorf("restore: %v\n%+v\n%+v", err, now, tty.old)
	}
}

// What was typed before the prompt is dropped (a pasted blank line would
// wipe the invite's QR unseen); what is typed after is read.
func TestFlushInput(t *testing.T) {
	master, slave := pty(t)
	if _, err := master.WriteString("typed ahead\n\n"); err != nil {
		t.Fatal(err)
	}
	within(t, "the terminal has what was typed", func() bool { return waiting(t, slave) == len("typed ahead\n\n") })
	flushInput(slave)
	if n := waiting(t, slave); n != 0 {
		t.Fatalf("%d bytes wait after flushInput", n)
	}
	if _, err := master.WriteString("after\n"); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, err := slave.Read(b)
	if err != nil || string(b[:n]) != "after\n" {
		t.Errorf("read %q, %v after the flush", b[:n], err)
	}
}

// On a terminal a secret is asked for on standard error, typed without
// echo, twice when it is a new one, and the terminal is left as it was.
func TestReadSecretTerminal(t *testing.T) {
	for _, c := range []struct {
		name          string
		confirm       bool
		first, second string
		want          string
		err           string
	}{
		{"once", false, "s3cret", "", "s3cret", ""},
		{"twice", true, "s3cret words", "s3cret words", "s3cret words", ""},
		{"differ", true, "s3cret", "s3cert", "", "the two entries differ"},
		{"empty", false, "", "", "", "nothing entered"},
	} {
		t.Run(c.name, func(t *testing.T) {
			master, slave := pty(t)
			stdin(t, slave)
			pr, pw, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer pr.Close()
			saved := os.Stderr
			os.Stderr = pw
			defer func() { os.Stderr = saved }()
			prompts := make(chan string, 16)
			go func() {
				b := make([]byte, 256)
				for {
					n, err := pr.Read(b)
					if n > 0 {
						prompts <- string(b[:n])
					}
					if err != nil {
						close(prompts)
						return
					}
				}
			}()
			shown := ""
			prompt := func(want string) {
				t.Helper()
				for !strings.Contains(shown, want) {
					select {
					case s, ok := <-prompts:
						if !ok {
							t.Fatalf("no prompt %q; standard error had %q", want, shown)
						}
						shown += s
					case <-time.After(5 * time.Second):
						t.Fatalf("no prompt %q within 5 s; standard error had %q", want, shown)
					}
				}
			}
			type result struct {
				secret string
				err    error
			}
			done := make(chan result, 1)
			go func() {
				s, err := readSecret("Passphrase: ", "", c.confirm)
				done <- result{s, err}
			}()
			// Typed once the echo is off, as a person types after the
			// prompt: before it, the terminal would show it.
			prompt("Passphrase: ")
			within(t, "the echo is off for the first entry", func() bool { return !echoes(t, slave) })
			if _, err := master.WriteString(c.first + "\n"); err != nil {
				t.Fatal(err)
			}
			if c.confirm {
				prompt("Again: ")
				within(t, "the echo is off for the second entry", func() bool { return !echoes(t, slave) })
				if _, err := master.WriteString(c.second + "\n"); err != nil {
					t.Fatal(err)
				}
			}
			var got result
			select {
			case got = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("readSecret did not return")
			}
			pw.Close()
			if got.secret != c.want || (got.err == nil) != (c.err == "") || (got.err != nil && got.err.Error() != c.err) {
				t.Errorf("readSecret: %q, %v; want %q, %q", got.secret, got.err, c.want, c.err)
			}
			if !echoes(t, slave) {
				t.Error("the echo is left off")
			}
			// The screen got the line ends the terminal still echoes for a
			// typed Enter (ECHONL is off: not even those), never the secret.
			mfd := int(master.Fd()) // once: Fd makes the file blocking
			if err := unix.SetNonblock(mfd, true); err != nil {
				t.Fatal(err)
			}
			screen := make([]byte, 256)
			n, err := unix.Read(mfd, screen)
			if err != nil && !errors.Is(err, unix.EAGAIN) {
				t.Fatal(err)
			}
			if n > 0 && (bytes.Contains(screen[:n], []byte("s3c")) || len(bytes.TrimSpace(screen[:n])) != 0) {
				t.Errorf("the terminal showed %q", screen[:n])
			}
			// Each entry ends its line on standard error, where the prompt
			// was.
			for s := range prompts {
				shown += s
			}
			wantLines := 1
			if c.confirm {
				wantLines = 2
			}
			if got := strings.Count(shown, "\n"); got != wantLines {
				t.Errorf("standard error had %q: %d line ends, want %d", shown, got, wantLines)
			}
		})
	}
}
