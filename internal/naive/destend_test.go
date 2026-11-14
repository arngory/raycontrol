package naive

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// endingDestination is a destination that sends "hello" and, once told,
// ends its connection: with a reset (RST) or cleanly (FIN).
func endingDestination(t *testing.T, reset bool) (addr string, end func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	told := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("hello"))
		<-told
		if reset {
			_ = c.(*net.TCPConn).SetLinger(0) // close sends a RST
		}
		c.Close()
	}()
	return ln.Addr().String(), func() { close(told) }
}

// A destination that breaks off (a reset) resets the client's stream: the
// client sees an error after what came, not an end it would take for the
// destination's own. A destination that ends (FIN) ends the stream.
func TestDestinationEnd(t *testing.T) {
	_, connect := tunnelServer(t, func(*Server) {})
	for name, reset := range map[string]bool{"reset": true, "end": false} {
		addr, end := endingDestination(t, reset)
		_, s, done := connect(addr)
		got := make([]byte, 5)
		if _, err := io.ReadFull(s, got); err != nil || string(got) != "hello" {
			t.Fatalf("%s: read %q %v", name, got, err)
		}
		end()
		type result struct {
			rest []byte
			err  error
		}
		read := make(chan result, 1)
		go func() {
			rest, err := io.ReadAll(s)
			read <- result{rest, err}
		}()
		select {
		case r := <-read:
			switch {
			case len(r.rest) != 0:
				t.Errorf("%s: %q after the destination was done", name, r.rest)
			case reset && r.err == nil:
				t.Errorf("%s: the stream ended cleanly: the client cannot tell a reset from the destination's end", name)
			case !reset && r.err != nil:
				t.Errorf("%s: the stream failed with %v after a clean end", name, r.err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("%s: the stream stayed open", name)
		}
		done()
	}
}

// What a destination sent before it reset is not lost with the stream's
// reset: a client that reads late reads all of it, then the error.
func TestBytesBeforeResetArrive(t *testing.T) {
	const size = 3 << 20
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write(bytes.Repeat([]byte{7}, size))
		// The node's kernel takes it all, then the RST.
		time.Sleep(300 * time.Millisecond)
		_ = c.(*net.TCPConn).SetLinger(0)
		c.Close()
	}()
	_, connect := tunnelServer(t, func(*Server) {})
	_, s, done := connect(ln.Addr().String())
	defer done()
	time.Sleep(time.Second) // the client reads late: the RST is long there
	n, err := io.Copy(io.Discard, s)
	if n != size {
		t.Errorf("read %d of %d bytes the destination sent before its reset (%v)", n, size, err)
	}
	if err == nil {
		t.Error("a clean end after a reset")
	}
}
