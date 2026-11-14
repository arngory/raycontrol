package appmirror

import (
	"context"
	"io"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// A connection is paced while any download it carries goes on (HTTP/2:
// two devices' downloads over one), and put back after the last.
func TestPacing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	lowat := func() int {
		var v int
		rc, _ := conn.(*net.TCPConn).SyscallConn()
		_ = rc.Control(func(fd uintptr) { v, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT) })
		return v
	}
	sys := lowat()
	ctx := context.Background()
	m := &Mirror{}
	a, _ := m.begin(ctx, "a", conn)
	b, _ := m.begin(ctx, "b", conn)
	if v := lowat(); v != notSentLowat {
		t.Fatalf("under way: %d", v)
	}
	m.end("a", a)
	if v := lowat(); v != notSentLowat {
		t.Errorf("one of two ended: %d", v)
	}
	m.end("b", b)
	if v := lowat(); v != sys {
		t.Errorf("both ended: %d, the system's %d", v, sys)
	}
}
