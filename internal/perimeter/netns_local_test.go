//go:build linux

package perimeter

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// TestNetnsLocal: the egress policy's local part (R4-38) in the kernel, as
// TestNetnsEgress, with loopback as the local network (all a namespace
// has; 127.0.0.0/8 is in local4, and to_node does not look at it):
//   - off (an older rayd: no Local), the data plane reaches loopback;
//   - on, its new TCP flows are reset at once (ECONNREFUSED), UDP EPERM; the stub's
//     port 53 and the probe's port pass; root and the extra UIDs pass;
//   - a client's connection to a data-plane listener on loopback (a client
//     on a local network) is answered: replies are not new flows;
//   - allowed (rayctl egress allow local), it passes again.
func TestNetnsLocal(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	loUp(t)
	fw := &NFT{NflogGroup: 7}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	gate := NewGate(fw, quiet)
	snap := testSnapshot()
	policy := func(e *perimeterv1.Egress) {
		t.Helper()
		snap.Egress = e
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		if !gate.egressOn {
			t.Fatalf("egress policy %v not in force", e)
		}
	}
	ap := func(a string, port uint16) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr(a), port) }
	service, probe, stub := ap("127.0.0.1", 17001), ap("127.0.0.1", 17002), ap("127.0.0.53", 53)
	for _, a := range []netip.AddrPort{service, probe} {
		peer := listenTCP(t, a)
		go func() {
			for range peer {
			}
		}()
	}
	reach := func(uid int, a netip.AddrPort) error {
		t.Helper()
		start := time.Now()
		c, err := connAs(uid, a)
		if err == nil {
			c.Close()
		} else if d := time.Since(start); d > time.Second {
			t.Errorf("uid %d to %v refused after %v, not at once", uid, a, d)
		}
		return err
	}
	const dataPlane, rayd = 9150, 4242

	policy(&perimeterv1.Egress{})
	if err := reach(dataPlane, service); err != nil {
		t.Fatalf("no Local, an older rayd: %v", err)
	}

	policy(&perimeterv1.Egress{Uids: []uint32{rayd}, Local: &perimeterv1.Local{Loopback: []*perimeterv1.Port{{Proto: "tcp", Port: 17002}}}})
	if err := reach(dataPlane, service); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("data plane to loopback: %v, want ECONNREFUSED", err)
	}
	if err := sendAs(dataPlane, service, []byte("x")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("data plane's UDP to loopback: %v, want EPERM", err)
	}
	if err := reach(dataPlane, probe); err != nil {
		t.Errorf("data plane to the probe's port: %v", err)
	}
	if err := sendAs(dataPlane, stub, []byte("x")); err != nil {
		t.Errorf("data plane to the stub's 53: %v", err)
	}
	for _, uid := range []int{0, rayd} {
		if err := reach(uid, service); err != nil {
			t.Errorf("uid %d to loopback: %v", uid, err)
		}
	}

	// A data-plane listener answers a client from a local address.
	ln, err := listenAs(dataPlane, ap("127.0.0.1", 17003))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Write([]byte("hello"))
			c.Close()
		}
	}()
	c, err := net.DialTimeout("tcp", "127.0.0.1:17003", 2*time.Second)
	if err != nil {
		t.Fatalf("a client to the data plane: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, err := io.ReadAll(c); err != nil || string(b) != "hello" {
		t.Errorf("the data plane's answer: %q %v", b, err)
	}
	c.Close()

	if bl, err := fw.EgressBlocks(); err != nil || bl["local"].Packets == 0 {
		t.Errorf("counter: %v %v", bl, err)
	}

	policy(&perimeterv1.Egress{Local: &perimeterv1.Local{Allow: true}})
	if err := reach(dataPlane, service); err != nil {
		t.Errorf("allowed: %v", err)
	}
}

// listenAs listens on TCP from a socket owned by uid.
func listenAs(uid int, a netip.AddrPort) (net.Listener, error) {
	family, sa := sockaddr(a)
	fd, err := socketAs(uid, family, unix.SOCK_STREAM)
	if err != nil {
		return nil, err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.Listen(fd, 8); err != nil {
		unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "listener")
	defer f.Close()
	return net.FileListener(f)
}
