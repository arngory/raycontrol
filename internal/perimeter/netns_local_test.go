//go:build linux

package perimeter

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
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

	// An operator's REALITY target on 127.0.0.1 (the host's own web
	// server): its exact address, TCP and port, from that service's
	// process only. Its port + 1 is refused, and so is the same target
	// from another data-plane process.
	const reality = 9120
	steal, next := ap("127.0.0.1", 17004), ap("127.0.0.1", 17005)
	for _, a := range []netip.AddrPort{steal, next} {
		peer := listenTCP(t, a)
		go func() {
			for range peer {
			}
		}()
	}
	policy(&perimeterv1.Egress{Local: &perimeterv1.Local{Exempt: []*perimeterv1.LocalExempt{
		{Addr: "127.0.0.1", Port: &perimeterv1.Port{Proto: "tcp", Port: 17004}, Uid: reality}}}})
	if err := reach(reality, steal); err != nil {
		t.Errorf("REALITY to its target: %v", err)
	}
	if err := reach(reality, next); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("REALITY to its target's port + 1: %v, want ECONNREFUSED", err)
	}
	if err := sendAs(reality, steal, []byte("x")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("REALITY's UDP to its TCP target: %v, want EPERM", err)
	}
	if err := reach(dataPlane, steal); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("another process to the REALITY target: %v, want ECONNREFUSED", err)
	}

	policy(&perimeterv1.Egress{Local: &perimeterv1.Local{Allow: true}})
	if err := reach(dataPlane, service); err != nil {
		t.Errorf("allowed: %v", err)
	}
}

// TestNetnsLocalUntracked: the front's DNS answers skip conntrack
// (notrack_out: UID 9100, source port a DNS tunnel's), and an untracked
// packet is never "ct state new": the jump to egress_local takes untracked
// ones too. From the front's DNS port a datagram to a local network (an
// SNMP agent on the LAN, the metadata address) is refused, EPERM; to the
// internet it goes; to the stub on 53 it goes (on lo, tracked, the stub's
// exception).
func TestNetnsLocalUntracked(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	loUp(t)
	for _, args := range [][]string{
		{"link", "add", "rc-lu", "type", "veth", "peer", "name", "rc-lv"}, {"addr", "add", "10.1.2.1/24", "dev", "rc-lu"},
		{"link", "set", "rc-lu", "up"}, {"link", "set", "rc-lv", "up"},
		{"route", "add", "169.254.0.0/16", "dev", "rc-lu"}, {"route", "add", "198.51.100.0/24", "dev", "rc-lu"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	defer exec.Command("ip", "link", "del", "rc-lu").Run()
	fw := &NFT{NflogGroup: 7}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	if err := fw.SetPublic([]Port{{"udp", 5353}}); err != nil {
		t.Fatal(err)
	}
	send := func(uid, sport int, dst netip.AddrPort) error {
		t.Helper()
		family, sa := sockaddr(dst)
		fd, err := socketAs(uid, family, unix.SOCK_DGRAM)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if err := unix.Bind(fd, &unix.SockaddrInet4{Port: sport}); err != nil {
			t.Fatal(err)
		}
		return unix.Sendto(fd, []byte("x"), 0, sa)
	}
	lan, metadata := netip.MustParseAddrPort("10.1.2.3:161"), netip.MustParseAddrPort("169.254.169.254:53")
	internet, stub := netip.MustParseAddrPort("198.51.100.7:53"), netip.MustParseAddrPort("127.0.0.53:53")

	// No policy yet: everything goes, the front's too.
	for _, dst := range []netip.AddrPort{lan, metadata, internet} {
		if err := send(frontUID, 5353, dst); err != nil {
			t.Fatalf("no policy, the front to %v: %v", dst, err)
		}
	}
	if err := fw.SetEgress(Egress{Local: true}); err != nil {
		t.Fatal(err)
	}
	for _, dst := range []netip.AddrPort{lan, metadata} {
		if err := send(frontUID, 5353, dst); !errors.Is(err, syscall.EPERM) {
			t.Errorf("the front's untracked UDP to %v: %v, want EPERM", dst, err)
		}
		// Tracked, from any other port: refused as before.
		if err := send(frontUID, 40001, dst); !errors.Is(err, syscall.EPERM) {
			t.Errorf("the front's UDP to %v from another port: %v, want EPERM", dst, err)
		}
	}
	for _, dst := range []netip.AddrPort{internet, stub} {
		if err := send(frontUID, 5353, dst); err != nil {
			t.Errorf("the front's UDP to %v: %v", dst, err)
		}
	}
	// Root's (the node's own query from the DNS port) is not the data plane's.
	if err := send(0, 5353, lan); err != nil {
		t.Errorf("root to %v: %v", lan, err)
	}
}

// TestNetnsLocalAzure: Azure's platform address, 168.63.129.16 (the
// WireServer), is in the local networks, but on port 53, TCP and UDP, the
// data plane reaches it (LocalResolvers): an Azure VM whose resolv.conf
// names it (RHEL and Rocky with NetworkManager, no systemd-resolved)
// resolves from niko-server's Hysteria2 and Yggdrasil. Its other ports are
// refused, the guest agent's 80 and 32526 among them, and so is another
// local network's port 53. It is routed out of a veth whose other end
// answers nothing: a refusal is the perimeter's, at once.
func TestNetnsLocalAzure(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	loUp(t)
	for _, args := range [][]string{
		{"link", "add", "rc-az", "type", "veth", "peer", "name", "rc-ay"}, {"addr", "add", "10.1.3.1/24", "dev", "rc-az"},
		{"link", "set", "rc-az", "up"}, {"link", "set", "rc-ay", "up"},
		{"route", "add", "168.63.129.16/32", "dev", "rc-az"}, {"route", "add", "169.254.0.0/16", "dev", "rc-az"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	defer exec.Command("ip", "link", "del", "rc-az").Run()
	fw := &NFT{NflogGroup: 7}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	if err := fw.SetEgress(Egress{Local: true}); err != nil {
		t.Fatal(err)
	}
	const dataPlane = 9150
	wire := func(port uint16) netip.AddrPort {
		return netip.AddrPortFrom(netip.MustParseAddr("168.63.129.16"), port)
	}
	// refused tells whether a TCP connect from uid is refused within a
	// moment; one that goes out waits for an answer that never comes.
	refused := func(uid int, a netip.AddrPort) bool {
		t.Helper()
		family, sa := sockaddr(a)
		fd, err := socketAs(uid, family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		switch err := unix.Connect(fd, sa); {
		case errors.Is(err, syscall.ECONNREFUSED):
			return true
		case !errors.Is(err, syscall.EINPROGRESS):
			t.Fatalf("connect to %v: %v", a, err)
		}
		time.Sleep(300 * time.Millisecond)
		v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			t.Fatal(err)
		}
		return syscall.Errno(v) == syscall.ECONNREFUSED //nolint:gosec // G115: an errno
	}

	if err := sendAs(dataPlane, wire(53), []byte("x")); err != nil {
		t.Errorf("the data plane's UDP to Azure's resolver: %v", err)
	}
	if refused(dataPlane, wire(53)) {
		t.Error("the data plane's TCP to Azure's resolver is refused")
	}
	for _, port := range []uint16{80, 32526} {
		if !refused(dataPlane, wire(port)) {
			t.Errorf("the data plane's TCP to the WireServer's %d is not refused", port)
		}
		if c, err := connAs(dataPlane, wire(port)); !errors.Is(err, syscall.ECONNREFUSED) {
			if c != nil {
				c.Close()
			}
			t.Errorf("the data plane to the WireServer's %d: %v, want ECONNREFUSED", port, err)
		}
		if err := sendAs(dataPlane, wire(port), []byte("x")); !errors.Is(err, syscall.EPERM) {
			t.Errorf("the data plane's UDP to the WireServer's %d: %v, want EPERM", port, err)
		}
	}
	// Port 53 elsewhere in the local networks is no resolver of the list:
	// AWS's 169.254.169.253 is reached only through systemd-resolved.
	if err := sendAs(dataPlane, netip.MustParseAddrPort("169.254.169.253:53"), []byte("x")); !errors.Is(err, syscall.EPERM) {
		t.Errorf("the data plane's UDP to 169.254.169.253:53: %v, want EPERM", err)
	}
	// Root (rayd's own lookups, the guest agent) is not the data plane's.
	if refused(0, wire(80)) {
		t.Error("root's TCP to the WireServer is refused")
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
