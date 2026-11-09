package perimeter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The conn-limit-v1 parts of the perimeter (spec/conn-limit-v1.md §6.2,
// §6.3, §9 item 5) in network namespaces, as TestNetns: root, under
// unshare -n, RAYCONTROL_NETNS_TEST=1. The node is the test's namespace;
// peers are namespaces of their own behind veth pairs. Only per-namespace
// keys are written (the conntrack times); nf_conntrack_max stays the
// system's: the guard's threshold comes from a stand-in max.

func netnsOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	nodeNS()
	loUp(t)
}

// nodeNS is the test's own network namespace, read once before any thread
// moves.
var nodeNS = sync.OnceValue(func() string {
	ns, _ := os.Readlink("/proc/self/ns/net")
	return ns
})

// peerNS is a network namespace held open by a sleeping process.
type peerNS struct {
	cmd *exec.Cmd
	fd  int
}

func newPeer(t *testing.T) *peerNS {
	t.Helper()
	cmd := exec.Command("unshare", "-n", "sleep", "600")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &peerNS{cmd: cmd, fd: -1}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if p.fd >= 0 {
			_ = unix.Close(p.fd)
		}
	})
	// The node's namespace, as the process started: a thread that went
	// into a peer's and ended may be the main one, which Go keeps.
	self := nodeNS()
	for end := time.Now().Add(5 * time.Second); ; {
		if ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid)); err == nil && ns != self {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the peer's namespace did not come up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	p.fd = fd
	p.run(t, "ip", "link", "set", "lo", "up")
	return p
}

// run runs a command in the peer's namespace.
func (p *peerNS) run(t *testing.T, args ...string) {
	t.Helper()
	full := append([]string{"-t", strconv.Itoa(p.cmd.Process.Pid), "-n"}, args...)
	if out, err := exec.Command("nsenter", full...).CombinedOutput(); err != nil {
		t.Fatalf("in the peer: %v: %v %s", args, err, out)
	}
}

// do runs fn on a thread in the peer's namespace: the sockets it makes
// stay there.
func (p *peerNS) do(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// The thread is not given back: it ends with the goroutine, in
		// whatever namespace it is.
		if err := unix.Setns(p.fd, unix.CLONE_NEWNET); err != nil {
			done <- err
			return
		}
		want, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", p.cmd.Process.Pid))
		if got, _ := os.Readlink("/proc/thread-self/ns/net"); got != want {
			done <- fmt.Errorf("the thread is in %s, not the peer's %s", got, want)
			return
		}
		fn()
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// link joins the node and a peer: veth node-side with nodeAddrs, the
// peer's side with peerAddrs (CIDR).
func link(t *testing.T, p *peerNS, name string, nodeAddrs, peerAddrs []string) {
	t.Helper()
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	ip("link", "add", name+"a", "type", "veth", "peer", "name", name+"b")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name+"a").Run() })
	ip("link", "set", name+"b", "netns", strconv.Itoa(p.cmd.Process.Pid))
	for _, a := range nodeAddrs {
		ip(append([]string{"addr", "add", a, "dev", name + "a"}, nodad(a)...)...)
	}
	ip("link", "set", name+"a", "up")
	for _, a := range peerAddrs {
		p.run(t, append([]string{"ip", "addr", "add", a, "dev", name + "b"}, nodad(a)...)...)
	}
	p.run(t, "ip", "link", "set", name+"b", "up")
}

func nodad(addr string) []string {
	if strings.Contains(addr, ":") {
		return []string{"nodad"}
	}
	return nil
}

// ctCount is nf_conntrack_count of the node's namespace.
func ctCount(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// entries are the node's conntrack entries of a family, by mark (marked:
// the data plane's bit set, or not).
func entries(t *testing.T, family uint8, marked bool) []ctEntry {
	t.Helper()
	c, err := dialConntrack()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	v := uint32(0)
	if marked {
		v = dataPlaneMarkBit
	}
	es, err := c.dump(family, v, dataPlaneMarkBit)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func findEntry(es []ctEntry, match func(ctEntry) bool) (ctEntry, bool) {
	for _, e := range es {
		if match(e) {
			return e, true
		}
	}
	return ctEntry{}, false
}

// synsFrom opens n connections from src to dst without waiting for them
// (one SYN each), and closes them after settle: retransmissions would
// count again.
func synsFrom(t *testing.T, p *peerNS, src netip.Addr, dst netip.AddrPort, n int, settle time.Duration) {
	t.Helper()
	var fds []int
	p.do(t, func() {
		family := unix.AF_INET
		if dst.Addr().Is6() {
			family = unix.AF_INET6
		}
		for range n {
			fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, 0)
			if err != nil {
				t.Errorf("socket: %v", err)
				return
			}
			_, sa := sockaddr(netip.AddrPortFrom(src, 0))
			if err := unix.Bind(fd, sa); err != nil {
				t.Errorf("bind %v: %v", src, err)
				unix.Close(fd)
				return
			}
			_, sa = sockaddr(dst)
			_ = unix.Connect(fd, sa)
			fds = append(fds, fd)
		}
	})
	if len(fds) != n {
		t.Fatalf("%d of %d connections opened", len(fds), n)
	}
	time.Sleep(settle)
	for _, fd := range fds {
		_ = unix.SetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{Onoff: 1})
		unix.Close(fd)
	}
}

// udpFrom sends one datagram from each of n sockets (n new flows).
func udpFrom(t *testing.T, p *peerNS, src netip.Addr, dst netip.AddrPort, n int) {
	t.Helper()
	p.do(t, func() {
		for range n {
			c, err := net.DialUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(src, 0)), net.UDPAddrFromAddrPort(dst))
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("q"))
			c.Close()
		}
	})
}

func inDrops(t *testing.T, fw *NFT, chain, rule string) uint64 {
	t.Helper()
	counts, err := fw.counters(chain)
	if err != nil {
		t.Fatal(err)
	}
	return counts[rule].Packets
}

// TestNetnsInboundRate: the per-address limit on new inbound TCP and UDP,
// the numbers divided by 10 (TCP 5/s with 100, a /48 1 600; UDP 2/s with
// 20). SYNs to a closed port are not counted; the admin's address is not
// limited; what is dropped leaves no entry; IPv6 is keyed by /64 and /48;
// off takes it away.
func TestNetnsInboundRate(t *testing.T) {
	netnsOnly(t)
	p := newPeer(t)
	nodeAddrs, peerAddrs := []string{"192.0.2.1/24"}, []string{"192.0.2.2/24", "192.0.2.3/24"}
	v6 := hasIPv6()
	if v6 {
		nodeAddrs = append(nodeAddrs, "2001:db8:1::1/48")
		peerAddrs = append(peerAddrs, "2001:db8:1::2/48", "2001:db8:1::3/48", "2001:db8:1:5::2/48")
	}
	link(t, p, "rc-in", nodeAddrs, peerAddrs)
	fw := &NFT{NflogGroup: 7, inDiv: 10}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	if err := fw.SetPublic([]Port{{"tcp", 18443}}); err != nil {
		t.Fatal(err)
	}
	if err := fw.SetAdmin([]netip.Prefix{netip.MustParsePrefix("192.0.2.3/32")}, []Port{{"tcp", 22}}); err != nil {
		t.Fatal(err)
	}
	if err := fw.Allow(netip.MustParseAddr("192.0.2.2"), []Port{{"udp", 18443}}, time.Minute); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":18443")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	pc, err := net.ListenPacket("udp", ":18443")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	node4 := netip.MustParseAddrPort("192.0.2.1:18443")

	// SYNs to a closed port: dropped by the input chain, never counted.
	synsFrom(t, p, netip.MustParseAddr("192.0.2.2"), netip.MustParseAddrPort("192.0.2.1:9999"), 150, 100*time.Millisecond)
	if n := inDrops(t, fw, "in_rate", "in-rate"); n != 0 {
		t.Fatalf("SYNs to a closed port counted: %d dropped", n)
	}
	// 150 to the open port: the burst of 100 passes, about 50 are dropped,
	// and the dropped leave no entry.
	before := ctCount(t)
	synsFrom(t, p, netip.MustParseAddr("192.0.2.2"), node4, 150, 300*time.Millisecond)
	dropped := inDrops(t, fw, "in_rate", "in-rate")
	if dropped < 40 || dropped > 50 {
		t.Fatalf("dropped %d of 150 SYNs, want ~50 (the burst 100 passes)", dropped)
	}
	if grew := ctCount(t) - before; grew > 150-int(dropped)+5 {
		t.Fatalf("entries grew by %d with %d SYNs dropped: dropped ones left entries", grew, dropped)
	}
	// The admin's address: not limited.
	synsFrom(t, p, netip.MustParseAddr("192.0.2.3"), node4, 150, 300*time.Millisecond)
	if n := inDrops(t, fw, "in_rate", "in-rate"); n != dropped {
		t.Fatalf("the admin's SYNs dropped: %d", n-dropped)
	}
	// UDP by grant: 30 new flows, the burst 20 passes.
	udpFrom(t, p, netip.MustParseAddr("192.0.2.2"), node4, 30)
	if n := inDrops(t, fw, "in_rate", "in-rate-udp"); n < 8 || n > 10 {
		t.Fatalf("UDP dropped %d of 30, want ~10", n)
	}
	// IPv6: two addresses of one /64 share its bucket of 100; another /64
	// of the same /48 has its own; the /48 has one.
	if v6 {
		inboundV6(t, p, fw, dropped)
	} else {
		t.Log("no IPv6 on this host (ipv6.disable=1?): the /64 and /48 keys are not run")
	}
	// Off: nothing limited.
	if err := fw.SetInLimit(false); err != nil {
		t.Fatal(err)
	}
	synsFrom(t, p, netip.MustParseAddr("192.0.2.2"), node4, 150, 300*time.Millisecond)
	if out, _ := exec.Command("nft", "list", "chain", "inet", Table, "in_rate").CombinedOutput(); strings.Contains(string(out), "drop") {
		t.Fatalf("off, still rules:\n%s", out)
	}
}

func hasIPv6() bool {
	_, err := os.Stat("/proc/sys/net/ipv6")
	return err == nil
}

func inboundV6(t *testing.T, p *peerNS, fw *NFT, dropped uint64) {
	t.Helper()
	node6 := netip.MustParseAddrPort("[2001:db8:1::1]:18443")
	synsFrom(t, p, netip.MustParseAddr("2001:db8:1::2"), node6, 60, 200*time.Millisecond)
	synsFrom(t, p, netip.MustParseAddr("2001:db8:1::3"), node6, 60, 200*time.Millisecond)
	synsFrom(t, p, netip.MustParseAddr("2001:db8:1:5::2"), node6, 60, 200*time.Millisecond)
	v6 := inDrops(t, fw, "in_rate", "in-rate") - dropped
	if v6 < 15 || v6 > 20 {
		t.Fatalf("IPv6: dropped %d of 180, want ~20 (one /64 over its 100)", v6)
	}
	for set, want := range map[string][]string{"in64": {"2001:db8:1::", "2001:db8:1:5::"}, "in48": {"2001:db8:1::"}} {
		out, err := exec.Command("nft", "list", "set", "inet", Table, set).CombinedOutput()
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range want {
			if !strings.Contains(string(out), w+" ") && !strings.Contains(string(out), w+" limit") {
				t.Errorf("%s lacks %s:\n%s", set, w, out)
			}
		}
		if set == "in48" && strings.Contains(string(out), "2001:db8:1:5::") {
			t.Errorf("in48 keyed finer than a /48:\n%s", out)
		}
	}
}

// TestNetnsInboundRateRelay: on a relay the per-address limit sits after
// the grant in relay_forward: a client without one spends nothing.
func TestNetnsInboundRateRelay(t *testing.T) {
	netnsOnly(t)
	client, exit := newPeer(t), newPeer(t)
	link(t, client, "rc-rc", []string{"198.51.100.1/24"}, []string{"198.51.100.2/24"})
	link(t, exit, "rc-re", []string{"203.0.113.1/24"}, []string{"203.0.113.2/24"})
	client.run(t, "ip", "route", "add", "default", "via", "198.51.100.1")
	exit.run(t, "ip", "route", "add", "default", "via", "203.0.113.1")
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	fw := &NFT{NflogGroup: 7, inDiv: 10, RelayTo: netip.MustParseAddr("203.0.113.2")}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	if err := fw.SetForward([]Port{{"tcp", 443}}); err != nil {
		t.Fatal(err)
	}
	exit.do(t, func() {
		ln, err := net.Listen("tcp", ":443")
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	})
	relay := netip.MustParseAddrPort("198.51.100.1:443")
	src := netip.MustParseAddr("198.51.100.2")
	// No grant: dropped as before, the bucket untouched.
	synsFrom(t, client, src, relay, 50, 200*time.Millisecond)
	if n := inDrops(t, fw, "relay_forward", "relay-no-grant"); n < 50 {
		t.Fatalf("without a grant: %d dropped", n)
	}
	if out, _ := exec.Command("nft", "list", "set", "inet", Table, "in4").CombinedOutput(); strings.Contains(string(out), "198.51.100.2") {
		t.Fatalf("a packet without a grant spent the bucket:\n%s", out)
	}
	if err := fw.Allow(src, []Port{{"tcp", 443}}, time.Minute); err != nil {
		t.Fatal(err)
	}
	synsFrom(t, client, src, relay, 150, 300*time.Millisecond)
	if n := inDrops(t, fw, "in_rate_fwd", "relay-in-rate"); n < 40 || n > 50 {
		t.Fatalf("through the relay: %d of 150 dropped, want ~50", n)
	}
	drops, err := fw.InboundDrops()
	if err != nil || drops["tcp"].Packets < 40 {
		t.Fatalf("InboundDrops %v %v", drops, err)
	}
}

// frontSocket is a UDP socket of the front (uid 9100) on port: it answers
// each query with the query.
func frontSocket(t *testing.T, port int) {
	t.Helper()
	fd, err := socketAs(frontUID, unix.AF_INET, unix.SOCK_DGRAM)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: port}); err != nil {
		t.Fatal(err)
	}
	// The file owns fd: closed once, through it (its finalizer would close
	// a reused number otherwise).
	f := os.NewFile(uintptr(fd), "front")
	pc, err := net.FilePacketConn(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], from)
		}
	}()
}

// TestNetnsNotrackDNS: queries to a DNS tunnel's port from many ports are
// answered and leave no entry; @public lets them in; the guard does not
// touch the front's answers; the stub on lo and the node's own queries
// are tracked as before.
func TestNetnsNotrackDNS(t *testing.T) {
	netnsOnly(t)
	p := newPeer(t)
	link(t, p, "rc-dn", []string{"192.0.2.1/24"}, []string{"192.0.2.2/24"})
	fw := &NFT{NflogGroup: 7}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	if err := fw.SetPublic([]Port{{"udp", 5353}}); err != nil {
		t.Fatal(err)
	}
	if err := fw.SetGuard(true); err != nil {
		t.Fatal(err)
	}
	frontSocket(t, 5353)
	answered := 0
	p.do(t, func() {
		for i := range 200 {
			c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:5353")))
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(time.Second))
			q := []byte(fmt.Sprintf("query %d", i))
			_, _ = c.Write(q)
			b := make([]byte, 64)
			if n, err := c.Read(b); err == nil && string(b[:n]) == string(q) {
				answered++
			}
			c.Close()
		}
	})
	if answered != 200 {
		t.Fatalf("%d of 200 queries answered", answered)
	}
	front := netip.MustParseAddrPort("192.0.2.1:5353")
	if e, ok := findEntry(append(entries(t, unix.AF_INET, false), entries(t, unix.AF_INET, true)...), func(e ctEntry) bool {
		return e.Orig.Dst == front || e.Orig.Src == front
	}); ok {
		t.Fatalf("an entry for the DNS port: %+v", e)
	}
	// The node's own query to a resolver's 53 (here 5353 at the peer): its
	// source port is not the tunnel's, it is tracked.
	p.do(t, func() {
		pc, err := net.ListenPacket("udp", "192.0.2.2:5353")
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { pc.Close() })
	})
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.2:5353")))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("own"))
	c.Close()
	// And the stub on lo.
	lc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:5353")))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = lc.Write([]byte("stub"))
	lc.Close()
	es := entries(t, unix.AF_INET, false)
	if _, ok := findEntry(es, func(e ctEntry) bool { return e.Orig.Dst == netip.MustParseAddrPort("192.0.2.2:5353") }); !ok {
		t.Error("the node's own query not tracked")
	}
	if _, ok := findEntry(es, func(e ctEntry) bool { return e.Orig.Dst == netip.MustParseAddrPort("127.0.0.1:5353") }); !ok {
		t.Error("the query on lo not tracked")
	}
}

// standIn makes a gate with the guard reading the real count against a
// stand-in max.
func standIn(t *testing.T, fw *NFT, max *uint64, now *time.Time) *Gate {
	t.Helper()
	g := NewGate(fw, quiet)
	g.now = func() time.Time { return *now }
	g.EnableGuard(&Guard{Read: func() (uint64, uint64, error) {
		c, _, err := ReadConntrackTable()
		return c, *max, err
	}, Refused: fw.GuardRefused})
	if err := g.Update(testSnapshot()); err != nil {
		t.Fatal(err)
	}
	return g
}

// TestNetnsConnGuard: a new data-plane flow gets the mark; with the guard
// off all passes; on, TCP gets ENETUNREACH and UDP EPERM, the refusals do
// not grow the table, lo and uid 0 pass; the named counter outlives the
// switches; after "flush ruleset" Tick brings the table and the guard
// back; on at 85 % of a stand-in max, off at 70 % after two minutes.
func TestNetnsConnGuard(t *testing.T) {
	netnsOnly(t)
	p := newPeer(t)
	link(t, p, "rc-gd", []string{"192.0.2.1/24"}, []string{"192.0.2.2/24"})
	p.do(t, func() {
		ln, err := net.Listen("tcp", ":8080")
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { time.Sleep(5 * time.Second); c.Close() }()
			}
		}()
	})
	fw := &NFT{NflogGroup: 7}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	now := time.Unix(1_700_000_000, 0)
	max := uint64(1 << 20)
	g := standIn(t, fw, &max, &now)
	tick := func(d time.Duration) {
		t.Helper()
		now = now.Add(d)
		if _, err := g.Tick(); err != nil {
			t.Fatal(err)
		}
	}
	peer := [4]byte{192, 0, 2, 2}
	tick(time.Second)
	if err := dialAs(9150, peer, 8080); err != nil {
		t.Fatalf("guard off, the data plane: %v", err)
	}
	if _, ok := findEntry(entries(t, unix.AF_INET, true), func(e ctEntry) bool {
		return e.Orig.Dst == netip.MustParseAddrPort("192.0.2.2:8080")
	}); !ok {
		t.Fatal("no mark on the data plane's flow")
	}
	// On: 85 % of the stand-in.
	count := uint64(ctCount(t))
	max = count * 100 / 85
	tick(time.Second)
	if !g.GuardOn() {
		t.Fatalf("not on at %d of %d", count, max)
	}
	before := ctCount(t)
	if err := dialAs(9150, peer, 8080); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("TCP of the data plane: %v, want ENETUNREACH", err)
	}
	if err := sendUDPAs(9150, peer, 9999); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("UDP of the data plane: %v, want EPERM", err)
	}
	if grew := ctCount(t) - before; grew > 0 {
		t.Fatalf("the refusals grew the table by %d", grew)
	}
	if err := dialAs(0, peer, 8080); err != nil {
		t.Fatalf("uid 0 refused: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := dialAs(9150, [4]byte{127, 0, 0, 1}, 18080); err != nil {
		t.Fatalf("lo refused: %v", err)
	}
	refused, err := fw.GuardRefused()
	if err != nil || refused < 2 {
		t.Fatalf("the counter: %d %v", refused, err)
	}
	// "flush ruleset": the table and the guard come back with the tick.
	if out, err := exec.Command("nft", "flush", "ruleset").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	tick(time.Second)
	if err := dialAs(9150, peer, 8080); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("after a restore: %v, want ENETUNREACH", err)
	}
	// The counter outlives the switches (a restore makes a new one).
	for _, on := range []bool{false, true} {
		if err := fw.SetGuard(on); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := fw.GuardRefused()
	if after < 1 {
		t.Fatalf("the counter after the switches: %d", after)
	}
	// Off: 70 % and two minutes.
	max = uint64(ctCount(t))*100/70 + 10
	tick(time.Minute)
	if !g.GuardOn() {
		t.Fatal("off within two minutes")
	}
	tick(time.Minute)
	if g.GuardOn() {
		t.Fatal("not off at 70 % after two minutes")
	}
	if err := dialAs(9150, peer, 8080); err != nil {
		rs, _ := exec.Command("nft", "list", "ruleset").CombinedOutput()
		ct, _ := exec.Command("conntrack", "-L").CombinedOutput()
		ad, _ := exec.Command("ip", "addr").CombinedOutput()
		ss, _ := exec.Command("nsenter", "-t", strconv.Itoa(p.cmd.Process.Pid), "-n", "ss", "-tanp").CombinedOutput()
		t.Fatalf("guard off again: %v\n%s\n%s\n%s\n%s", err, rs, ct, ad, ss)
	}
}

// TestNetnsGuardSweep: the sweep removes the entries a far end keeps alive
// after the connection ended (UDP, TCP out, TCP in), keeps live sockets'
// entries, a socket's TIME_WAIT and NATed ones.
func TestNetnsGuardSweep(t *testing.T) {
	netnsOnly(t)
	p := newPeer(t)
	link(t, p, "rc-sw", []string{"192.0.2.1/24"}, []string{"192.0.2.2/24"})
	// The far end does not hear resets.
	p.run(t, "nft", "add", "table", "inet", "t")
	p.run(t, "nft", "add", "chain", "inet", "t", "in", "{ type filter hook input priority 0; }")
	p.run(t, "nft", "add", "rule", "inet", "t", "in", "tcp flags rst drop")
	// What earlier tests in this namespace left goes first.
	if _, err := (&Sweeper{}).Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	fw := &NFT{NflogGroup: 7}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	if err := fw.SetPublic([]Port{{"tcp", 443}}); err != nil {
		t.Fatal(err)
	}
	if err := fw.SetACME(18080, time.Minute); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	keepAlive := net.KeepAliveConfig{Enable: true, Idle: time.Second, Interval: time.Second, Count: 100}

	// The peer: a TCP listener that keeps what it accepts alive, and a
	// UDP socket that answers and keeps sending to whoever spoke last.
	var udpPeer *net.UDPConn
	p.do(t, func() {
		lc := net.ListenConfig{KeepAliveConfig: keepAlive}
		ln, err := lc.Listen(ctx, "tcp", ":8080")
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { <-ctx.Done(); c.Close() }()
			}
		}()
		udpPeer, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.2:7000")))
		if err != nil {
			t.Error(err)
		}
	})
	defer udpPeer.Close()
	go func() {
		b := make([]byte, 64)
		var last *net.UDPAddr
		for ctx.Err() == nil {
			_ = udpPeer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, from, err := udpPeer.ReadFromUDP(b); err == nil {
				last = from
			}
			if last != nil {
				_, _ = udpPeer.WriteToUDP([]byte("still here"), last)
			}
		}
	}()
	// The node's listeners: 443, and 18080 behind ACME's redirect.
	nodeListen := func(port int) {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				// Closed with a reset at once: the far end keeps it alive.
				_ = c.(*net.TCPConn).SetLinger(0)
				c.Close()
			}
		}()
	}
	nodeListen(443)
	nodeListen(18080)

	peer := netip.MustParseAddrPort("192.0.2.2:8080")
	// Outbound UDP of the data plane: one socket closed (orphan), one live.
	udpAs := func() (*net.UDPConn, netip.AddrPort) {
		fd, err := socketAs(9150, unix.AF_INET, unix.SOCK_DGRAM)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Connect(fd, &unix.SockaddrInet4{Port: 7000, Addr: [4]byte{192, 0, 2, 2}}); err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(fd), "udp")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("hi"))
		return c.(*net.UDPConn), c.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	gone, goneAt := udpAs()
	gone.Close()
	live, liveAt := udpAs()
	defer live.Close()
	// Outbound TCP of the data plane: one reset (orphan), one closed first
	// by the node (its socket in TIME_WAIT).
	tcpAs := func() net.Conn {
		c, err := connAs(9150, peer)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	reset := tcpAs()
	resetAt := reset.LocalAddr().(*net.TCPAddr).AddrPort()
	_ = reset.(*net.TCPConn).SetLinger(0)
	reset.Close()
	tw := tcpAs()
	twAt := tw.LocalAddr().(*net.TCPAddr).AddrPort()
	tw.Close()
	// Inbound TCP to 443, and to 80 (redirected): reset by the node, kept
	// alive by the peer.
	var in443, in80 netip.AddrPort
	p.do(t, func() {
		d := net.Dialer{KeepAliveConfig: keepAlive}
		for _, port := range []uint16{443, 80} {
			c, err := d.Dial("tcp", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port).String())
			if err != nil {
				t.Error(err)
				return
			}
			t.Cleanup(func() { c.Close() })
			at := c.LocalAddr().(*net.TCPAddr).AddrPort()
			if port == 443 {
				in443 = at
			} else {
				in80 = at
			}
		}
	})
	// Long past the 10 s of CLOSE: the far ends keep them.
	time.Sleep(12 * time.Second)
	has := func(es []ctEntry, local netip.AddrPort) bool {
		_, ok := findEntry(es, func(e ctEntry) bool {
			return unmapAP(e.Orig.Src) == local || unmapAP(e.Orig.Dst) == local && e.Orig.Src.Port() != 0
		})
		return ok
	}
	byPeerPort := func(es []ctEntry, from netip.AddrPort) bool {
		_, ok := findEntry(es, func(e ctEntry) bool { return unmapAP(e.Orig.Src) == from })
		return ok
	}
	marked, unmarked := entries(t, unix.AF_INET, true), entries(t, unix.AF_INET, false)
	for name, ok := range map[string]bool{
		"udp orphan": has(marked, goneAt), "udp live": has(marked, liveAt), "tcp reset": has(marked, resetAt),
		"tcp time_wait": has(marked, twAt), "in 443": byPeerPort(unmarked, in443), "in 80 (dnat)": byPeerPort(unmarked, in80),
	} {
		if !ok {
			t.Fatalf("before the sweep: no entry for %s", name)
		}
	}
	orphan443, _ := findEntry(unmarked, func(e ctEntry) bool { return unmapAP(e.Orig.Src) == in443 })
	r, err := (&Sweeper{}).Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Earlier tests in this namespace may have left orphans of their own
	// since the first sweep: at least these.
	if r.UDP < 1 || r.TCPOut < 1 || r.TCPIn < 1 {
		t.Fatalf("swept %+v, want one of each at least", r)
	}
	// The inbound orphan, by its ID: the far end's next probe may make a
	// new entry of the same tuple for a moment (reset at once, not ASSURED).
	if _, ok := findEntry(entries(t, unix.AF_INET, false), func(e ctEntry) bool { return e.ID == orphan443.ID }); ok {
		t.Error("the inbound orphan left")
	}
	marked, unmarked = entries(t, unix.AF_INET, true), entries(t, unix.AF_INET, false)
	if has(marked, goneAt) || has(marked, resetAt) {
		t.Error("an orphan of the data plane left")
	}
	if !has(marked, liveAt) {
		ct, _ := exec.Command("conntrack", "-L").CombinedOutput()
		t.Errorf("a live socket's entry swept (%v), swept %+v: %+v\n%s", liveAt, r, marked, ct)
	}
	if !has(marked, twAt) {
		t.Errorf("a closed socket's entry swept (%v): %+v", twAt, marked)
	}
	if !byPeerPort(unmarked, in80) {
		t.Error("the redirected (dnat) entry swept")
	}
}
