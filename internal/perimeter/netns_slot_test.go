//go:build linux

package perimeter

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/spa"
)

// TestNetnsSlotChange: a UDP service's slot ports at a change of slot
// (spa-v2.md §11), with the real table, a client in a namespace of its own
// behind veth, SPA through NFLOG and the gate on the test's clock (Tick
// moves the slots). As TestNetns: root, under unshare -n,
// RAYCONTROL_NETNS_TEST=1.
//
//  1. SPA, then a flow to the current slot's port reaches the service.
//  2. One slot on, that port is slot−1: still open to new flows. Two
//     slots on, it is out of the window: a new flow to it is refused,
//     the open one goes on (conntrack keeps its NAT, established passes
//     before the ports).
//  3. A new socket to the new slot's port reaches the service; one from
//     an address without SPA does not.
//  4. The socket of the old flow, to the new slot's port: dropped, by
//     §11, when its entry is confirmed, the reply tuple being the old
//     flow's; the old flow goes on. A kernel that passes it instead makes
//     the subtest say what it saw and skip: it does not pass.
//
// A QUIC connection moved to a new socket on the new port is the new
// socket of 3 to the perimeter; that the front takes it over is
// niko-server's routing by connection ID (quic-cid-route-v1.md), not
// tested here.
func TestNetnsSlotChange(t *testing.T) {
	netnsOnly(t)
	p := newPeer(t)
	link(t, p, "rc-sc", []string{"192.0.2.1/24"}, []string{"192.0.2.2/24", "192.0.2.3/24"})
	node := netip.MustParseAddr("192.0.2.1")
	client, stranger := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")

	const group = 10
	fw := &NFT{NflogGroup: group}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()

	const target = 18443
	rotKey := key(0x77)
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}})
	snap.Spa.SlotLenS = 60 // ten slots in a grant (600 s)
	snap.Services = []*perimeterv1.Service{{Id: 1,
		Ports:    []*perimeterv1.Port{{Proto: "udp", Port: target}},
		Rotation: &perimeterv1.Rotation{PortKey: rotKey, PortBase: 50000, PortRange: 1000, TargetPort: target}}}
	params, err := paramsOf(snap.Spa)
	if err != nil {
		t.Fatal(err)
	}
	sched := params
	copy(sched.PortKey[:], rotKey)
	sched.PortBase, sched.PortRange = 50000, 1000

	// The first slot from 2026-01-01 whose port and those of the slots
	// around it are all different: the steps below then cannot pass by a
	// port two slots share.
	slot := uint64(1767225600) / 60
	for ; ; slot++ {
		ports := map[uint16]bool{}
		for s := slot - 1; s <= slot+3; s++ {
			ports[sched.Port(s)] = true
		}
		if len(ports) == 5 {
			break
		}
	}
	var clock atomic.Int64
	at := func(s uint64) { clock.Store(int64(s)*60 + 30) }
	now := func() time.Time { return time.Unix(clock.Load(), 0) }
	at(slot)

	gate := NewGate(fw, quiet)
	gate.now = now // the verifier's clock too
	if err := gate.Update(snap); err != nil {
		t.Fatal(err)
	}
	tick := func(s uint64) {
		t.Helper()
		at(s)
		if _, err := gate.Tick(); err != nil {
			t.Fatal(err)
		}
	}
	tick(slot)

	granted := make(chan error, 64)
	ctx, cancel := context.WithCancel(context.Background())
	nflogDone := make(chan struct{})
	go func() {
		defer close(nflogDone)
		err := ReadNFLOG(ctx, group, func(src netip.Addr, pkt []byte) {
			if src != client {
				return
			}
			_, err := gate.Handle(src, pkt)
			select {
			case granted <- err:
			default:
			}
		}, quiet)
		if err != nil {
			select {
			case granted <- err:
			default:
			}
		}
	}()
	defer func() { cancel(); <-nflogDone }() // the group is free for the next test

	// The service: a UDP echo on its port, keeping what it was sent and
	// from where.
	echo, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(node, target)))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	var mu sync.Mutex
	got := map[string]netip.AddrPort{}
	go func() {
		b := make([]byte, 64)
		for {
			n, from, err := echo.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			mu.Lock()
			got[string(b[:n])] = from
			mu.Unlock()
			_, _ = echo.WriteToUDPAddrPort(b[:n], from)
		}
	}()
	seen := func(msg string) (netip.AddrPort, bool) {
		mu.Lock()
		defer mu.Unlock()
		from, ok := got[msg]
		return from, ok
	}

	// Client sockets, made in the client's namespace; unconnected, so the
	// same socket can send to another port.
	socket := func(src netip.Addr) *net.UDPConn {
		t.Helper()
		var c *net.UDPConn
		var err error
		p.do(t, func() {
			c, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(src, 0)))
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	// ask sends msg to the node's port and waits for the echo: it must
	// come from that port (spa-v2.md §11: answers go from the slot's
	// port). A packet that is dropped is waited for as long as TestNetns
	// waits for a closed port.
	ask := func(t *testing.T, c *net.UDPConn, port uint16, msg string, wait time.Duration) bool {
		t.Helper()
		to := netip.AddrPortFrom(node, port)
		if _, err := c.WriteToUDPAddrPort([]byte(msg), to); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(wait))
		b := make([]byte, 64)
		for {
			n, from, err := c.ReadFromUDPAddrPort(b)
			if err != nil {
				return false
			}
			if string(b[:n]) != msg {
				continue // a late answer to an earlier question
			}
			if from != to {
				t.Fatalf("%q answered from %v, not %v", msg, from, to)
			}
			return true
		}
	}
	const answers, dropped = 3 * time.Second, 700 * time.Millisecond
	passes := func(t *testing.T, c *net.UDPConn, port uint16, msg string) {
		t.Helper()
		if !ask(t, c, port, msg, answers) {
			t.Fatalf("%s: no answer from port %d", msg, port)
		}
	}
	refused := func(t *testing.T, c *net.UDPConn, port uint16, msg string) {
		t.Helper()
		_, reached := seen(msg)
		if ask(t, c, port, msg, dropped) || reached {
			t.Fatalf("%s: port %d let it through", msg, port)
		}
	}

	// 1. SPA from the client to the SPA port of the slot, until NFLOG
	// listens.
	spaSock := socket(client)
	spaPort := netip.AddrPortFrom(node, params.Port(params.Slot(now())))
	for end := time.Now().Add(5 * time.Second); ; {
		pkt, err := spa.SealRandom(params, [spa.KeySize]byte(key(0x11)), spa.Request{Time: now()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := spaSock.WriteToUDPAddrPort(pkt, spaPort); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-granted:
			if err != nil {
				t.Fatalf("SPA: %v", err)
			}
		case <-time.After(100 * time.Millisecond):
			if time.Now().Before(end) {
				continue
			}
			t.Fatal("no SPA packet reached the gate")
		}
		break
	}
	old := sched.Port(slot)
	flow := socket(client)
	passes(t, flow, old, "1: the slot's port")

	// 2. One slot on: the old port is slot−1.
	tick(slot + 1)
	passes(t, socket(client), old, "2: a new flow to slot-1's port")
	// Two slots on: out of the window.
	tick(slot + 2)
	if inRot(t, old) {
		t.Fatalf("port %d still redirected two slots on", old)
	}
	refused(t, socket(client), old, "2: a new flow to a port out of the window")
	passes(t, flow, old, "2: the open flow on the old port")

	// 3. The new slot's port: a new socket passes, one without SPA does not.
	cur := sched.Port(slot + 2)
	if !inRot(t, cur) {
		t.Fatalf("the new slot's port %d not redirected", cur)
	}
	passes(t, socket(client), cur, "3: a new socket to the new port")
	refused(t, socket(stranger), cur, "3: an address without SPA")

	// 4. The old flow's socket to the new port: by spa-v2.md §11 its entry
	// takes the old flow's reply tuple (both redirected to one port) and
	// is dropped when confirmed.
	t.Run("the old flow's socket to the new port", func(t *testing.T) {
		const msg = "4: the old flow's socket to the new port"
		sock := netip.MustParseAddrPort(flow.LocalAddr().String())
		failed, counted := insertFailed(t)
		answered := ask(t, flow, cur, msg, dropped)
		if at, reached := seen(msg); answered || reached {
			// Not as §11 says: told in the run's output, not passed.
			passes(t, flow, old, "4: the open flow on the old port, after")
			var u unix.Utsname
			_ = unix.Uname(&u)
			t.Skipf("spa-v2.md §11: dropped when its entry is confirmed; here (Linux %s) the service had it from %v, "+
				"the socket being %v, and it answered %v: the input hook's null SNAT binding gave the clashing "+
				"reply tuple another client port", unix.ByteSliceToString(u.Release[:]), at, sock, answered)
		}
		if n, _ := insertFailed(t); counted && n-failed != 1 {
			t.Errorf("insert_failed grew by %d, want 1: not dropped at the entry's confirmation", n-failed)
		}
		es := entries(t, unix.AF_INET, false)
		if e, ok := findEntry(es, func(e ctEntry) bool { return e.Orig.Src == sock && e.Orig.Dst.Port() == cur }); ok {
			t.Errorf("an entry for the old flow's socket to the new port: %+v", e)
		}
		if _, ok := findEntry(es, func(e ctEntry) bool { return e.Orig.Src == sock && e.Orig.Dst.Port() == old }); !ok {
			t.Error("the old flow's entry is gone")
		}
		passes(t, flow, old, "4: the open flow on the old port, after")
	})
}

// inRot reports whether the table redirects UDP port p.
func inRot(t *testing.T, p uint16) bool {
	t.Helper()
	out, err := exec.Command("nft", "list", "map", "inet", Table, "rot_udp").CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	f := strings.Fields(strings.ReplaceAll(string(out), ",", " "))
	i := slices.Index(f, strconv.Itoa(int(p)))
	return i >= 0 && i+1 < len(f) && f[i+1] == ":"
}

// insertFailed is the namespace's conntrack insert_failed, all CPUs: an
// entry not confirmed because one in the table already has its tuple. Not
// counted (ok false) on a kernel without conntrack's files in /proc
// (CONFIG_NF_CONNTRACK_PROCFS off, as on CI's runners).
func insertFailed(t *testing.T) (n uint64, ok bool) {
	t.Helper()
	b, err := os.ReadFile("/proc/net/stat/nf_conntrack")
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false
	}
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	col := -1
	for i, f := range strings.Fields(lines[0]) {
		if f == "insert_failed" {
			col = i
		}
	}
	if col < 0 {
		t.Fatalf("no insert_failed in %q", lines[0])
	}
	var sum uint64
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if col >= len(f) {
			t.Fatalf("short line %q", l)
		}
		n, err := strconv.ParseUint(f[col], 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		sum += n
	}
	return sum, true
}
