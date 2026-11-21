package perimeter

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// TestNetnsSPAFlood: SPA packets reach rayspa at the rate of one IPv6 /64,
// whatever the addresses inside it, and of all sources at once at most the
// ceiling's, which also holds when the per-source sets cannot keep up
// (S-8, protocol review 2026-11). Root under unshare -n, as TestNetns.
func TestNetnsSPAFlood(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	loUp(t)
	// Sources: one address in each of 150 IPv4 /24s of 127/8, which needs
	// no setup; with IPv6, 20 addresses of one /64.
	var many4, one64 []netip.Addr
	for i := 1; i <= 150; i++ {
		many4 = append(many4, netip.AddrFrom4([4]byte{127, 1, byte(i), 1}))
	}
	v6 := hasIPv6()
	if v6 {
		var batch strings.Builder
		for i := 1; i <= 20; i++ {
			a := netip.MustParseAddr(fmt.Sprintf("2001:db8:1:1::%x", i))
			one64 = append(one64, a)
			fmt.Fprintf(&batch, "addr add %s/128 dev lo nodad\n", a)
		}
		cmd := exec.Command("ip", "-batch", "-")
		cmd.Stdin = strings.NewReader(batch.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ip: %v: %s", err, out)
		}
	}

	const rate = 2 // a /64: 2/s, burst 4; a /48: 8/s, burst 16; all: 100/s, burst 200
	fw := &NFT{NflogGroup: 8, FilterLoopback: true, RateLimit: rate}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	gate := NewGate(fw, quiet)
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}})
	if err := gate.Update(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Tick(); err != nil {
		t.Fatal(err)
	}
	var got atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ReadNFLOG(ctx, 8, func(_, _ netip.Addr, _ []byte) { got.Add(1) }, quiet) }()
	time.Sleep(300 * time.Millisecond) // NFLOG subscription

	params, _ := paramsOf(snap.Spa)
	port := int(params.Port(params.Slot(time.Now())))
	junk := make([]byte, 120)
	send := func(from []netip.Addr, each int) {
		for _, a := range from {
			dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
			if a.Is6() {
				dst.IP = net.IPv6loopback
			}
			c, err := net.DialUDP("udp", &net.UDPAddr{IP: a.AsSlice()}, dst)
			if err != nil {
				t.Fatal(err)
			}
			for range each {
				c.Write(junk)
			}
			c.Close()
		}
	}
	settle := func() int64 {
		time.Sleep(500 * time.Millisecond)
		return got.Swap(0)
	}

	// Each source passes its own burst, 4; together the ceiling's.
	// NFLOG loses packets of a flood on its own: what the rules did is in
	// their counters.
	send(many4, 4)
	n := settle()
	ceiling, perSource := inDrops(t, fw, "input", "spa-ceiling"), inDrops(t, fw, "input", "spa-rate")
	t.Logf("150 sources, 600 packets: the ceiling dropped %d, the sources' limits %d, %d reached rayspa", ceiling, perSource, n)
	if n == 0 || perSource != 0 || ceiling < 600-200-100 || ceiling > 600-200 {
		t.Fatalf("150 sources sent 600 packets within their own bursts: the ceiling dropped %d, want ~400 (its burst 200 through)", ceiling)
	}
	if !v6 {
		t.Log("no IPv6 on this host (ipv6.disable=1?): the /64 key is not run")
		return
	}
	// The ceiling refills at 100/s: wait it full again.
	time.Sleep(2500 * time.Millisecond)
	got.Store(0)
	// One /64: its burst, not 20 bursts of /128s.
	before := inDrops(t, fw, "input", "spa-rate")
	send(one64, 4)
	settle()
	if d := inDrops(t, fw, "input", "spa-rate") - before; d < 80-4-2*rate || d > 80-4 {
		t.Fatalf("one /64 sent 80 packets: its limit dropped %d, want 76 (its burst 4 through)", d)
	}
}
