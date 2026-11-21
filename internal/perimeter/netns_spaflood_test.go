//go:build linux

package perimeter

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// TestNetnsSPARate: SPA packets are limited per IPv4 address and per IPv6
// /64 whatever the addresses inside it (S-8, protocol review 2026-11); not
// per /48, whose /64s each have their own. Root under unshare -n, as
// TestNetns; the IPv6 parts where the kernel has IPv6.
func TestNetnsSPARate(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	loUp(t)
	// IPv6 sources: 20 addresses of one /64; one address in each of 20 /64s
	// of another /48.
	v6 := hasIPv6()
	var one64, one48 []netip.Addr
	if v6 {
		var batch strings.Builder
		for i := 1; i <= 20; i++ {
			a := netip.MustParseAddr(fmt.Sprintf("2001:db8:1:1::%x", i))
			b := netip.MustParseAddr(fmt.Sprintf("2001:db8:2:%x::1", i))
			one64, one48 = append(one64, a), append(one48, b)
			fmt.Fprintf(&batch, "addr add %s/128 dev lo nodad\naddr add %s/128 dev lo nodad\n", a, b)
		}
		cmd := exec.Command("ip", "-batch", "-")
		cmd.Stdin = strings.NewReader(batch.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ip: %v: %s", err, out)
		}
	}

	const rate = 2 // an address or a /64: 2/s, burst 4
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ReadNFLOG(ctx, 8, func(_, _ netip.Addr, _ []byte) {}, quiet) }()
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
	// What the rules dropped is in their counters: NFLOG loses packets of a
	// burst on its own.
	dropped := func(f func()) uint64 {
		before := inDrops(t, fw, "input", "spa-rate")
		f()
		time.Sleep(200 * time.Millisecond)
		return inDrops(t, fw, "input", "spa-rate") - before
	}
	if d := dropped(func() { send([]netip.Addr{netip.MustParseAddr("127.1.0.1")}, 40) }); d < 40-4-2*rate || d > 40-4 {
		t.Fatalf("one IPv4 address sent 40: %d dropped, want 36 (its burst 4 through)", d)
	}
	// Other addresses each have their own.
	var many4 []netip.Addr
	for i := 1; i <= 20; i++ {
		many4 = append(many4, netip.AddrFrom4([4]byte{127, 2, byte(i), 1}))
	}
	if d := dropped(func() { send(many4, 4) }); d != 0 {
		t.Fatalf("20 IPv4 addresses within their bursts: %d dropped", d)
	}
	if !v6 {
		t.Log("no IPv6 on this host (ipv6.disable=1?): the /64 and /48 keys are not run")
		return
	}
	if d := dropped(func() { send(one64, 4) }); d < 80-4-2*rate || d > 80-4 {
		t.Fatalf("one /64 sent 80 from 20 addresses: %d dropped, want 76 (its burst 4 through)", d)
	}
	// 20 /64s of one /48, 4 each within their own: none dropped.
	if d := dropped(func() { send(one48, 4) }); d != 0 {
		t.Fatalf("one /48 sent 80 from 20 /64s within their bursts: %d dropped", d)
	}
}
