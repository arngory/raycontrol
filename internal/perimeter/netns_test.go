package perimeter

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/arngory/raycontrol/internal/dnscheck"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/spa"
)

// TestNetns runs the real perimeter: nftables, NFLOG and the TCP carrier.
// It must run as root in a fresh network namespace, e.g.
//
//	go test -c -o perimeter.test ./internal/perimeter
//	sudo RAYCONTROL_NETNS_TEST=1 unshare -n ./perimeter.test -test.run TestNetns -test.v
//
// All traffic there is loopback, so the table is installed with
// FilterLoopback to put lo under the same rules as a real interface.
func TestNetns(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	loUp(t)

	fw := &NFT{NflogGroup: 7, FilterLoopback: true}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	t.Logf("destroy element supported: %v", fw.destroy)

	gate := NewGate(fw, quiet)
	alice := &perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1}}
	snap := testSnapshot(alice)
	snap.Services = []*perimeterv1.Service{{Id: 1, Ports: []*perimeterv1.Port{{Proto: "tcp", Port: 18443}}}}
	snap.PublicPorts = []*perimeterv1.Port{{Proto: "udp", Port: 15353}}
	if err := gate.Update(snap); err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 16)
	handle := func(src netip.Addr, pkt []byte) {
		_, err := gate.Handle(src, pkt)
		results <- err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := ReadNFLOG(ctx, 7, handle, quiet); err != nil {
			results <- err
		}
	}()
	carrier := &TCPCarrier{Handler: handle, LenMax: gate.LenMax, Log: quiet}
	defer carrier.Close()
	ports, err := gate.Tick()
	if err != nil {
		t.Fatal(err)
	}
	carrier.Reconcile(ports)
	time.Sleep(300 * time.Millisecond) // NFLOG subscription

	service, err := net.Listen("tcp", "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	go func() {
		for {
			c, err := service.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	public, err := net.ListenPacket("udp", "127.0.0.1:15353")
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			n, a, err := public.ReadFrom(buf)
			if err != nil {
				return
			}
			public.WriteTo(buf[:n], a)
		}
	}()

	reach := func() bool {
		c, err := net.DialTimeout("tcp", "127.0.0.1:18443", 700*time.Millisecond)
		if err == nil {
			c.Close()
		}
		return err == nil
	}
	params, _ := paramsOf(snap.Spa)
	slotPort := func() string { return strconv.Itoa(int(params.Port(params.Slot(time.Now())))) }
	sendUDP := func(pkt []byte) {
		c, err := net.Dial("udp", "127.0.0.1:"+slotPort())
		if err != nil {
			t.Fatal(err)
		}
		c.Write(pkt)
		c.Close()
	}
	waitResult := func(want error) {
		t.Helper()
		select {
		case err := <-results:
			if !errors.Is(err, want) {
				t.Fatalf("spa result %v, want %v", err, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no spa packet reached rayspa")
		}
	}
	sealNow := func() []byte {
		pkt, err := spa.SealRandom(params, [spa.KeySize]byte(key(0x11)), spa.Request{Time: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return pkt
	}

	t.Run("closed before SPA", func(t *testing.T) {
		if reach() {
			t.Fatal("service port open without SPA")
		}
	})
	t.Run("public port open", func(t *testing.T) {
		c, err := net.Dial("udp", "127.0.0.1:15353")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("ping"))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8)
		if n, err := c.Read(buf); err != nil || string(buf[:n]) != "ping" {
			t.Fatalf("public udp: %q %v", buf[:n], err)
		}
	})

	t.Run("IP options and fragments dropped before reassembly", func(t *testing.T) {
		rx, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer rx.Close()
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		// Locally sent fragments would wait in the output defragmenter (NAT
		// in the test loads conntrack); a remote one meets the early chain
		// first, which this makes the test see too.
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_NODEFRAG, 1); err != nil {
			t.Fatal(err)
		}
		src := uint16(rx.LocalAddr().(*net.UDPAddr).Port)
		// send writes a UDP datagram to the public echo port by hand: IPv4
		// options and the fragment field as given.
		send := func(options []byte, frag uint16) {
			udp := []byte{0, 0, 0x3b, 0xf9, 0, 12, 0, 0, 'p', 'i', 'n', 'g'} // to 15353, no checksum
			binary.BigEndian.PutUint16(udp, src)
			ip := make([]byte, 20+len(options))
			ip[0], ip[8], ip[9] = 0x40|byte(len(ip)/4), 64, unix.IPPROTO_UDP
			binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(udp)))
			binary.BigEndian.PutUint16(ip[6:], frag)
			copy(ip[12:], []byte{127, 0, 0, 1, 127, 0, 0, 1})
			copy(ip[20:], options)
			if err := unix.Sendto(fd, append(ip, udp...), 0, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
				t.Fatal(err)
			}
		}
		answered := func() bool {
			buf := make([]byte, 16)
			rx.SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := rx.ReadFrom(buf)
			return err == nil && string(buf[:n]) == "ping"
		}
		send(nil, 0)
		if !answered() {
			t.Fatal("a plain datagram got no answer")
		}
		send([]byte{1, 1, 1, 0}, 0) // NOP NOP NOP, end of options
		if answered() {
			t.Fatal("a datagram with IPv4 options got through")
		}
		send(nil, 0x2000) // more fragments: the first of two
		answered()
		out, err := exec.Command("nft", "list", "chain", "inet", Table, "early").Output()
		if err != nil {
			t.Fatal(err)
		}
		// nft versions print the fragment test as "!= 0" or "!= 0x0".
		for _, rule := range []string{`ip hdrlength != 5`, `ip frag-off & 0x3fff != 0(?:x0)?`} {
			m := regexp.MustCompile(rule + ` counter packets (\d+)`).FindSubmatch(out)
			if m == nil || string(m[1]) == "0" {
				t.Errorf("%q dropped nothing:\n%s", rule, out)
			}
		}
		drops, err := fw.EarlyDrops()
		if err != nil {
			t.Fatal(err)
		}
		for _, reason := range []string{"ipv4-options", "ipv4-fragment"} {
			if drops[reason].Packets == 0 || drops[reason].Bytes == 0 {
				t.Errorf("EarlyDrops: %s = %+v (%v)", reason, drops[reason], drops)
			}
		}
	})

	udpPkt := sealNow()
	t.Run("UDP SPA opens the service", func(t *testing.T) {
		start := time.Now()
		sendUDP(udpPkt)
		waitResult(nil)
		// A client connects 150-400 ms after SPA (spa-v2.md §7).
		if d := time.Since(start); d > 150*time.Millisecond {
			t.Fatalf("grant took %v", d)
		}
		if !reach() {
			t.Fatal("service still closed after SPA")
		}
	})
	t.Run("replay rejected", func(t *testing.T) {
		sendUDP(udpPkt)
		waitResult(spa.ErrReplay)
	})
	t.Run("revocation closes", func(t *testing.T) {
		snap.Devices = nil
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		if reach() {
			t.Fatal("service open after revocation")
		}
	})
	t.Run("TCP carrier opens the service", func(t *testing.T) {
		snap.Devices = []*perimeterv1.Device{alice}
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("tcp", "127.0.0.1:"+slotPort())
		if err != nil {
			t.Fatal(err)
		}
		pkt := sealNow()
		c.Write(pkt[:7])
		c.Write(pkt[7:])
		c.Close()
		waitResult(nil)
		if !reach() {
			t.Fatal("service closed after TCP SPA")
		}
	})
	t.Run("TCP carrier as a TLS ClientHello opens the service", func(t *testing.T) {
		// spa-v2.md §10.1 (RAYCONTROL.md §22.2.3).
		snap.Devices = []*perimeterv1.Device{alice}
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("tcp", "127.0.0.1:"+slotPort())
		if err != nil {
			t.Fatal(err)
		}
		rec, err := spa.TLSCarrier(sealNow())
		if err != nil {
			t.Fatal(err)
		}
		c.Write(rec)
		c.Close()
		waitResult(nil)
		if !reach() {
			t.Fatal("service closed after the ClientHello carrier")
		}
	})
	t.Run("admin prefix reaches SSH without SPA", func(t *testing.T) {
		ssh, err := net.Listen("tcp", "127.0.0.1:18022")
		if err != nil {
			t.Fatal(err)
		}
		defer ssh.Close()
		go func() {
			for {
				c, err := ssh.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		dial := func() bool {
			c, err := net.DialTimeout("tcp", "127.0.0.1:18022", 700*time.Millisecond)
			if err == nil {
				c.Close()
			}
			return err == nil
		}
		if dial() {
			t.Fatal("ssh open before admin access")
		}
		snap.AdminPrefixes = []string{"127.0.0.0/8", "127.0.0.1/32"} // overlapping: merged for the interval set
		snap.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 18022}}
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		if !dial() {
			t.Fatal("admin prefix cannot reach ssh")
		}
		snap.AdminPrefixes = []string{"198.51.100.0/24"}
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		if dial() {
			t.Fatal("ssh open for a foreign admin prefix")
		}
	})
	t.Run("a relay's address reaches the relay ports without SPA, not SSH", func(t *testing.T) {
		// relay-v1 §3: devices knock at the relay; this node lets the
		// relay's address in on the service ports only.
		svc, err := net.Listen("tcp", "127.0.0.1:18444")
		if err != nil {
			t.Fatal(err)
		}
		defer svc.Close()
		ssh, err := net.Listen("tcp", "127.0.0.1:18023")
		if err != nil {
			t.Fatal(err)
		}
		defer ssh.Close()
		for _, l := range []net.Listener{svc, ssh} {
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					c.Close()
				}
			}()
		}
		dial := func(port string) bool {
			c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 700*time.Millisecond)
			if err == nil {
				c.Close()
			}
			return err == nil
		}
		if dial("18444") {
			t.Fatal("service open before the relay")
		}
		snap.RelayPrefixes = []string{"127.0.0.1/32"}
		snap.RelayPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 18444}}
		snap.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: 18023}}
		snap.AdminPrefixes = nil
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		if !dial("18444") {
			t.Fatal("the relay's address cannot reach the relay port")
		}
		if dial("18023") {
			t.Fatal("the relay's address reaches SSH")
		}
		// Flows the relay has open end with it, not only new ones: when its
		// port is no longer forwarded, when it goes; TCP with a reset. Not
		// when something else still lets them in (a public port), and not
		// when the table is made again.
		type flow struct {
			c   net.Conn
			got chan string
		}
		open := func(proto string, port int) flow {
			t.Helper()
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			got := make(chan string, 8)
			if proto == "udp" {
				pc, err := net.ListenPacket("udp", addr)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { pc.Close() })
				go func() {
					buf := make([]byte, 16)
					for {
						n, from, err := pc.ReadFrom(buf)
						if err != nil {
							return
						}
						got <- string(buf[:n])
						pc.WriteTo(buf[:n], from) // a reply: the flow is established
					}
				}()
				c, err := net.Dial("udp", addr)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				return flow{c, got}
			}
			l, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			c, err := net.DialTimeout("tcp", addr, 700*time.Millisecond)
			if err != nil {
				t.Fatalf("the relay's address cannot open a flow to %s", addr)
			}
			// Accepted before the listener closes, which would reset it.
			sc, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close(); sc.Close() })
			go func() {
				buf := make([]byte, 16)
				for {
					n, err := sc.Read(buf)
					if err != nil {
						return
					}
					got <- string(buf[:n])
				}
			}()
			return flow{c, got}
		}
		sends := func(f flow, msg string) bool {
			t.Helper()
			if _, err := f.c.Write([]byte(msg)); err != nil {
				return false
			}
			select {
			case m := <-f.got:
				return m == msg
			case <-time.After(700 * time.Millisecond):
				return false
			}
		}
		port := func(proto string, n uint32) *perimeterv1.Port { return &perimeterv1.Port{Proto: proto, Port: n} }
		public := snap.PublicPorts
		snap.RelayPorts = []*perimeterv1.Port{port("tcp", 18444), port("tcp", 18445), port("udp", 18446), port("tcp", 18447), port("tcp", 18448)}
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		tcpFlow, udpFlow, publicFlow := open("tcp", 18445), open("udp", 18446), open("tcp", 18447)
		for _, f := range []flow{tcpFlow, udpFlow, publicFlow} {
			if !sends(f, "a") {
				t.Fatal("an open relay flow does not pass")
			}
		}
		// The table made again: the flows go on, before the relays are back
		// in it and after.
		if err := fw.Setup(); err != nil {
			t.Fatal(err)
		}
		if !sends(tcpFlow, "b") {
			t.Fatal("a relay flow cut by the table made again")
		}
		if out, err := exec.Command("nft", "delete", "table", "inet", Table).CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if _, err := gate.Tick(); err != nil {
			t.Fatal(err)
		}
		if !sends(tcpFlow, "c") || !sends(udpFlow, "c") {
			t.Fatal("a relay flow cut by the table restored")
		}
		if !dial("18444") {
			t.Fatal("no new relay flow after the table is restored")
		}
		// rayspa started again with the relay removed meanwhile: the flow
		// the relay had open ends.
		downFlow := open("tcp", 18448)
		if !sends(downFlow, "a") {
			t.Fatal("an open relay flow does not pass")
		}
		gone := proto.Clone(snap).(*perimeterv1.Snapshot)
		gone.RelayPrefixes, gone.RelayPorts = nil, nil // as rayd sends it with no relays
		if err := fw.Setup(); err != nil {
			t.Fatal(err)
		}
		if err := NewGate(fw, quiet).Update(gone); err != nil {
			t.Fatal(err)
		}
		if sends(downFlow, "b") {
			t.Fatal("a relay flow goes on after rayspa started again without the relay")
		}
		// This test's gate puts its own table back.
		if out, err := exec.Command("nft", "delete", "table", "inet", Table).CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if _, err := gate.Tick(); err != nil {
			t.Fatal(err)
		}
		snap.RelayPorts = []*perimeterv1.Port{port("tcp", 18444), port("udp", 18446), port("tcp", 18447)}
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		if sends(tcpFlow, "d") {
			t.Fatal("a relay flow goes on after its port is no longer forwarded")
		}
		tcpFlow.c.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := tcpFlow.c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("a cut relay flow is not reset: %v", err)
		}
		snap.RelayPrefixes = nil
		snap.PublicPorts = append(slices.Clone(public), port("tcp", 18447))
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		if sends(udpFlow, "e") {
			t.Fatal("a UDP relay flow goes on after the relay is gone")
		}
		if !sends(publicFlow, "e") {
			t.Fatal("a relay flow to a port now public is cut")
		}
		if dial("18444") {
			t.Fatal("the service stays open after the relay is gone")
		}
		snap.RelayPorts = []*perimeterv1.Port{port("tcp", 18444)}
		snap.PublicPorts = public
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("rotated UDP port reaches the service after SPA", func(t *testing.T) {
		// A UDP service on 18443 with its own port schedule (spa-v2.md §11).
		echo, err := net.ListenPacket("udp", "127.0.0.1:18443")
		if err != nil {
			t.Fatal(err)
		}
		defer echo.Close()
		go func() {
			buf := make([]byte, 64)
			for {
				n, a, err := echo.ReadFrom(buf)
				if err != nil {
					return
				}
				echo.WriteTo(buf[:n], a)
			}
		}()
		rotKey := key(0x77)
		snap.Services = []*perimeterv1.Service{{Id: 1,
			Ports:    []*perimeterv1.Port{{Proto: "udp", Port: 18443}},
			Rotation: &perimeterv1.Rotation{PortKey: rotKey, PortBase: 50000, PortRange: 1000, TargetPort: 18443}}}
		snap.Devices = []*perimeterv1.Device{alice}
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		sched := params
		copy(sched.PortKey[:], rotKey)
		sched.PortBase, sched.PortRange = 50000, 1000
		svcPort := strconv.Itoa(int(sched.Port(sched.Slot(time.Now()))))
		ask := func() bool {
			c, err := net.Dial("udp", "127.0.0.1:"+svcPort)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.Write([]byte("hi"))
			c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
			buf := make([]byte, 8)
			n, err := c.Read(buf)
			return err == nil && string(buf[:n]) == "hi"
		}
		// The address still holds a grant for tcp/18443 only.
		if ask() {
			t.Fatal("rotated port answered without a UDP grant")
		}
		sendUDP(sealNow())
		waitResult(nil)
		if !ask() {
			t.Fatal("rotated port silent after SPA")
		}
	})
	t.Run("ACME window redirects TCP 80 and closes", func(t *testing.T) {
		acme, err := net.Listen("tcp", "127.0.0.1:18089")
		if err != nil {
			t.Fatal(err)
		}
		defer acme.Close()
		go func() {
			for {
				c, err := acme.Accept()
				if err != nil {
					return
				}
				c.Write([]byte("acme"))
				c.Close()
			}
		}()
		hello := func() string {
			c, err := net.DialTimeout("tcp", "127.0.0.1:80", 700*time.Millisecond)
			if err != nil {
				return ""
			}
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 8)
			n, _ := c.Read(buf)
			return string(buf[:n])
		}
		if got := hello(); got != "" {
			t.Fatalf("port 80 answers before the window: %q", got)
		}
		snap.Acme = &perimeterv1.AcmeWindow{Port: 18089, Until: time.Now().Add(2 * time.Second).Unix()}
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		if got := hello(); got != "acme" {
			t.Fatalf("window open, port 80 got %q", got)
		}
		// Expires by itself, without rayspa.
		time.Sleep(3 * time.Second)
		if got := hello(); got != "" {
			t.Fatalf("port 80 answers after the window: %q", got)
		}
		snap.Acme = nil
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("grants without destroy element", func(t *testing.T) {
		// nft before 1.0.8 and kernels before 6.3: what is absent cannot
		// fail a delete, and what fails is said.
		was := fw.destroy
		fw.destroy = false
		defer func() { fw.destroy = was }()
		a, p := netip.MustParseAddr("192.0.2.77"), []Port{{"tcp", 18999}, {"udp", 18999}}
		list := func() string {
			out, err := exec.Command("nft", "list", "set", "inet", Table, "allow4").CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			return string(out)
		}
		if err := fw.Deny(a, p); err != nil {
			t.Fatalf("closing what is not there: %v", err)
		}
		if err := fw.Allow(a, p, time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := fw.Allow(a, p, time.Minute); err != nil {
			t.Fatal(err)
		}
		if got := list(); !strings.Contains(got, "192.0.2.77 . tcp . 18999 timeout 1m") || strings.Contains(got, "timeout 1h") {
			t.Fatalf("a shorter grant again: %s", got)
		}
		if err := fw.Deny(a, p); err != nil || strings.Contains(list(), "192.0.2.77") {
			t.Fatalf("closed: %v\n%s", err, list())
		}
		bad := netip.MustParseAddr("192.0.2.78")
		if err := fw.Deny(bad, []Port{{"nosuchproto", 1}}); err == nil {
			t.Fatal("a real error said nothing")
		}
	})
	t.Run("table restored after flush ruleset", func(t *testing.T) {
		allow4 := func() string {
			out, err := exec.Command("nft", "list", "set", "inet", Table, "allow4").CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			return string(out)
		}
		if !strings.Contains(allow4(), "127.0.0.1") {
			t.Fatal("no grant to restore")
		}
		if out, err := exec.Command("nft", "flush", "ruleset").CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if ok, err := fw.Present(); ok || err != nil {
			t.Fatalf("present after flush: %v %v", ok, err)
		}
		if _, err := gate.Tick(); err != nil {
			t.Fatal(err)
		}
		if ok, err := fw.Present(); !ok || err != nil {
			t.Fatalf("present after tick: %v %v", ok, err)
		}
		if got := allow4(); !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "expires") {
			t.Fatalf("grant lost, or back without its timeout: %s", got)
		}
		// The slot ports log to rayspa again.
		sendUDP(make([]byte, 120))
		waitResult(spa.ErrAuth)
	})
	t.Run("garbage on the slot port", func(t *testing.T) {
		sendUDP(make([]byte, 120))
		waitResult(spa.ErrAuth)
	})
}

func loUp(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		t.Fatal(err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		t.Fatal(err)
	}
}

// TestNetnsDataPlaneToNode: a data-plane process (UID 9100-9179) does not
// reach the node's own addresses, root does; loopback stays open to both
// (the channel probe, S-2). Same conditions as TestNetns.
func TestNetnsDataPlaneToNode(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	loUp(t)
	// A non-loopback address of the node, as a lo alias.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	ifr, err := unix.NewIfreq("lo:9")
	if err != nil {
		t.Fatal(err)
	}
	if err := ifr.SetInet4Addr([]byte{192, 0, 2, 9}); err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFADDR, ifr); err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	// And one on another interface, as a node's public address: traffic
	// to it still leaves through lo, which the output chain matches first.
	for _, args := range [][]string{
		{"link", "add", "rc-va", "type", "veth", "peer", "name", "rc-vb"},
		{"addr", "add", "192.0.2.10/24", "dev", "rc-va"},
		// A subnet of its own, as the provider's segment (lo:9 above makes
		// all of 192.0.2.0/24 local).
		{"addr", "add", "198.51.100.10/24", "dev", "rc-va"},
		{"link", "set", "rc-va", "up"},
		{"link", "set", "rc-vb", "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}

	fw := &NFT{NflogGroup: 7, FilterLoopback: true}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	if err := fw.SetPublic([]Port{{"tcp", 18999}, {"tcp", 53}}); err != nil { // lo is filtered here, open in production
		t.Fatal(err)
	}
	for _, addr := range []string{"192.0.2.9:18999", "192.0.2.10:18999", "127.0.0.1:18999"} {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	for _, c := range []struct {
		uid  int
		addr [4]byte
		want bool
	}{
		{0, [4]byte{192, 0, 2, 9}, true},
		{9110, [4]byte{192, 0, 2, 9}, false},
		{9100, [4]byte{192, 0, 2, 9}, false},
		{9190, [4]byte{192, 0, 2, 9}, true}, // rayd
		{9110, [4]byte{127, 0, 0, 1}, true},
		{0, [4]byte{192, 0, 2, 10}, true},
		{9110, [4]byte{192, 0, 2, 10}, false},
	} {
		err := dialAs(c.uid, c.addr, 18999)
		if (err == nil) != c.want {
			t.Errorf("uid %d to %v: %v, want reachable=%v", c.uid, c.addr, err, c.want)
		}
	}
	// systemd-resolved's stub: port 53, nothing else of the node.
	for _, port := range []int{53, 18999} {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.53:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	for _, c := range []struct {
		uid, port int
		want      bool
	}{
		{9110, 53, true},
		{9110, 18999, false},
		{0, 18999, true},
	} {
		err := dialAs(c.uid, [4]byte{127, 0, 0, 53}, c.port)
		if (err == nil) != c.want {
			t.Errorf("uid %d to the stub's port %d: %v, want reachable=%v", c.uid, c.port, err, c.want)
		}
	}
	// The subnet's broadcast address: the node and its neighbours.
	for _, c := range []struct {
		uid  int
		addr [4]byte
		want bool
	}{
		{0, [4]byte{198, 51, 100, 255}, true},
		{9110, [4]byte{198, 51, 100, 255}, false},
		{9110, [4]byte{198, 51, 100, 77}, true}, // a neighbour's unicast address: not the output chain's
	} {
		err := sendUDPAs(c.uid, c.addr, 18999)
		if (err == nil) != c.want {
			t.Errorf("UDP, uid %d to %v: %v, want sent=%v", c.uid, c.addr, err, c.want)
		}
	}
}

// TestNetnsEgress: the egress policy (spec/egress-policy-v1.md §3) in the
// kernel, from sockets of the data plane's UIDs to loopback, which the
// guard of the node's own addresses leaves to them. Off, everything
// passes. SMTP: TCP 25 refused at once over IPv4 and IPv6, a connection
// open before ends; 465 and 587 pass, so do root and rayd. BitTorrent: the
// handshake reset before it reaches the peer, the UDP tracker, uTP SYN and
// DHT dropped (EPERM); what only resembles them passes. rayd's UID where it
// runs the data plane is covered, without the guard of the node's own
// addresses. The counters grow; the policy comes back with the table after
// "flush ruleset"; the TCP rule by tcp doff does what @ih does. Same
// conditions as TestNetns.
func TestNetnsEgress(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	loUp(t)
	// Loopback accepted as in production: only the output chain decides.
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

	v4 := func(port uint16) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port) }
	v6 := func(port uint16) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr("::1"), port) }
	// A kernel without IPv6 (ipv6.disable=1) tests IPv4 alone.
	ipv6 := true
	if fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0); err != nil {
		ipv6 = false
		t.Logf("no IPv6 here (%v): IPv4 only", err)
	} else {
		unix.Close(fd)
	}
	skip6 := func(ap netip.AddrPort) bool { return ap.Addr().Is6() && !ipv6 }
	tcpPeers := map[netip.AddrPort]<-chan []byte{}
	for _, ap := range []netip.AddrPort{v4(25), v6(25), v4(465), v4(587), v4(16881), v4(18080)} {
		if !skip6(ap) {
			tcpPeers[ap] = listenTCP(t, ap)
		}
	}
	udpPeers := map[netip.AddrPort]<-chan []byte{}
	for _, ap := range []netip.AddrPort{v4(16881), v6(16881)} {
		if !skip6(ap) {
			udpPeers[ap] = listenUDP(t, ap)
		}
	}
	// What a peer got of one connection: nothing when it is reset first.
	peerGot := func(ap netip.AddrPort) []byte {
		t.Helper()
		select {
		case b := <-tcpPeers[ap]:
			return b
		case <-time.After(3 * time.Second):
			t.Fatalf("no connection at %v", ap)
			return nil
		}
	}
	reach := func(uid int, ap netip.AddrPort) error {
		t.Helper()
		start := time.Now()
		c, err := connAs(uid, ap)
		if err == nil {
			c.Close()
			peerGot(ap)
		} else if d := time.Since(start); d > time.Second {
			t.Errorf("uid %d to %v refused after %v, not at once", uid, ap, d)
		}
		return err
	}
	handshake := append([]byte("\x13BitTorrent protocol"), make([]byte, 48)...) // reserved, info_hash, peer_id
	// send writes b over a connection of uid's to ap and returns what the
	// peer got and what the writer's next read says.
	send := func(uid int, ap netip.AddrPort, b []byte) ([]byte, error) {
		t.Helper()
		c, err := connAs(uid, ap)
		if err != nil {
			t.Fatalf("uid %d to %v: %v", uid, ap, err)
		}
		defer c.Close()
		if _, err := c.Write(b); err != nil {
			return peerGot(ap), err
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, err = c.Read(make([]byte, 64))
		return peerGot(ap), err
	}
	datagram := func(uid int, ap netip.AddrPort, b []byte, delivered bool) {
		t.Helper()
		if skip6(ap) {
			return
		}
		err := sendAs(uid, ap, b)
		switch {
		case delivered && err != nil:
			t.Errorf("uid %d to %v, % x...: %v, want it sent", uid, ap, b[:min(len(b), 12)], err)
		case !delivered && !errors.Is(err, unix.EPERM):
			t.Errorf("uid %d to %v, % x...: %v, want EPERM", uid, ap, b[:min(len(b), 12)], err)
		}
		select {
		case got := <-udpPeers[ap]:
			if !delivered || !slices.Equal(got, b) {
				t.Errorf("uid %d to %v, % x...: delivered %d bytes, want delivered %v", uid, ap, b[:min(len(b), 12)], len(got), delivered)
			}
		case <-time.After(300 * time.Millisecond):
			if delivered {
				t.Errorf("uid %d to %v, % x...: not delivered", uid, ap, b[:min(len(b), 12)])
			}
		}
	}

	// The BitTorrent signatures (spec/egress-policy-v1.md §2) and what
	// resembles them.
	tracker := binary.BigEndian.AppendUint64(nil, 0x41727101980)
	tracker = binary.BigEndian.AppendUint32(tracker, 0)          // connect
	tracker = binary.BigEndian.AppendUint32(tracker, 0x2a3b4c5d) // transaction ID
	utp := func(typ, ext byte, tsDiff uint32, rest ...byte) []byte {
		b := []byte{typ<<4 | 1, ext, 0x4a, 0x3f, 0x8c, 0x3a, 0x91, 0xd2}
		b = binary.BigEndian.AppendUint32(b, tsDiff)
		b = append(b, 0x00, 0x10, 0x00, 0x00, 0x71, 0xee, 0x00, 0x00) // window, seq_nr, ack_nr
		return append(b, rest...)
	}
	utpSyn20 := utp(4, 0, 0)
	utpSyn30 := utp(4, 2, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0) // extension bits, as µTorrent
	utpData := utp(0, 0, 0x5678, 'x', 'y', 'z')
	dht := append([]byte("d1:ad2:id20:"), []byte("abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")...)
	wireguard := append([]byte{1, 0, 0, 0}, slices.Repeat([]byte{0x5a}, 144)...) // handshake initiation, 148 bytes
	quic := append([]byte{0xc3, 0, 0, 0, 1, 8}, slices.Repeat([]byte{0xa5}, 1194)...)
	// A DNS query for example.com with EDNS, and a 20-byte one without it
	// whose ID starts as uTP's ST_SYN does.
	dnsEDNS := []byte{0x41, 0x00, 0x01, 0x20, 0, 1, 0, 0, 0, 0, 0, 1, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
		0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0}
	dnsShort := []byte{0x41, 0xff, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 2, 'c', 'o', 0, 0, 1, 0, 1}
	stun := append([]byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42}, slices.Repeat([]byte{7}, 12)...) // binding request
	dhtAnswer := []byte("d1:rd2:id20:abcdefghij0123456789e1:t2:aa1:y1:re")
	http := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	t.Run("the kernel's dry run takes it", func(t *testing.T) {
		// rayctl check and rayctl egress block: nft -c, nothing changes.
		doff, err := CheckEgress(Egress{SMTP: true, BitTorrent: true, UIDs: []uint32{0}}, fw.Check)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("@ih in this kernel: %v", !doff)
		if blocks, err := fw.EgressBlocks(); err != nil || len(blocks) != 0 {
			t.Fatalf("the dry run changed the table: %+v %v", blocks, err)
		}
	})

	t.Run("off: everything passes", func(t *testing.T) {
		policy(&perimeterv1.Egress{})
		if err := reach(9110, v4(25)); err != nil {
			t.Errorf("25: %v", err)
		}
		if got, err := send(9110, v4(16881), handshake); len(got) != len(handshake) {
			t.Errorf("handshake: %v, the peer got %d bytes", err, len(got))
		}
		for _, b := range [][]byte{tracker, utpSyn20, utpSyn30, dht, wireguard} {
			datagram(9110, v4(16881), b, true)
		}
	})

	t.Run("smtp", func(t *testing.T) {
		// To 25, open before the policy; the peer keeps its side open.
		early, err := connAs(9110, v4(25))
		if err != nil {
			t.Fatal(err)
		}
		defer early.Close()
		peerGot(v4(25))
		policy(&perimeterv1.Egress{Smtp: true})
		for _, c := range []struct {
			uid  int
			ap   netip.AddrPort
			want bool
		}{
			{9110, v4(25), false},
			{9110, v6(25), false},
			{9100, v4(25), false},
			{9179, v4(25), false},
			{9110, v4(465), true},
			{9110, v4(587), true},
			{0, v4(25), true},
			{0, v6(25), true},
			{9190, v4(25), true}, // rayd
		} {
			if skip6(c.ap) {
				continue
			}
			err := reach(c.uid, c.ap)
			if c.want && err != nil || !c.want && !errors.Is(err, unix.ECONNREFUSED) {
				t.Errorf("uid %d to %v: %v, want reachable=%v", c.uid, c.ap, err, c.want)
			}
		}
		// "On" is at once: a connection opened before ends with its next
		// segment.
		early.Write([]byte("EHLO x\r\n"))
		early.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := early.Read(make([]byte, 64)); !errors.Is(err, unix.ECONNRESET) {
			t.Errorf("a connection to 25 from before the policy: %v, want reset", err)
		}
		// BitTorrent is not this part's.
		if got, err := send(9110, v4(16881), handshake); len(got) != len(handshake) {
			t.Errorf("handshake with smtp alone: %v, the peer got %d bytes", err, len(got))
		}
		blocks, err := fw.EgressBlocks()
		if err != nil || blocks["smtp"].Packets < 3 || blocks["smtp"].Bytes == 0 || len(blocks) != 1 {
			t.Errorf("counters: %+v %v", blocks, err)
		}
	})

	bittorrent := func(t *testing.T) {
		t.Helper()
		if got, err := send(9110, v4(16881), handshake); !errors.Is(err, unix.ECONNRESET) || len(got) != 0 {
			t.Errorf("handshake: %v, the peer got %d bytes; want reset, nothing", err, len(got))
		}
		// The peer answers nothing: the writer's read times out.
		if got, err := send(9150, v4(18080), http); !errors.Is(err, os.ErrDeadlineExceeded) || len(got) != len(http) {
			t.Errorf("HTTP: %v, the peer got %d bytes", err, len(got))
		}
		if got, err := send(0, v4(16881), handshake); errors.Is(err, unix.ECONNRESET) || len(got) != len(handshake) {
			t.Errorf("root's handshake: %v, the peer got %d bytes", err, len(got))
		}
	}
	t.Run("bittorrent", func(t *testing.T) {
		policy(&perimeterv1.Egress{Bittorrent: true})
		bittorrent(t)
		for _, c := range []struct {
			name      string
			b         []byte
			delivered bool
		}{
			{"tracker connect", tracker, false},
			{"uTP SYN, 20 bytes", utpSyn20, false},
			{"uTP SYN, 30 bytes", utpSyn30, false},
			{"DHT query", dht, false},
			{"WireGuard initiation", wireguard, true},
			{"QUIC Initial", quic, true},
			{"DNS with EDNS", dnsEDNS, true},
			{"DNS, 20 bytes, ID 0x41ff", dnsShort, true},
			// The one that is a uTP SYN to the byte (spec §3): one in
			// 65 536 of such short queries, a retry goes through.
			{"DNS, 20 bytes, ID 0x4100", append([]byte{0x41, 0x00}, dnsShort[2:]...), false},
			{"uTP data", utpData, true},
			{"STUN", stun, true},
			{"DHT answer", dhtAnswer, true},
		} {
			t.Run(c.name, func(t *testing.T) {
				datagram(9110, v4(16881), c.b, c.delivered)
				datagram(9110, v6(16881), c.b, c.delivered)
				datagram(0, v4(16881), c.b, true)
			})
		}
		if err := reach(9110, v4(25)); err != nil {
			t.Errorf("25 with bittorrent alone: %v", err)
		}
		blocks, err := fw.EgressBlocks()
		if err != nil {
			t.Fatal(err)
		}
		for rule, n := range map[string]uint64{"bittorrent-tcp": 1, "bittorrent-tracker": 1, "bittorrent-utp": 2, "bittorrent-dht": 1} {
			if d := blocks[rule]; d.Packets < n || d.Bytes == 0 {
				t.Errorf("counter %s: %+v, want %d packets at least", rule, d, n)
			}
		}
		if _, ok := blocks["smtp"]; ok {
			t.Errorf("smtp counted with bittorrent alone: %+v", blocks)
		}
	})

	t.Run("rayd's UID where it runs the data plane", func(t *testing.T) {
		policy(&perimeterv1.Egress{Smtp: true, Uids: []uint32{4242}})
		if err := reach(4242, v4(25)); !errors.Is(err, unix.ECONNREFUSED) {
			t.Errorf("uid 4242: %v, want refused", err)
		}
		if err := reach(4243, v4(25)); err != nil {
			t.Errorf("uid 4243: %v", err)
		}
		// The guard of the node's own addresses stays the data plane's:
		// rayd reaches the node.
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		ifr, _ := unix.NewIfreq("lo:39")
		ifr.SetInet4Addr([]byte{192, 0, 2, 39})
		if err := unix.IoctlIfreq(fd, unix.SIOCSIFADDR, ifr); err != nil {
			t.Fatal(err)
		}
		unix.Close(fd)
		node := netip.MustParseAddrPort("192.0.2.39:18999")
		tcpPeers[node] = listenTCP(t, node)
		if err := reach(4242, node); err != nil {
			t.Errorf("uid 4242 to the node's address: %v", err)
		}
		if err := dialAs(9110, node.Addr().As4(), int(node.Port())); err == nil {
			t.Error("the data plane reached the node's address")
		}
	})

	t.Run("back after flush ruleset", func(t *testing.T) {
		policy(&perimeterv1.Egress{Smtp: true, Bittorrent: true})
		if out, err := exec.Command("nft", "flush", "ruleset").CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if err := reach(9110, v4(25)); err != nil {
			t.Fatalf("25 with the table gone: %v", err)
		}
		if _, err := gate.Tick(); err != nil {
			t.Fatal(err)
		}
		if err := reach(9110, v4(25)); !errors.Is(err, unix.ECONNREFUSED) {
			t.Errorf("25 after the restore: %v, want refused", err)
		}
		bittorrent(t)
		datagram(9110, v4(16881), tracker, false)
		if blocks, err := fw.EgressBlocks(); err != nil || len(blocks) != len(EgressRules) {
			t.Errorf("rules after the restore: %+v %v", blocks, err)
		}
	})

	t.Run("tcp doff in place of @ih", func(t *testing.T) {
		fw.egressDoff = true
		defer func() { fw.egressDoff = false }()
		if err := fw.SetEgress(Egress{BitTorrent: true}); err != nil {
			t.Fatal(err)
		}
		out, _ := exec.Command("nft", "list", "chain", "inet", Table, "egress").CombinedOutput()
		if !strings.Contains(string(out), "tcp doff 5") || !strings.Contains(string(out), "tcp doff 8") || strings.Contains(string(out), "@ih") {
			t.Fatalf("egress chain:\n%s", out)
		}
		// With TCP timestamps (doff 8) and without (doff 5).
		const ts = "/proc/sys/net/ipv4/tcp_timestamps"
		was, err := os.ReadFile(ts)
		if err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(ts, was, 0o644)
		for _, v := range []string{"1", "0"} {
			if err := os.WriteFile(ts, []byte(v), 0o644); err != nil {
				t.Fatal(err)
			}
			if got, err := send(9110, v4(16881), handshake); !errors.Is(err, unix.ECONNRESET) || len(got) != 0 {
				t.Errorf("tcp_timestamps=%s: %v, the peer got %d bytes; want reset, nothing", v, err, len(got))
			}
			if got, err := send(9110, v4(18080), http); !errors.Is(err, os.ErrDeadlineExceeded) || len(got) != len(http) {
				t.Errorf("tcp_timestamps=%s, HTTP: %v, the peer got %d bytes", v, err, len(got))
			}
		}
	})
}

// listenTCP accepts connections at ap and sends what each brought within
// 700 ms. It keeps them open until the test ends: a peer that closed would
// reset the writer for reasons of its own.
func listenTCP(t *testing.T, ap netip.AddrPort) <-chan []byte {
	t.Helper()
	l, err := net.Listen("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { l.Close(); close(done) })
	got := make(chan []byte, 64)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
				b, _ := io.ReadAll(c)
				got <- b
				<-done
			}()
		}
	}()
	return got
}

// listenUDP sends every datagram that reaches ap.
func listenUDP(t *testing.T, ap netip.AddrPort) <-chan []byte {
	t.Helper()
	pc, err := net.ListenPacket("udp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	got := make(chan []byte, 64)
	go func() {
		b := make([]byte, 2048)
		for {
			n, _, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			got <- slices.Clone(b[:n])
		}
	}()
	return got
}

// socketAs makes a socket owned by uid: it takes the thread's fsuid when
// it is made, and that is what "meta skuid" matches.
func socketAs(uid, family, typ int) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unix.Setfsuid(uid)
	defer unix.Setfsuid(0)
	return unix.Socket(family, typ, 0)
}

func sockaddr(ap netip.AddrPort) (int, unix.Sockaddr) {
	if ap.Addr().Is4() {
		return unix.AF_INET, &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}
	}
	return unix.AF_INET6, &unix.SockaddrInet6{Port: int(ap.Port()), Addr: ap.Addr().As16()}
}

// connAs connects over TCP from a socket owned by uid.
func connAs(uid int, ap netip.AddrPort) (net.Conn, error) {
	family, sa := sockaddr(ap)
	fd, err := socketAs(uid, family, unix.SOCK_STREAM)
	if err != nil {
		return nil, err
	}
	tv := unix.Timeval{Sec: 2}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	if err := unix.Connect(fd, sa); err != nil {
		unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "tcp")
	defer f.Close()
	return net.FileConn(f)
}

// sendAs sends one UDP datagram from a socket owned by uid.
func sendAs(uid int, ap netip.AddrPort, b []byte) error {
	family, sa := sockaddr(ap)
	fd, err := socketAs(uid, family, unix.SOCK_DGRAM)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Sendto(fd, b, 0, sa)
}

// sendUDPAs sends one datagram from a socket owned by uid, with
// SO_BROADCAST on: only the perimeter decides.
func sendUDPAs(uid int, addr [4]byte, port int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unix.Setfsuid(uid)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	unix.Setfsuid(0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
		return err
	}
	return unix.Sendto(fd, []byte("x"), 0, &unix.SockaddrInet4{Port: port, Addr: addr})
}

// dialAs connects over TCP from a socket owned by uid: the socket takes the
// thread's fsuid when it is made, and that is what "meta skuid" matches.
func dialAs(uid int, addr [4]byte, port int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unix.Setfsuid(uid)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	unix.Setfsuid(0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	tv := unix.Timeval{Sec: 2}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	return unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: addr})
}

// The node's own check of its DNS zones (dnscheck) under the real ruleset:
// the front (uid 9100, data plane) on 0.0.0.0:53 answers over loopback,
// while its answer to the node's public address goes over lo to a local
// address, which the output chain refuses to the data plane (S-2). A
// v0.13.0-v0.18.0 node asked there and saw "no answer in 5s (last ok
// never)" for every zone, its clients' tunnels working.
func TestNetnsNodeChecksItsFront(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	loUp(t)
	for _, args := range [][]string{
		{"link", "add", "rc-fa", "type", "veth", "peer", "name", "rc-fb"},
		{"addr", "add", "192.0.2.20/24", "dev", "rc-fa"},
		{"link", "set", "rc-fa", "up"},
		{"link", "set", "rc-fb", "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	defer exec.Command("ip", "link", "del", "rc-fa").Run() //nolint:errcheck
	fw := &NFT{NflogGroup: 7}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	if err := fw.SetPublic([]Port{{"udp", 53}}); err != nil {
		t.Fatal(err)
	}
	// The front: NXDOMAIN to every query, from a socket of uid 9100.
	runtime.LockOSThread()
	unix.Setfsuid(9100)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	unix.Setfsuid(0)
	runtime.UnlockOSThread()
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: 53}); err != nil {
		t.Fatal(err)
	}
	pc, err := net.FilePacketConn(os.NewFile(uintptr(fd), "front"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		b := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			if n >= 12 {
				b[2] |= 0x80                   // QR
				b[3] = b[3]&0xf0 | 3           // NXDOMAIN
				_, _ = pc.WriteTo(b[:n], from) // refused by the kernel to a local address
			}
		}
	}()

	z := dnscheck.Zone{Service: "mdns", Kind: "masterdns", Name: "t.example.com", Host: "192.0.2.20"}
	c := &dnscheck.Checker{System: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9")}, Retry: 200 * time.Millisecond,
		GiveUp: time.Second, Round: 5 * time.Second}
	front := c.Check(context.Background(), []dnscheck.Zone{z}, nil, false).Zones[0].Front
	if front.State != dnscheck.OK || !strings.HasPrefix(front.Detail, "answers on 127.0.0.1:53") {
		t.Errorf("the node's check of its front: %+v", front)
	}
	// Why not the public address: the answer does not come back.
	z.Front = netip.MustParseAddrPort("192.0.2.20:53")
	if front := c.Check(context.Background(), []dnscheck.Zone{z}, nil, false).Zones[0].Front; front.State != dnscheck.Fail {
		t.Errorf("the front's answer to the node's public address passed the output chain: %+v", front)
	}
}
