package perimeter

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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
		snap.AdminPrefixes = []string{"127.0.0.0/8"}
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
		snap.RelayPrefixes = nil
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		if dial("18444") {
			t.Fatal("the service stays open after the relay is gone")
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
		if !strings.Contains(allow4(), "127.0.0.1") {
			t.Fatal("grant lost")
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

	fw := &NFT{NflogGroup: 7, FilterLoopback: true}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	if err := fw.SetPublic([]Port{{"tcp", 18999}}); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"192.0.2.9:18999", "127.0.0.1:18999"} {
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
	} {
		err := dialAs(c.uid, c.addr, 18999)
		if (err == nil) != c.want {
			t.Errorf("uid %d to %v: %v, want reachable=%v", c.uid, c.addr, err, c.want)
		}
	}
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
