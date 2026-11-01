package perimeter

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
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
