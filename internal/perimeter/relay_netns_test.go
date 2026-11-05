package perimeter

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/spa"
)

// TestRelayRole plays one part of the relay test (test/relay/run.sh,
// relay-v1 §3.1), chosen by RAYCONTROL_RELAY_ROLE, each in its own network
// namespace:
//   - relay: the perimeter with RelayTo the exit, SPA by UDP;
//   - exit: TCP and UDP 443 that answer with the address they see;
//   - client: 443 at the relay is closed, then SPA, then TCP and UDP 443
//     reach the exit, which sees the relay's address.
func TestRelayRole(t *testing.T) {
	role := os.Getenv("RAYCONTROL_RELAY_ROLE")
	if role == "" {
		t.Skip("run by test/relay/run.sh")
	}
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1, 2}})
	switch role {
	case "relay":
		exit := netip.MustParseAddr(os.Getenv("RAYCONTROL_RELAY_EXIT"))
		fw := &NFT{NflogGroup: 8, RelayTo: exit}
		if err := fw.Setup(); err != nil {
			t.Fatal(err)
		}
		defer fw.Teardown()
		gate := NewGate(fw, quiet)
		if err := gate.Update(snap); err != nil {
			t.Fatal(err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		go ReadNFLOG(ctx, 8, func(src netip.Addr, pkt []byte) { gate.Handle(src, pkt) }, quiet)
		fmt.Println("relay ready")
		for ctx.Err() == nil {
			gate.Tick()
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	case "exit":
		ln, err := net.Listen("tcp", ":443")
		if err != nil {
			t.Fatal(err)
		}
		pc, err := net.ListenPacket("udp", ":443")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				fmt.Fprintln(c, c.RemoteAddr().(*net.TCPAddr).IP)
				c.Close()
			}
		}()
		go func() {
			buf := make([]byte, 64)
			for {
				_, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				pc.WriteTo([]byte(from.(*net.UDPAddr).IP.String()), from)
			}
		}()
		fmt.Println("exit ready")
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		<-ctx.Done()
	case "client":
		relay := os.Getenv("RAYCONTROL_RELAY_ADDR")
		tcp := func() (string, error) {
			c, err := net.DialTimeout("tcp", net.JoinHostPort(relay, "443"), time.Second)
			if err != nil {
				return "", err
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			line, err := bufio.NewReader(c).ReadString('\n')
			return strings.TrimSpace(line), err
		}
		if seen, err := tcp(); err == nil {
			t.Fatalf("443 at the relay open before SPA (the exit saw %s)", seen)
		}
		params, err := paramsOf(snap.Spa)
		if err != nil {
			t.Fatal(err)
		}
		pkt, err := spa.SealRandom(params, [spa.KeySize]byte(key(0x11)), spa.Request{Time: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		port := params.Port(params.Slot(time.Now()))
		u, err := net.Dial("udp", net.JoinHostPort(relay, fmt.Sprint(port)))
		if err != nil {
			t.Fatal(err)
		}
		u.Write(pkt)
		u.Close()
		time.Sleep(500 * time.Millisecond)
		seen, err := tcp()
		if err != nil {
			t.Fatalf("443 at the relay after SPA: %v", err)
		}
		if want := os.Getenv("RAYCONTROL_RELAY_SEEN"); seen != want {
			t.Fatalf("the exit saw %s, want the relay's %s", seen, want)
		}
		uc, err := net.Dial("udp", net.JoinHostPort(relay, "443"))
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		uc.SetDeadline(time.Now().Add(2 * time.Second))
		uc.Write([]byte("hi"))
		buf := make([]byte, 64)
		n, err := uc.Read(buf)
		if err != nil || string(buf[:n]) != os.Getenv("RAYCONTROL_RELAY_SEEN") {
			t.Fatalf("UDP 443 through the relay: %q %v", buf[:n], err)
		}
		fmt.Println("client: TCP and UDP 443 reach the exit through the relay after SPA, not before")
	}
}
