//go:build linux

package perimeter

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// A relay's forward of TCP 80 to its exit for the exit's ACME window
// (spec/relay-names-v1.md §6), in network namespaces as TestNetns: root,
// under unshare -n, RAYCONTROL_NETNS_TEST=1. The relay is the test's
// namespace, the client and the exit peers of their own. While the
// snapshot's acme_forward_until is ahead, TCP 80 from an address with no
// grant reaches the exit, which sees the relay's address; TCP 443 still
// needs a grant; after the deadline a new connection to 80 goes nowhere,
// and the one opened in the window goes on (a validation under way).
func TestNetnsRelayACMEForward(t *testing.T) {
	netnsOnly(t)
	client, exit := newPeer(t), newPeer(t)
	link(t, client, "rc-ac", []string{"198.51.100.1/24"}, []string{"198.51.100.2/24"})
	link(t, exit, "rc-ae", []string{"203.0.113.1/24"}, []string{"203.0.113.2/24"})
	client.run(t, "ip", "route", "add", "default", "via", "198.51.100.1")
	exit.run(t, "ip", "route", "add", "default", "via", "203.0.113.1")
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	fw := &NFT{NflogGroup: 7, RelayTo: netip.MustParseAddr("203.0.113.2")}
	if err := fw.Setup(); err != nil {
		t.Fatal(err)
	}
	defer fw.Teardown()
	// The exit: each connection gets the address it came from, then its
	// lines back.
	exit.do(t, func() {
		for _, port := range []string{"80", "443"} {
			ln, err := net.Listen("tcp", ":"+port)
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
					go func() {
						defer c.Close()
						fmt.Fprintln(c, c.RemoteAddr().(*net.TCPAddr).IP)
						r := bufio.NewReader(c)
						for {
							line, err := r.ReadString('\n')
							if err != nil {
								return
							}
							fmt.Fprint(c, line)
						}
					}()
				}
			}()
		}
	})
	// dial connects from the client to the relay, and gives the
	// connection with the address the exit saw.
	dial := func(port string) (net.Conn, string, error) {
		var c net.Conn
		var seen string
		var err error
		client.do(t, func() {
			c, err = net.DialTimeout("tcp", "198.51.100.1:"+port, 700*time.Millisecond)
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			seen, err = bufio.NewReader(c).ReadString('\n')
		})
		if err != nil && c != nil {
			c.Close()
			c = nil
		}
		return c, strings.TrimSpace(seen), err
	}

	gate := NewGate(fw, quiet)
	snap := testSnapshot(&perimeterv1.Device{Id: "alice", Key: key(0x11), Allowed: []uint32{1, 2}})
	if err := gate.Update(snap); err != nil {
		t.Fatal(err)
	}
	if c, _, err := dial("80"); err == nil {
		c.Close()
		t.Fatal("TCP 80 through the relay before the window")
	}
	until := time.Now().Add(3 * time.Second)
	snap.AcmeForwardUntil = until.Unix() + 1 // the element lasts whole seconds
	if err := gate.Update(snap); err != nil {
		t.Fatal(err)
	}
	open, seen, err := dial("80")
	if err != nil || seen != "203.0.113.1" {
		t.Fatalf("TCP 80 in the window: the exit saw %q, %v", seen, err)
	}
	defer open.Close()
	if c, _, err := dial("443"); err == nil {
		c.Close()
		t.Fatal("TCP 443 through the relay without a grant, in the window")
	}
	if n := inDrops(t, fw, "relay_forward", "relay-no-grant"); n == 0 {
		t.Fatal("443 without a grant not dropped as relay-no-grant")
	}
	time.Sleep(time.Until(until.Add(2500 * time.Millisecond)))
	if c, seen, err := dial("80"); err == nil {
		c.Close()
		t.Fatalf("TCP 80 through the relay after the window (the exit saw %s)", seen)
	}
	// The connection of the window goes on.
	_ = open.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprintln(open, "still"); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(open).ReadString('\n'); err != nil || line != "still\n" {
		t.Fatalf("the window's connection after it: %q %v", line, err)
	}
}
