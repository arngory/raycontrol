// Command knock goes through a relay as a client does, for
// test/relay/host.sh (spec/relay-v1.md §4): SPA to the relay with the
// device's K_relay, then TCP to the relay's port 443, which the relay
// forwards to its exit.
//
//	knock -bundle DEVICE -payload PAYLOAD [-relay NAME] [-closed]
//
// DEVICE holds the device's bundle (rayctl device add: its key and its
// exit's node ID), PAYLOAD the subscription's payload (rayctl probe
// -payload), whose relay hint has the relay's address and SPA. A
// connection that the exit accepts, or refuses, came back through the
// relay; a timeout did not. With -closed, no knock: 443 must time out.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/sub"
)

func main() {
	bundle := flag.String("bundle", "", "the device's bundle (rcdev1:...), a file")
	payload := flag.String("payload", "", "the subscription's payload, JSON, a file")
	relay := flag.String("relay", "r1", "the relay's name")
	closed := flag.Bool("closed", false, "no knock: the relay's 443 must not answer")
	flag.Parse()
	if err := run(*bundle, *payload, *relay, *closed); err != nil {
		fmt.Fprintln(os.Stderr, "knock:", err)
		os.Exit(1)
	}
}

func run(bundleFile, payloadFile, name string, closed bool) error {
	raw, err := os.ReadFile(bundleFile) //nolint:gosec // G304: the test's file
	if err != nil {
		return err
	}
	b, err := node.DecodeBundle(strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}
	raw, err = os.ReadFile(payloadFile) //nolint:gosec // G304: the test's file
	if err != nil {
		return err
	}
	var p sub.Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	var hint *sub.RelayHint
	for i := range p.Relays {
		if p.Relays[i].ID == name {
			hint = &p.Relays[i]
		}
	}
	if hint == nil {
		return fmt.Errorf("no relay %s in the subscription", name)
	}
	params, err := hint.SPA.Params()
	if err != nil {
		return err
	}
	k, err := hex.DecodeString(b.DeviceKey)
	exit, nerr := hex.DecodeString(b.SPA.NodeID)
	if err != nil || nerr != nil || len(k) != spa.KeySize || len(exit) != spa.NodeIDSize {
		return errors.New("no device key or node ID in the bundle")
	}
	to := net.JoinHostPort(hint.Host, "443")
	if !closed {
		kRelay := spa.RelayKey([spa.KeySize]byte(k), [spa.NodeIDSize]byte(exit), params.NodeID, name)
		now := time.Now()
		pkt, err := spa.SealRandom(params, kRelay, spa.Request{Time: now})
		if err != nil {
			return err
		}
		u, err := net.Dial("udp", net.JoinHostPort(hint.Host, strconv.Itoa(int(params.Port(params.Slot(now))))))
		if err != nil {
			return err
		}
		_, err = u.Write(pkt)
		_ = u.Close()
		if err != nil {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
	c, err := net.DialTimeout("tcp", to, 3*time.Second)
	answered := err == nil || errors.Is(err, syscall.ECONNREFUSED)
	if c != nil {
		_ = c.Close()
	}
	switch {
	case closed && answered:
		return fmt.Errorf("tcp %s answered with no knock", to)
	case closed:
		fmt.Printf("tcp %s: closed with no knock (%v)\n", to, err)
	case err == nil:
		fmt.Printf("tcp %s: connected through relay %s, after a knock with K_relay\n", to, name)
	case answered:
		fmt.Printf("tcp %s: refused by the exit through relay %s, after a knock with K_relay\n", to, name)
	default:
		return fmt.Errorf("tcp %s after a knock with K_relay: %w", to, err)
	}
	return nil
}
