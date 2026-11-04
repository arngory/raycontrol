package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/sub"
)

// knock sends SPA only: the node opens the device's services to this
// address for a while (the scope is everything the device may use). With
// the emergency bundle that is SSH (D-6): knock, then ssh as usual. The
// subscription, which every device may reach, shows that the window opened.
func knock(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("knock", flag.ContinueOnError)
	carrier := fs.String("carrier", "auto", "SPA carrier: udp, tls (TCP as a TLS ClientHello), tcp (bare TCP) or auto (UDP, then tls, then bare TCP for a node before v0.10)")
	addr := fs.String("addr", "", "node address to use instead of the bundle's host")
	ttl := fs.Duration("ttl", 0, "how long to stay open (0: the node's default, 10 min; at most its -spa-max-ttl, 1 h)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || *ttl < 0 {
		return errUsage
	}
	raw, err := readArg(fs.Arg(0))
	if err != nil {
		return err
	}
	b, err := node.DecodeBundle(raw)
	if err != nil {
		return err
	}
	params, err := b.SPA.Params()
	if err != nil {
		return err
	}
	k, err := hex.DecodeString(b.DeviceKey)
	if err != nil || len(k) != spa.KeySize {
		return errors.New("bad device key in the bundle")
	}
	key := [spa.KeySize]byte(k)
	host := b.Host
	if *addr != "" {
		host = *addr
	}
	ip, err := resolve(ctx, host)
	if err != nil {
		return err
	}
	carriers := carrierList(*carrier)
	if carriers == nil {
		return errUsage
	}
	var client *sub.Client
	if b.Sub != nil {
		client = &sub.Client{Addr: net.JoinHostPort(ip.String(), strconv.Itoa(int(b.Sub.Port))), Pin: b.Sub.Pin,
			DeviceID: b.DeviceID, DeviceKey: key, NodeKeys: b.NodeKeys, NodeID: b.SPA.NodeID}
	}
	window := "the node's default time (10 min unless set otherwise)"
	if *ttl > 0 {
		window = ttl.String() + " (or the node's -spa-max-ttl, if shorter)"
	}
	var lastErr error
	for _, c := range carriers {
		start := time.Now()
		port := params.Port(params.Slot(start))
		pkt, err := spa.SealRandom(params, key, spa.Request{Time: start, TTL: *ttl})
		if err != nil {
			return err
		}
		if err := sendSPA(c, netip.AddrPortFrom(ip, port), pkt); err != nil {
			fmt.Printf("SPA over %s to port %d: %v\n", c, port, err)
			lastErr = err
			continue
		}
		if client == nil {
			fmt.Printf("SPA sent over %s to %s port %d; the bundle has no subscription to confirm it with\n", c, ip, port)
			return nil
		}
		// spa-v2.md §7: connect 150-400 ms after the packet.
		time.Sleep(300 * time.Millisecond)
		fctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		_, err = client.Fetch(fctx, time.Now())
		cancel()
		if err != nil {
			fmt.Printf("SPA over %s to port %d, then the subscription: %v\n", c, port, err)
			lastErr = err
			continue
		}
		fmt.Printf("open: %s lets this address reach device %s's services for %s; for SSH, connect now (ssh root@%s)\n",
			host, b.DeviceID, window, ip)
		return nil
	}
	return fmt.Errorf("the node did not open: %w", lastErr)
}
