package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/redact"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/sub"
)

// probe checks a node from outside, as a client would: SPA v2 over UDP (then
// TCP), then the subscription with its pin and both signatures. It needs
// only the device bundle, not rayd.
func probe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	carrier := fs.String("carrier", "auto", "SPA carrier: udp, tcp or auto (UDP, then TCP)")
	addr := fs.String("addr", "", "node address to use instead of the bundle's host")
	links := fs.Bool("links", false, "print the profile links (they carry credentials)")
	redacted := fs.Bool("redact", false, "hide the node's address and names, IDs and keys, to share the output in an issue")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
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
	if b.Sub == nil {
		return errors.New("the bundle has no subscription endpoint (made before R1?)")
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
	// One address for SPA and TLS: the grant is per source and destination
	// family, so a domain with A and AAAA must not switch between them.
	ip, err := resolve(ctx, host)
	if err != nil {
		return err
	}
	carriers := map[string][]string{"auto": {"udp", "tcp"}, "udp": {"udp"}, "tcp": {"tcp"}}[*carrier]
	if carriers == nil {
		return errUsage
	}
	client := sub.Client{
		Addr: net.JoinHostPort(ip.String(), strconv.Itoa(int(b.Sub.Port))), Pin: b.Sub.Pin,
		DeviceID: b.DeviceID, DeviceKey: key, NodeKeys: b.NodeKeys, NodeID: b.SPA.NodeID,
	}
	printf := func(format string, a ...any) { fmt.Printf(format, a...) }
	if *redacted {
		red := redact.New(host, domainOf(host))
		printf = func(format string, a ...any) { fmt.Print(red.String(fmt.Sprintf(format, a...))) }
		*links = false
	}
	printf("node %s (%s), device %s\n", host, ip, b.DeviceID)

	var lastErr error
	for _, c := range carriers {
		start := time.Now()
		port := params.Port(params.Slot(start))
		pkt, err := spa.SealRandom(params, key, spa.Request{Time: start})
		if err != nil {
			return err
		}
		if err := sendSPA(c, netip.AddrPortFrom(ip, port), pkt); err != nil {
			printf("SPA over %s to port %d: %v\n", c, port, err)
			lastErr = err
			continue
		}
		// spa-v2.md §7: connect 150-400 ms after the packet.
		time.Sleep(300 * time.Millisecond)
		fctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		p, err := client.Fetch(fctx, time.Now())
		cancel()
		if err != nil {
			printf("SPA over %s to port %d, then subscription: %v\n", c, port, err)
			lastErr = err
			continue
		}
		printf("SPA over %s to port %d, subscription in %v: both signatures valid\n",
			c, port, time.Since(start).Round(time.Millisecond))
		printf("seq %d, expires %s, %d profiles\n", p.Seq, time.Unix(p.Expires, 0).UTC().Format(time.RFC3339), len(p.Profiles))
		for _, pr := range p.Profiles {
			if *links {
				printf("  %s (service %d): %s\n", pr.Name, pr.Svc, pr.Link)
			} else {
				printf("  %s (service %d)\n", pr.Name, pr.Svc)
			}
		}
		return nil
	}
	return fmt.Errorf("node not reachable: %w", lastErr)
}

func readArg(s string) (string, error) {
	switch {
	case s == "-":
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		return string(b), err
	case strings.HasPrefix(s, "@"):
		b, err := os.ReadFile(s[1:])
		return string(b), err
	}
	return s, nil
}

func resolve(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("resolving %s: %w", host, err)
	}
	return ips[0].Unmap(), nil
}

// sendSPA sends one packet: a UDP datagram, or the first data of a TCP
// connection that is closed right after (spa-v2.md §10).
func sendSPA(carrier string, to netip.AddrPort, pkt []byte) error {
	c, err := net.DialTimeout(carrier, to.String(), 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(pkt)
	return err
}
