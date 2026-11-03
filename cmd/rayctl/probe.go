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
	chprobe "github.com/arngory/raycontrol/internal/probe"
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
	channel := fs.Bool("channel", false, "then measure the channel (probe-v1): TCP down and up, UDP echo")
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
		if *channel {
			return measure(ctx, client, p, printf)
		}
		return nil
	}
	return fmt.Errorf("node not reachable: %w", lastErr)
}

// readArg reads the bundle from the argument, a file (@FILE) or stdin
// (-); in a file or on stdin the rcdev1 token is found in whatever text
// surrounds it (the output of rayctl device add, a message); an rcinv1
// invite is found the same way.
func readArg(s string) (string, error) {
	var text string
	switch {
	case s == "-":
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return "", err
		}
		text = string(b)
	case strings.HasPrefix(s, "@"):
		b, err := os.ReadFile(s[1:])
		if err != nil {
			return "", err
		}
		text = string(b)
	default:
		return s, nil
	}
	for _, f := range strings.Fields(text) {
		if strings.HasPrefix(f, node.BundlePrefix) || strings.HasPrefix(f, node.InvitePrefix) {
			return f, nil
		}
	}
	return strings.TrimSpace(text), nil
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

// measure runs the channel probes of probe-v1 (R4-16) after SPA: 8 MiB
// down, 4 MiB up, and 50 datagrams of 1200 bytes 20 ms apart.
func measure(ctx context.Context, sc sub.Client, p sub.Payload, printf func(string, ...any)) error {
	if p.Probe == nil {
		printf("channel: the node serves no probes (raycontrol before R4-16)\n")
		return nil
	}
	hc := sc.HTTP()
	defer hc.CloseIdleConnections()
	c := chprobe.Client{HTTP: hc, Base: "https://" + sc.Addr, Authorize: sc.Authorize}
	tcp := func(t chprobe.Transfer) string {
		if t.Server.TCP == nil {
			return ""
		}
		return fmt.Sprintf(" (node: rtt %.1f ms, retransmits %d)", float64(t.Server.TCP.RTTus)/1000, t.Server.TCP.Retrans)
	}
	down, err := c.Down(ctx, 8<<20)
	if err != nil {
		return fmt.Errorf("channel down: %w", err)
	}
	printf("channel down: %d bytes in %v, %.1f Mbit/s%s\n", down.Bytes, down.Duration.Round(time.Millisecond), down.Mbps(), tcp(down))
	up, err := c.Up(ctx, 4<<20)
	if err != nil {
		return fmt.Errorf("channel up: %w", err)
	}
	upRate := 0.0
	if up.Server.Ms > 0 {
		upRate = float64(up.Server.Bytes) * 8 / float64(up.Server.Ms) / 1000
	}
	printf("channel up: %d bytes, %.1f Mbit/s at the node%s\n", up.Server.Bytes, upRate, tcp(up))
	if !p.Probe.UDP {
		printf("channel udp: no echo on this node\n")
		return nil
	}
	e, err := c.Echo(ctx, 50, 1200, 20*time.Millisecond)
	if err != nil {
		return fmt.Errorf("channel udp: %w", err)
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	printf("channel udp: %d sent, %d back; lost up %d, down %d; rtt min/avg/max %.1f/%.1f/%.1f ms, jitter %.1f ms, reordered %d\n",
		e.Sent, e.Received, e.LostUp(), e.LostDown(), ms(e.RTTMin), ms(e.RTTAvg), ms(e.RTTMax), ms(e.Jitter), e.Reordered)
	return nil
}
