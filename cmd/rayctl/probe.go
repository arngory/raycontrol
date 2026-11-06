package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/dnscheck"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
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
	carrier := fs.String("carrier", "auto", "SPA carrier: udp, tls (TCP as a TLS ClientHello), tcp (bare TCP) or auto (UDP, then tls, then bare TCP for a node before v0.10)")
	addr := fs.String("addr", "", "node address to use instead of the bundle's host")
	links := fs.Bool("links", false, "print the profile links (they carry credentials)")
	redacted := fs.Bool("redact", false, "hide the node's address and names, IDs and keys, to share the output in an issue")
	channel := fs.Bool("channel", false, "then measure the channel (probe-v1): TCP down and up, UDP echo")
	report := fs.String("report", "", "then send this summary of the network (probe-v1 §6), JSON or @FILE")
	dnsCheck := fs.Bool("dns", false, "then check the subscription's DNS tunnel zones as this machine sees them: the parent's delegation, the node's front and backend (a poll sealed and tagged as this device's), the zones through -resolver")
	dnsResolvers := fs.String("resolver", "system", "with -dns: the resolvers to ask, "+strings.Join(dnscheck.ResolverNames(), ", ")+", udp:IP or tcp:IP")
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
	carriers := carrierList(*carrier)
	if carriers == nil {
		return errUsage
	}
	client := sub.Client{
		Addr: net.JoinHostPort(ip.String(), strconv.Itoa(int(b.Sub.Port))), Pin: b.Sub.Pin,
		DeviceID: b.DeviceID, DeviceKey: key, NodeKeys: b.NodeKeys, NodeID: b.SPA.NodeID,
	}
	printf := func(format string, a ...any) { fmt.Printf(format, a...) }
	var red *redact.Redactor
	if *redacted {
		red = redact.New(host, domainOf(host))
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
		if h := p.Hints; h != nil {
			printf("hints for this network (%d reports in %d days): order %v, avoid %v, udp blocked %v, tcp stall %d KiB, udp mtu %q\n",
				h.Devices, h.Days, h.Order, h.Avoid, h.UDPBlocked, h.TCPStallKiB, h.UDPMTU)
		}
		if *report != "" {
			body := []byte(*report)
			if strings.HasPrefix(*report, "@") {
				if body, err = os.ReadFile(strings.TrimPrefix(*report, "@")); err != nil {
					return err
				}
			}
			hc := client.HTTP()
			c := chprobe.Client{HTTP: hc, Base: "https://" + client.Addr, Authorize: client.Authorize}
			if err := c.Report(ctx, body); err != nil {
				return err
			}
			hc.CloseIdleConnections()
			printf("report taken\n")
		}
		if *dnsCheck {
			if err := probeDNS(ctx, &p, host, ip, key, *dnsResolvers, red, printf); err != nil {
				return err
			}
		}
		if *channel {
			return measure(ctx, client, p, printf)
		}
		return nil
	}
	return fmt.Errorf("node not reachable: %w", lastErr)
}

// probeDNS checks the subscription's DNS tunnel zones from this machine, as
// rayd checks them from the node (internal/dnscheck): through this
// machine's resolvers, with the device's own dnsauth key and the seal key
// of the link, so what works for rayd and not here is this network's.
func probeDNS(ctx context.Context, p *sub.Payload, host string, ip netip.Addr, deviceKey [spa.KeySize]byte, resolverList string,
	red *redact.Redactor, printf func(string, ...any)) error {
	zones := probeDNSZones(p, host, ip, deviceKey)
	if len(zones) == 0 {
		printf("no DNS tunnel in the subscription\n")
		return nil
	}
	if red != nil {
		// The zones, and the domains they are under, are the node's
		// names too (review 13: -redact printed them in clear).
		for _, z := range zones {
			red.Add(z.Name)
			if _, parent, ok := strings.Cut(z.Name, "."); ok && strings.Contains(parent, ".") {
				red.Add(parent)
			}
		}
	}
	resolvers, err := dnscheck.ParseResolvers(splitList(resolverList))
	if err != nil {
		return err
	}
	rep := (&dnscheck.Checker{}).Check(ctx, zones, resolvers, false)
	pb := api.DNSReportPB(rep)
	// The fixes are the node's commands: said as such off the node.
	for _, z := range pb.Zones {
		for _, s := range []*nodev1.DNSCheckStep{z.Parent, z.Front, z.Backend} {
			if s != nil && s.Fix != "" {
				s.Fix = "on the node: " + s.Fix
			}
		}
	}
	var out strings.Builder
	w := tabwriter.NewWriter(&out, 0, 4, 2, ' ', 0)
	printDNSCheck(w, pb, time.Now())
	if err := w.Flush(); err != nil {
		return err
	}
	printf("%s", out.String())
	return nil
}

// probeDNSZones are the DNS tunnel zones of a subscription's links, the
// main one and its spares (niko-dns-spare, spec/dnszones-v1.md §2), with
// what a check needs: the probe key of the subscription, the seal key of
// the link and the device's dnsauth key for the service, the same in each
// zone of a link.
func probeDNSZones(p *sub.Payload, host string, ip netip.Addr, deviceKey [spa.KeySize]byte) []dnscheck.Zone {
	var probeKey []byte
	if p.DNSProbe != nil {
		probeKey, _ = base64.RawURLEncoding.DecodeString(p.DNSProbe.Key)
	}
	var zones []dnscheck.Zone
	for _, pr := range p.Profiles {
		u, err := url.Parse(pr.Link)
		if err != nil {
			continue
		}
		q := u.Query()
		f := strings.Split(q.Get("niko-dns"), ";") // kind;;zone;key or method
		if len(f) < 3 || (f[0] != "dnstt" && f[0] != "masterdns") || f[2] == "" {
			continue
		}
		// The front is asked at the node's address: off the node the
		// checker's fallback, loopback, is this machine's own (review 13).
		z := dnscheck.Zone{Service: pr.Name, Kind: f[0], Name: f[2], Host: host, SvcID: pr.Svc, Front: netip.AddrPortFrom(ip, 53)}
		if z.Kind == "dnstt" {
			if len(probeKey) == 32 {
				z.ProbeKey = probeKey
			}
			z.Seal, z.Auth = "off", "off"
			if v, ok := strings.CutPrefix(q.Get("niko-dnsseal"), "v1;"); ok {
				if k, err := base64.RawURLEncoding.DecodeString(v); err == nil && len(k) == 32 {
					z.Seal, z.SealKey = "required", k
				}
			}
			if q.Get("niko-dnsauth") == "v1" {
				if id, err := hex.DecodeString(q.Get("niko-node")); err == nil && len(id) == spa.NodeIDSize {
					k := spa.DNSAuthKey(deviceKey, [spa.NodeIDSize]byte(id), pr.Svc)
					z.Auth, z.AuthKey = "required", k[:]
					// dnsauth-v2 when the subscription says the node takes it
					// (spec/dnsauth-v2.md §4), as Niko does.
					z.AuthV2 = p.DNSAuth != nil && slices.Contains(p.DNSAuth.V, 2)
				}
			}
		}
		zones = append(zones, z)
		for spare := range strings.SplitSeq(q.Get("niko-dns-spare"), ",") {
			if spare != "" {
				zz := z
				zz.Name, zz.Spare = spare, true
				zones = append(zones, zz)
			}
		}
	}
	return zones
}

// readArg reads the bundle from the argument, a file (@FILE) or stdin
// (-); in a file or on stdin the rcdev1 token is found in whatever text
// surrounds it (the output of rayctl device add, a message); an invite,
// RCINV2 or rcinv1, is found the same way.
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
	n := len(node.InvitePrefix2)
	for _, f := range strings.Fields(text) {
		if strings.HasPrefix(f, node.BundlePrefix) || strings.HasPrefix(f, node.InvitePrefix) ||
			len(f) > n && strings.EqualFold(f[:n], node.InvitePrefix2) {
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

// carrierList is the order the carriers are tried in for -carrier: auto
// is UDP, then the ClientHello, then bare TCP for a node before v0.10,
// which takes no ClientHello; nil for an unknown name.
func carrierList(name string) []string {
	return map[string][]string{"auto": {"udp", "tls", "tcp"}, "udp": {"udp"}, "tcp": {"tcp"}, "tls": {"tls"}}[name]
}

// sendSPA sends one packet: a UDP datagram, or the first data of a TCP
// connection that is closed right after (spa-v2.md §10): bare (tcp) or as
// a TLS ClientHello (tls, §10.1).
func sendSPA(carrier string, to netip.AddrPort, pkt []byte) error {
	network := carrier
	if carrier == "tls" {
		rec, err := spa.TLSCarrier(pkt)
		if err != nil {
			return err
		}
		network, pkt = "tcp", rec
	}
	c, err := net.DialTimeout(network, to.String(), 3*time.Second)
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
	if st, err := c.Link(ctx); err != nil {
		printf("channel link: %v\n", err)
	} else {
		printf("channel link: %d connections of this address on 443 at the node; rtt median %.1f ms, retransmits %.2f%%\n",
			st.Connections, float64(st.RTTus.Median)/1000, st.RetransRate*100)
	}
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
