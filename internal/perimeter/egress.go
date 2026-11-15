package perimeter

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// Egress is the node's egress policy (spec/egress-policy-v1.md §3): what
// the data plane may not send, whoever the user. It lives in the chain
// egress, which the output chain enters for the data plane's UIDs
// (GuardUIDs) and for UIDs, after the guard of the node's own addresses.
type Egress struct {
	SMTP       bool // TCP to port 25: reset
	BitTorrent bool // the handshake: reset; uTP SYN, UDP tracker connect, DHT query: dropped
	// UIDs are processes it covers besides GuardUIDs: rayd's own where the
	// data plane runs as its children (rayd serve -supervise).
	UIDs []uint32
	// Local refuses the data plane's new flows to the node's own and local
	// networks (R4-38, LocalNets): GuardUIDs only, not UIDs, as the guard
	// of the node's addresses (rayd reaches them itself). Loopback are the
	// ports on 127.0.0.1 it reaches all the same (the channel probe).
	Local    bool
	Loopback []Port
	// Exempt are exact destinations one data-plane process reaches all
	// the same: a REALITY service's target on a local address, from that
	// service's UID only (spec/egress-policy-v1.md §10).
	Exempt []LocalExempt
}

// LocalExempt is a destination by its exact address, protocol and port,
// for one UID.
type LocalExempt struct {
	Addr netip.Addr
	Port Port
	UID  uint32
}

func (x LocalExempt) String() string {
	return fmt.Sprintf("%s %s from uid %d", x.Port.Proto, netip.AddrPortFrom(x.Addr, x.Port.Num), x.UID)
}

// exemptUIDs are the UIDs an exemption may name: a service's process
// (store.FirstServiceUID to store.LastServiceUID), never the front's.
const exemptFirstUID, exemptLastUID = 9110, 9179

// Equal reports whether two policies are the same.
func (e Egress) Equal(o Egress) bool {
	return e.SMTP == o.SMTP && e.BitTorrent == o.BitTorrent && slices.Equal(e.UIDs, o.UIDs) &&
		e.Local == o.Local && slices.Equal(e.Loopback, o.Loopback) && slices.Equal(e.Exempt, o.Exempt)
}

func egressOf(e *perimeterv1.Egress) Egress {
	if e == nil {
		return Egress{}
	}
	uids := slices.Clone(e.Uids)
	slices.Sort(uids)
	out := Egress{SMTP: e.Smtp, BitTorrent: e.Bittorrent, UIDs: slices.Compact(uids)}
	// No Local: a rayd from before R4-38, which leaves local networks to
	// the processes, as then.
	if l := e.GetLocal(); l != nil && !l.Allow {
		out.Local = true
		for _, p := range portsOf(l.Loopback) {
			if (p.Proto == "tcp" || p.Proto == "udp") && p.Num != 0 && !slices.Contains(out.Loopback, p) {
				out.Loopback = append(out.Loopback, p)
			}
		}
		slices.SortFunc(out.Loopback, func(a, b Port) int { return strings.Compare(a.String(), b.String()) })
		// One address, TCP or UDP, a port, a service's UID: anything else
		// of a later rayd is left out, never widened.
		for _, x := range l.GetExempt() {
			a, err := netip.ParseAddr(x.GetAddr())
			p := Port{x.GetPort().GetProto(), uint16(x.GetPort().GetPort())} //nolint:gosec // G115: checked below
			if err != nil || a.Zone() != "" || (p.Proto != "tcp" && p.Proto != "udp") || p.Num == 0 || x.GetPort().GetPort() > 65535 ||
				x.GetUid() < exemptFirstUID || x.GetUid() > exemptLastUID {
				continue
			}
			ex := LocalExempt{Addr: a.Unmap(), Port: p, UID: x.GetUid()}
			if !slices.Contains(out.Exempt, ex) {
				out.Exempt = append(out.Exempt, ex)
			}
		}
		slices.SortFunc(out.Exempt, func(a, b LocalExempt) int { return strings.Compare(a.String(), b.String()) })
	}
	return out
}

// LocalNets are the node's own and local networks the data plane does not
// reach (R4-38): loopback, "this network", private (RFC 1918, ULA),
// CGNAT, link-local with the cloud metadata address 169.254.169.254,
// IETF protocol assignments, benchmarking, multicast, reserved and
// broadcast; and the IPv6 prefixes that carry IPv4 addresses (NAT64,
// 6to4, IPv4-compatible): 64:ff9b::a9fe:a9fe is 169.254.169.254 where
// NAT64 is routed. Xray's routing keeps the same list out of the inner
// stage and REALITY (render.privateNets).
//
// The clouds' platform addresses are in these ranges, but for Azure's
// WireServer, 168.63.129.16, a public address that answers only inside
// Azure (DHCP, DNS, health probes, the guest agent's channel to the
// host): https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16
// The others: AWS's IMDS 169.254.169.254 and fd00:ec2::254, its resolver
// 169.254.169.253 and fd00:ec2::253 (link-local, ULA:
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html,
// https://docs.aws.amazon.com/vpc/latest/userguide/AmazonDNS-concepts.html);
// GCP's 169.254.169.254 and fd20:ce::254 (ULA:
// https://cloud.google.com/compute/docs/metadata/querying-metadata);
// Alibaba's 100.100.100.200 (CGNAT:
// https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata);
// Oracle's and OpenStack's 169.254.169.254, OpenStack's fe80::a9fe:a9fe
// (https://docs.openstack.org/nova/latest/user/metadata.html).
var LocalNets = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "168.63.129.16/32", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	"::/96", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16",
}

// LocalResolvers are the resolvers in LocalNets the data plane reaches
// all the same, on port 53 (TCP and UDP) and no other: systemd-resolved's
// stub (127.0.0.53, and 127.0.0.54 without its DNSSEC and search
// handling), where /etc/resolv.conf points on most hosts, and Azure's
// platform resolver on the WireServer, 168.63.129.16, which resolv.conf
// names itself on an Azure VM without systemd-resolved (RHEL and Rocky
// with NetworkManager): niko-server's Hysteria2 and Yggdrasil look names
// up with the host's resolver. The WireServer's other ports (80 and
// 32526, the guest agent's) stay refused, as the stub's (to_node).
// deploy.SandboxResolverProblem reads the same list: a resolver not in it
// is one the data plane does not reach.
var LocalResolvers = []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("127.0.0.54"), netip.MustParseAddr("168.63.129.16")}

// InLocalNets reports whether a is in LocalNets.
func InLocalNets(a netip.Addr) bool {
	a = a.Unmap()
	for _, n := range LocalNets {
		if netip.MustParsePrefix(n).Contains(a) {
			return true
		}
	}
	return false
}

// LocalRefuses53 reports whether the policy's local part, in force,
// refuses a new flow of the data plane to a's port 53 (a resolver):
// every address of LocalNets but LocalResolvers. What to_node refuses
// before (the node's own addresses) is the caller's to know.
func LocalRefuses53(a netip.Addr) bool {
	return InLocalNets(a) && !slices.Contains(LocalResolvers, a.Unmap())
}

// resolverElems are LocalResolvers of one family as set elements; only
// the loopback ones (the stub's, which to_node guards) with loopback.
func resolverElems(v6, loopback bool) string {
	var out []string
	for _, a := range LocalResolvers {
		if a.Is6() == v6 && (!loopback || a.IsLoopback()) {
			out = append(out, a.String())
		}
	}
	return strings.Join(out, ", ")
}

// localSets are the sets of LocalNets in the table, IPv4 and IPv6.
func localSets() (v4, v6 string) {
	var a, b []string
	for _, n := range LocalNets {
		if strings.Contains(n, ":") {
			b = append(b, n)
		} else {
			a = append(a, n)
		}
	}
	return strings.Join(a, ", "), strings.Join(b, ", ")
}

// EgressRules are the comments of the policy's rules, the label values of
// its metrics (spec/egress-policy-v1.md §6).
var EgressRules = []string{"smtp", "bittorrent-tcp", "bittorrent-utp", "bittorrent-tracker", "bittorrent-dht", "local"}

// egressChains are the policy's chains: SetEgress writes them whole.
var egressChains = []string{"egress", "bt_tracker", "bt_utp", "bt_dht", "egress_local"}

// optionalChains are the parts but local, in a transaction of their own
// (EgressOptionalScript): a kernel that refuses them does not take local
// away, nor the reverse.
var optionalChains = []string{"egress", "bt_tracker", "bt_utp", "bt_dht"}

// The start of the BitTorrent handshake (BEP 3): the length byte 19, then
// "BitTorrent protocol". A raw payload match takes 16 bytes at most, so
// the 20 bytes go as 1 + 16 + 3.
const (
	btLen  = "0x13"
	btName = "0x426974546f7272656e742070726f746f" // "BitTorrent proto"
	btTail = "0x636f6c"                           // "col"
)

// EgressScript is the nft transaction that puts e in force: the extra UIDs
// replaced, the policy's chains flushed and filled, all or nothing. The
// rest of the table, the guard of the node's own addresses included, is
// not touched. doff matches the TCP handshake by the length of the TCP
// header (no options or timestamps, as stacks send data) for kernels
// without the inner header base (@ih).
//
// Every rule counts what it blocks; none logs: a log line would carry the
// destination (spec/egress-policy-v1.md §6).
func EgressScript(e Egress, doff bool) string {
	return EgressLocalScript(e) + EgressOptionalScript(e, doff)
}

// EgressOptionalScript is the transaction of the policy's parts but
// local: the extra UIDs, SMTP and BitTorrent.
func EgressOptionalScript(e Egress, doff bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s egress_uid\n", Table)
	if len(e.UIDs) > 0 {
		uids := make([]string, len(e.UIDs))
		for i, u := range e.UIDs {
			uids[i] = strconv.FormatUint(uint64(u), 10)
		}
		fmt.Fprintf(&b, "add element inet %s egress_uid { %s }\n", Table, strings.Join(uids, ", "))
	}
	for _, c := range optionalChains {
		fmt.Fprintf(&b, "flush chain inet %s %s\n", Table, c)
	}
	rule := func(chain, r string) { fmt.Fprintf(&b, "add rule inet %s %s %s\n", Table, chain, r) }
	if e.SMTP {
		// No conntrack state: every packet to 25, so that a connection
		// opened before the policy ends too.
		rule("egress", `tcp dport 25 counter reject with tcp reset comment "smtp"`)
	}
	if e.BitTorrent {
		const verdict = `counter reject with tcp reset comment "bittorrent-tcp"`
		if doff {
			for _, words := range []int{5, 8} {
				at := words * 32
				rule("egress", fmt.Sprintf("tcp doff %d @th,%d,8 %s @th,%d,128 %s @th,%d,24 %s %s",
					words, at, btLen, at+8, btName, at+136, btTail, verdict))
			}
		} else {
			rule("egress", fmt.Sprintf("meta l4proto tcp @ih,0,8 %s @ih,8,128 %s @ih,136,24 %s %s", btLen, btName, btTail, verdict))
		}
		// UDP by the first byte of the payload: the UDP header is always
		// 8 bytes, so the offsets are from it on any kernel.
		rule("egress", "meta l4proto udp @th,64,8 vmap { 0x00 : jump bt_tracker, 0x41 : jump bt_utp, 0x64 : jump bt_dht }")
		// BEP 15: connect, the protocol ID and action 0.
		rule("bt_tracker", `@th,64,64 0x41727101980 @th,128,32 0 counter drop comment "bittorrent-tracker"`)
		// BEP 29: ST_SYN (type 4, version 1) with timestamp_difference 0,
		// alone (libtorrent, 20 bytes) or with the extension bits (µTorrent,
		// 30 bytes): the extension byte too, as the Xray fork's check
		// does, so that a 20-byte DNS query without EDNS matches only with
		// the ID 0x4100, not 0x41xx.
		rule("bt_utp", `udp length 28 @th,72,8 0 @th,128,32 0 counter drop comment "bittorrent-utp"`)
		rule("bt_utp", `udp length 38 @th,72,8 2 @th,128,32 0 @th,224,16 8 counter drop comment "bittorrent-utp"`)
		// BEP 5: a query, "d1:ad2:id20:" (bencode sorts the keys).
		rule("bt_dht", `@th,64,96 0x64313a6164323a696432303a counter drop comment "bittorrent-dht"`)
	}
	return b.String()
}

// EgressLocalScript is the transaction of the policy's local part
// (R4-38): egress_local flushed and, when on, filled. It goes first and on
// its own (SetEgress): closed by default, it must not depend on a kernel
// taking the BitTorrent rules.
func EgressLocalScript(e Egress) string {
	var b strings.Builder
	fmt.Fprintf(&b, "flush chain inet %s egress_local\n", Table)
	rule := func(chain, r string) { fmt.Fprintf(&b, "add rule inet %s %s %s\n", Table, chain, r) }
	if e.Local {
		// Only the data plane's new flows come here (the output chain):
		// the node's own and local networks are refused, but for the
		// resolvers on 53 (LocalResolvers: systemd-resolved's stub, whose
		// other ports to_node refuses before, and Azure's) and the channel
		// probe on 127.0.0.1. A refusal the socket
		// sees at once, as to_node's: TCP a reset (ECONNREFUSED), UDP and
		// ICMP EPERM. An ICMP error to a connect comes while connect holds
		// the socket, counts as a soft error, and the refusal waits for the
		// SYN's first retransmission, a second. naive and Hysteria2 answer
		// an honest connect "denied" from their own check before it comes
		// to this.
		for _, family := range []string{"ip", "ip6"} {
			if elems := resolverElems(family == "ip6", false); elems != "" {
				rule("egress_local", fmt.Sprintf("meta l4proto { tcp, udp } %s daddr { %s } th dport 53 return", family, elems))
			}
		}
		// An operator's REALITY target on a local address: that address,
		// protocol and port, from that service's process only.
		for _, x := range e.Exempt {
			family := "ip"
			if x.Addr.Is6() {
				family = "ip6"
			}
			rule("egress_local", fmt.Sprintf("meta skuid %d %s daddr %s meta l4proto %s th dport %d return", x.UID, family, x.Addr, x.Port.Proto, x.Port.Num))
		}
		if len(e.Loopback) > 0 {
			rule("egress_local", fmt.Sprintf("ip daddr 127.0.0.1 meta l4proto . th dport { %s } return", strings.Join(portElems(e.Loopback), ", ")))
		}
		for _, set := range []string{"ip daddr @local4", "ip6 daddr @local6"} {
			rule("egress_local", set+` meta l4proto tcp counter reject with tcp reset comment "local"`)
			rule("egress_local", set+` counter reject with icmpx admin-prohibited comment "local"`)
		}
	}
	return b.String()
}

// SetEgress puts the egress policy in force in two transactions: local
// first (EgressLocalScript), then the rest (EgressOptionalScript). A
// refusal of one leaves that one as it was and takes nothing of the other
// or of the table; an error says which. A kernel without the inner header
// base (@ih) gets the TCP handshake by the TCP header's length. On a relay
// it does nothing: no data plane runs there.
func (n *NFT) SetEgress(e Egress) error {
	if n.RelayTo.IsValid() {
		return nil
	}
	var errs []error
	if err := n.run(EgressLocalScript(e)); err != nil {
		errs = append(errs, fmt.Errorf("local: %w", err))
	}
	if err := n.setOptional(e); err != nil {
		errs = append(errs, fmt.Errorf("smtp, bittorrent: %w", err))
	}
	return errors.Join(errs...)
}

func (n *NFT) setOptional(e Egress) error {
	if !e.BitTorrent || n.egressDoff {
		return n.run(EgressOptionalScript(e, n.egressDoff))
	}
	err := n.run(EgressOptionalScript(e, false))
	if err == nil {
		return nil
	}
	if n.run(EgressOptionalScript(e, true)) == nil {
		n.egressDoff = true
		return nil
	}
	return err
}

// Check dry-runs an nft script in the kernel (nft -c): nothing changes.
func (n *NFT) Check(script string) ([]byte, error) {
	bin := n.Bin
	if bin == "" {
		bin = "nft"
	}
	cmd := exec.Command(bin, "-c", "-f", "-") //nolint:gosec // G204: see run
	cmd.Stdin = strings.NewReader(script)
	return cmd.CombinedOutput()
}

// CheckEgress dry-runs the policy in the kernel on the perimeter table as
// Setup makes it, before anything changes: run takes the script on nft -c's
// standard input. It says whether the TCP handshake needs the tcp doff
// rules (no @ih in this kernel), or why the kernel refuses the policy.
func CheckEgress(e Egress, run func(script string) ([]byte, error)) (doff bool, err error) {
	table := (&NFT{NflogGroup: 7}).Ruleset()
	out, err := run(table + EgressScript(e, false))
	if err == nil {
		return false, nil
	}
	refused := fmt.Errorf("%w: %s", err, firstLines(out, 3))
	if !e.BitTorrent {
		return false, refused
	}
	outDoff, errDoff := run(table + EgressScript(e, true))
	if errDoff == nil {
		return true, nil
	}
	return false, fmt.Errorf("%w; with tcp doff in place of @ih: %w: %s", refused, errDoff, firstLines(outDoff, 3))
}

func firstLines(b []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "; ")
}

// EgressBlocks reads the counters of the policy's rules by their comment
// (EgressRules) for local metrics: packets and bytes blocked, never where
// to or whose. A part not in force has no rules, so no entry.
func (n *NFT) EgressBlocks() (map[string]Drops, error) {
	out := map[string]Drops{}
	for _, c := range egressChains {
		if c == "egress_local" {
			if ok, _ := n.hasChain(c); !ok {
				continue // a table from before R4-38
			}
		}
		counts, err := n.counters(c)
		if err != nil {
			return nil, err
		}
		for rule, d := range counts {
			sum := out[rule]
			sum.Packets += d.Packets
			sum.Bytes += d.Bytes
			out[rule] = sum
		}
	}
	return out, nil
}
