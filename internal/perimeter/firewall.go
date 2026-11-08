// Package perimeter runs the node perimeter: an nftables table that drops
// everything except the SPA slot ports and public ports, and grants that
// open service ports to an address after a valid SPA v2 packet.
package perimeter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Port is a transport port on the node.
type Port struct {
	Proto string // tcp | udp
	Num   uint16
}

func (p Port) String() string { return p.Proto + "/" + strconv.Itoa(int(p.Num)) }

// Firewall is what the gate needs from the packet filter.
type Firewall interface {
	// Setup (re)creates the table. Existing grants are lost; established
	// connections survive through conntrack.
	Setup() error
	// Present reports whether the table is still there: "flush ruleset"
	// (an nftables.service restart on Debian) removes it with everything else.
	Present() (bool, error)
	SetSPAPorts(udp, tcp []uint16) error
	SetPublic(ports []Port) error
	// SetAdmin opens ports (SSH) to the given prefixes without SPA:
	// emergency access when SPA itself fails.
	SetAdmin(prefixes []netip.Prefix, ports []Port) error
	// SetForward replaces the ports a relay forwards to its exit (no-op
	// when the host is not a relay).
	SetForward(ports []Port) error
	// SetRelays opens the service ports to relays' addresses without SPA
	// (relay-v1): devices knock at the relay, which forwards to this node.
	SetRelays(addrs []netip.Prefix, ports []Port) error
	// SetRotation replaces the UDP slot ports redirected to service ports
	// (spa-v2.md §11): slot port -> service port.
	SetRotation(udp map[uint16]uint16) error
	// SetACME opens the ACME window: TCP 80 from anyone to port, for ttl.
	// The elements expire by themselves; ttl 0 closes the window now.
	SetACME(port uint16, ttl time.Duration) error
	Allow(addr netip.Addr, ports []Port, ttl time.Duration) error
	Deny(addr netip.Addr, ports []Port) error
	Teardown() error
}

// Table is the nftables table raycontrol owns. Nothing else in the ruleset
// is touched: other tables (Docker, distribution defaults) keep working,
// and a packet must be accepted by every base chain to pass.
const Table = "raycontrol"

// NFT drives nftables through the nft binary.
type NFT struct {
	NflogGroup uint16
	// RateLimit is how many SPA packets (UDP) or SYNs (TCP) per second one
	// source address may send to the slot ports.
	RateLimit int
	Bin       string // nft binary, "nft" when empty
	// FilterLoopback drops the "accept everything on lo" rule. Only for tests
	// in a network namespace, where all traffic is loopback.
	FilterLoopback bool
	// GuardUIDs are the data-plane processes (DataPlaneUIDs when empty):
	// they carry users' traffic, which must not reach the node itself.
	GuardUIDs string
	// RelayTo makes this host a relay (relay-v1 §3.1): the forwarded ports
	// (SetForward) go to this exit by DNAT, only from addresses with an SPA
	// grant, masqueraded. Invalid: not a relay.
	RelayTo netip.Addr

	destroy bool // nft and kernel support "destroy element"
}

func (n *NFT) run(script string) error {
	bin := n.Bin
	if bin == "" {
		bin = "nft"
	}
	cmd := exec.Command(bin, "-f", "-") //nolint:gosec // G204: the binary is the operator's nft; the script goes through stdin.
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// DataPlaneUIDs are the UIDs of the front and the data-plane services
// (render.FrontUID to store.LastServiceUID, docs/08-decisions.md, R1-6).
const DataPlaneUIDs = "9100-9179"

// Ruleset returns the table definition. It replaces any previous version of
// the table atomically.
func (n *NFT) Ruleset() string {
	rate := n.RateLimit
	if rate <= 0 {
		rate = 20
	}
	limit := fmt.Sprintf("limit rate over %d/second burst %d packets", rate, 2*rate)
	lo := `iif "lo" accept`
	// Local traffic skips prerouting; tests in a namespace need the same
	// redirect on output.
	loNAT := ""
	if n.FilterLoopback {
		lo = "# loopback filtered (test)"
		loNAT = "chain output_nat { type nat hook output priority -100; policy accept; udp dport @rot_udp redirect to : udp dport map @rot_udp; " +
			"tcp dport @acme_redirect redirect to : tcp dport map @acme_redirect; }"
	}
	guard := n.GuardUIDs
	if guard == "" {
		guard = DataPlaneUIDs
	}
	relay := ""
	if to := n.RelayTo.Unmap(); to.IsValid() {
		family, nfproto, saddr, set := "ip", "ipv4", "ip saddr", "@allow4"
		if to.Is6() {
			family, nfproto, saddr, set = "ip6", "ipv6", "ip6 saddr", "@allow6"
		}
		relay = fmt.Sprintf(`
	# A relay (relay-v1 §3.1): the forwarded ports go to the exit, in the
	# kernel; only from an address with an SPA grant for the port.
	set relay_fwd { type inet_proto . inet_service; }
	chain relay_dnat {
		type nat hook prerouting priority dstnat - 1; policy accept;
		meta nfproto %[5]s fib daddr type local meta l4proto . th dport @relay_fwd dnat %[1]s to %[2]s
	}
	chain relay_forward {
		type filter hook forward priority 0; policy drop;
		ct state established,related accept
		ct status dnat %[1]s daddr %[2]s %[3]s . meta l4proto . th dport %[4]s accept
		ct status dnat %[1]s daddr %[2]s counter drop comment "relay-no-grant"
		counter comment "relay-not-forwarded"
	}
	chain relay_snat {
		type nat hook postrouting priority srcnat; policy accept;
		ct status dnat %[1]s daddr %[2]s masquerade
	}`, family, to, saddr, set, nfproto)
	}
	return fmt.Sprintf(`table inet %[1]s {}
delete table inet %[1]s
table inet %[1]s {
	set spa_udp { type inet_service; }
	set spa_tcp { type inet_service; }
	set public { type inet_proto . inet_service; }
	set allow4 { type ipv4_addr . inet_proto . inet_service; flags timeout; size 65536; }
	set allow6 { type ipv6_addr . inet_proto . inet_service; flags timeout; size 65536; }
	set admin4 { type ipv4_addr; flags interval; }
	set admin6 { type ipv6_addr; flags interval; }
	set admin_ports { type inet_proto . inet_service; }
	set relay4 { type ipv4_addr; }
	set relay6 { type ipv6_addr; }
	set relay_ports { type inet_proto . inet_service; }
	map rot_udp { type inet_service : inet_service; }
	map acme_redirect { type inet_service : inet_service; flags timeout; }
	set acme_in { type inet_service; flags timeout; }
	set rate4 { type ipv4_addr; flags dynamic, timeout; timeout 1m; size 65536; }
	set rate6 { type ipv6_addr; flags dynamic, timeout; timeout 1m; size 65536; }

	# Before defragmentation and conntrack (priority -400 and -200): what the
	# kernel never has to parse for anyone, packets to the node itself only
	# (docs/08-decisions.md, R4-9). Fragments, IPv4 options and IPv6
	# extension headers are where remote bugs of IP stacks keep turning up;
	# clients need none of them (SPA packets are small, QUIC sets DF, TCP
	# does path MTU discovery). ICMP errors, packet-too-big included, pass.
	chain early {
		type filter hook prerouting priority -450; policy accept;
		%[6]s
		fib daddr type != local accept
		ip frag-off & 0x3fff != 0 counter drop comment "ipv4-fragment"
		ip hdrlength != 5 counter drop comment "ipv4-options"
		meta nfproto ipv6 exthdr frag exists counter drop comment "ipv6-fragment"
		meta nfproto ipv6 exthdr rt exists counter drop comment "ipv6-routing"
		meta nfproto ipv6 exthdr dst exists counter drop comment "ipv6-dstopts"
		meta nfproto ipv6 exthdr hbh exists ip6 saddr != fe80::/10 counter drop comment "ipv6-hopopts"
		tcp flags & (fin | syn) == fin | syn counter drop comment "tcp-syn-fin"
		tcp flags & (syn | rst) == syn | rst counter drop comment "tcp-syn-rst"
		tcp flags & (fin | syn | rst | psh | ack | urg) == 0x0 counter drop comment "tcp-null"
		tcp flags & (fin | syn | rst | psh | ack | urg) == fin | psh | urg counter drop comment "tcp-xmas"
	}

	# Rotated UDP slot ports land on the service port; the input chain then
	# applies the SPA grants of that port as usual.
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		udp dport @rot_udp redirect to : udp dport map @rot_udp
		tcp dport @acme_redirect redirect to : tcp dport map @acme_redirect
	}
	%[5]s

	chain input {
		type filter hook input priority -10; policy drop;
		%[4]s
		ct mark & %[9]s == %[9]s ct state established ct direction original jump relay_check
		ct state established,related accept
		ct state invalid drop
		icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept

		udp dport @spa_udp update @rate4 { ip saddr %[2]s } drop
		udp dport @spa_udp update @rate6 { ip6 saddr %[2]s } drop
		udp dport @spa_udp log group %[3]d drop

		tcp dport @spa_tcp tcp flags syn update @rate4 { ip saddr %[2]s } drop
		tcp dport @spa_tcp tcp flags syn update @rate6 { ip6 saddr %[2]s } drop
		jump admit
	}

	# What lets a flow in. A relay's flows (most of an exit's traffic when
	# it has relays: first) are marked in conntrack, so that relay_check
	# can tell them later.
	chain admit {
		ip saddr @relay4 meta l4proto . th dport @relay_ports ct mark set ct mark | %[9]s accept
		ip6 saddr @relay6 meta l4proto . th dport @relay_ports ct mark set ct mark | %[9]s accept
		tcp dport @spa_tcp accept
		tcp dport @acme_in accept
		meta l4proto . th dport @public accept
		ip saddr @admin4 meta l4proto . th dport @admin_ports accept
		ip6 saddr @admin6 meta l4proto . th dport @admin_ports accept
		ip saddr . meta l4proto . th dport @allow4 accept
		ip6 saddr . meta l4proto . th dport @allow6 accept
	}

	# A flow a relay opened goes on only while something still lets it in
	# (admit): a relay removed, or a service no longer forwarded, loses
	# the flows it had open too, not only new ones, unless its port is
	# public or the address has a grant. TCP gets a reset. Related packets
	# (ICMP errors from routers on the way) and the node's replies are not
	# looked at. SetRelays fills it: until then, after Setup, open flows
	# go on as before.
	chain relay_check {
	}

	# Users' traffic does not reach the node itself (S-2): a proxy exit
	# connecting to one of the node's own addresses would come in on lo,
	# past SPA and the admin addresses, to SSH, the API and the
	# subscription. Loopback stays with the processes' own rules (Xray's
	# block list, systemd's IPAddressDeny): the channel probe goes there.
	# A local destination always leaves through lo, so every other packet
	# stops at the first, cheapest match; the FIB lookup comes last.
	# A subnet's broadcast address looks public to the processes and
	# reaches the node and its neighbours: refused too, looked up only for
	# UDP the conntrack has not seen answered (broadcast never is).
	# systemd-resolved's stub, which units that resolve may reach
	# (IPAddressAllow), answers on 53 only: whatever else listens on any
	# address does not take the data plane there.
	chain output {
		type filter hook output priority 0; policy accept;
		oif "lo" meta skuid %[7]s ip daddr != 127.0.0.0/8 fib daddr type local jump to_node
		oif "lo" meta skuid %[7]s ip6 daddr != ::1 fib daddr type local jump to_node
		meta nfproto ipv4 meta l4proto udp ct state != established meta skuid %[7]s fib daddr type broadcast jump to_node
		oif "lo" meta skuid %[7]s ip daddr { 127.0.0.53, 127.0.0.54 } meta l4proto { tcp, udp } th dport != 53 jump to_node
	}
	chain to_node {
		counter comment "data-plane-to-node"
		meta l4proto tcp reject with tcp reset
		reject with icmpx admin-prohibited
	}%[8]s
}
`, Table, limit, n.NflogGroup, lo, loNAT, lo, guard, relay, relayMark)
}

// Setup installs the table and detects whether "destroy element" works.
func (n *NFT) Setup() error {
	if err := n.run(n.Ruleset()); err != nil {
		return err
	}
	probe := fmt.Sprintf("destroy element inet %s allow4 { 192.0.2.1 . tcp . 1 }\n", Table)
	n.destroy = n.run(probe) == nil
	return nil
}

// Present looks the table up in "nft list tables".
func (n *NFT) Present() (bool, error) {
	bin := n.Bin
	if bin == "" {
		bin = "nft"
	}
	out, err := exec.Command(bin, "list", "tables").Output() //nolint:gosec // G204: see run
	if err != nil {
		return false, fmt.Errorf("nft list tables: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "table inet "+Table {
			return true, nil
		}
	}
	return false, nil
}

// Teardown removes the table.
func (n *NFT) Teardown() error {
	return n.run(fmt.Sprintf("table inet %[1]s {}\ndelete table inet %[1]s\n", Table))
}

func joinPorts(ports []uint16) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(int(p))
	}
	return strings.Join(s, ", ")
}

// SetSPAPorts replaces the slot ports in one transaction.
func (n *NFT) SetSPAPorts(udp, tcp []uint16) error {
	var b strings.Builder
	for _, set := range []struct {
		name  string
		ports []uint16
	}{{"spa_udp", udp}, {"spa_tcp", tcp}} {
		fmt.Fprintf(&b, "flush set inet %s %s\n", Table, set.name)
		if len(set.ports) > 0 {
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", Table, set.name, joinPorts(set.ports))
		}
	}
	return n.run(b.String())
}

// SetPublic replaces the ports open to everyone.
func (n *NFT) SetPublic(ports []Port) error {
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s public\n", Table)
	if len(ports) > 0 {
		fmt.Fprintf(&b, "add element inet %s public { %s }\n", Table, strings.Join(portElems(ports), ", "))
	}
	return n.run(b.String())
}

// SetAdmin replaces the admin prefixes and ports in one transaction.
func (n *NFT) SetAdmin(prefixes []netip.Prefix, ports []Port) error {
	var v4, v6 []string
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	var b strings.Builder
	for _, set := range []struct {
		name  string
		elems []string
	}{{"admin4", v4}, {"admin6", v6}, {"admin_ports", portElems(ports)}} {
		fmt.Fprintf(&b, "flush set inet %s %s\n", Table, set.name)
		if len(set.elems) > 0 {
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", Table, set.name, strings.Join(set.elems, ", "))
		}
	}
	return n.run(b.String())
}

// SetForward replaces the ports a relay forwards (relay-v1 §3.1).
func (n *NFT) SetForward(ports []Port) error {
	if !n.RelayTo.IsValid() {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s relay_fwd\n", Table)
	if elems := portElems(ports); len(elems) > 0 {
		fmt.Fprintf(&b, "add element inet %s relay_fwd { %s }\n", Table, strings.Join(elems, ", "))
	}
	return n.run(b.String())
}

// relayMark is the conntrack mark bit of flows a relay opened (admit,
// relay_check); other bits stay as they are. Rules elsewhere that set the
// whole mark, or match it without a mask, see this bit too
// (docs/08-decisions.md, R4-32).
const relayMark = "0x00400000"

// SetRelays replaces the relays' addresses (single ones) and the ports they
// reach, and turns relay_check on: the flows a relay opened end when
// nothing lets them in any more.
func (n *NFT) SetRelays(addrs []netip.Prefix, ports []Port) error {
	var v4, v6 []string
	for _, p := range addrs {
		if p.Addr().Is4() {
			v4 = append(v4, p.Addr().String())
		} else {
			v6 = append(v6, p.Addr().String())
		}
	}
	var b strings.Builder
	for _, set := range []struct {
		name  string
		elems []string
	}{{"relay4", v4}, {"relay6", v6}, {"relay_ports", portElems(ports)}} {
		fmt.Fprintf(&b, "flush set inet %s %s\n", Table, set.name)
		if len(set.elems) > 0 {
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", Table, set.name, strings.Join(set.elems, ", "))
		}
	}
	// With the sets, in the same transaction.
	fmt.Fprintf(&b, "flush chain inet %[1]s relay_check\n"+
		"add rule inet %[1]s relay_check jump admit\n"+
		"add rule inet %[1]s relay_check counter comment \"relay-removed\"\n"+
		"add rule inet %[1]s relay_check meta l4proto tcp reject with tcp reset\n"+
		"add rule inet %[1]s relay_check drop\n", Table)
	return n.run(b.String())
}

// SetRotation replaces the rotation map in one transaction.
func (n *NFT) SetRotation(udp map[uint16]uint16) error {
	var b strings.Builder
	fmt.Fprintf(&b, "flush map inet %s rot_udp\n", Table)
	if len(udp) > 0 {
		keys := make([]int, 0, len(udp))
		for k := range udp {
			keys = append(keys, int(k))
		}
		sort.Ints(keys)
		elems := make([]string, len(keys))
		for i, k := range keys {
			elems[i] = fmt.Sprintf("%d : %d", k, udp[uint16(k)])
		}
		fmt.Fprintf(&b, "add element inet %s rot_udp { %s }\n", Table, strings.Join(elems, ", "))
	}
	return n.run(b.String())
}

// SetACME replaces the ACME window in one transaction.
func (n *NFT) SetACME(port uint16, ttl time.Duration) error {
	var b strings.Builder
	fmt.Fprintf(&b, "flush map inet %s acme_redirect\nflush set inet %s acme_in\n", Table, Table)
	if port != 0 && ttl > 0 {
		secs := int((ttl + time.Second - 1) / time.Second)
		fmt.Fprintf(&b, "add element inet %s acme_redirect { 80 timeout %ds : %d }\n", Table, secs, port)
		fmt.Fprintf(&b, "add element inet %s acme_in { %d timeout %ds }\n", Table, port, secs)
	}
	return n.run(b.String())
}

func portElems(ports []Port) []string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = fmt.Sprintf("%s . %d", p.Proto, p.Num)
	}
	return out
}

func elements(addr netip.Addr, ports []Port, ttl time.Duration) (set, elems string) {
	set = "allow4"
	if addr.Is6() && !addr.Is4In6() {
		set = "allow6"
	}
	addr = addr.Unmap()
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%s . %s . %d", addr, p.Proto, p.Num)
		if ttl > 0 {
			// Whole seconds, rounded up: "timeout 0s" would never expire.
			parts[i] += fmt.Sprintf(" timeout %ds", int((ttl+time.Second-1)/time.Second))
		}
	}
	return set, strings.Join(parts, ", ")
}

// Allow opens ports for addr until ttl passes; a repeat sets the timer anew,
// shorter or longer.
func (n *NFT) Allow(addr netip.Addr, ports []Port, ttl time.Duration) error {
	if len(ports) == 0 {
		return nil
	}
	set, elems := elements(addr, ports, ttl)
	// One transaction: the old element (if any) goes, the new timer starts.
	return n.run(n.forget(addr, ports) + fmt.Sprintf("add element inet %s %s { %s }\n", Table, set, elems))
}

// forget is the part of a transaction that removes elements, there or not.
// Without "destroy element" (nft before 1.0.8, kernels before 6.3), adding
// first makes the delete unable to fail for an absent element, so that the
// transaction fails only for real.
func (n *NFT) forget(addr netip.Addr, ports []Port) string {
	set, keys := elements(addr, ports, 0)
	if n.destroy {
		return fmt.Sprintf("destroy element inet %s %s { %s }\n", Table, set, keys)
	}
	_, placeholders := elements(addr, ports, time.Second)
	return fmt.Sprintf("add element inet %[1]s %[2]s { %[3]s }\ndelete element inet %[1]s %[2]s { %[4]s }\n", Table, set, placeholders, keys)
}

// Grant is a port open to an address for the time left.
type Grant struct {
	Addr netip.Addr
	Port Port
	TTL  time.Duration
}

// AllowAll opens the grants in one transaction, on a table just made
// (Setup): there is nothing of theirs to replace.
func (n *NFT) AllowAll(grants []Grant) error {
	var b strings.Builder
	for _, gr := range grants {
		set, elems := elements(gr.Addr, []Port{gr.Port}, gr.TTL)
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", Table, set, elems)
	}
	if b.Len() == 0 {
		return nil
	}
	return n.run(b.String())
}

// Deny closes ports for addr now, in one transaction; an error is real.
func (n *NFT) Deny(addr netip.Addr, ports []Port) error {
	if len(ports) == 0 {
		return nil
	}
	return n.run(n.forget(addr, ports))
}

// Drops counts what one rule of the early chain dropped.
type Drops struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// EarlyDrops reads the counters of the early chain by reason (the rule's
// comment) for local metrics.
func (n *NFT) EarlyDrops() (map[string]Drops, error) {
	bin := n.Bin
	if bin == "" {
		bin = "nft"
	}
	out, err := exec.Command(bin, "-j", "list", "chain", "inet", Table, "early").Output() //nolint:gosec // G204: see run
	if err != nil {
		return nil, fmt.Errorf("nft list chain early: %w", err)
	}
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string            `json:"comment"`
				Expr    []json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("nft list chain early: %w", err)
	}
	drops := map[string]Drops{}
	for _, o := range doc.Nftables {
		if o.Rule == nil || o.Rule.Comment == "" {
			continue
		}
		for _, e := range o.Rule.Expr {
			var c struct {
				Counter *Drops `json:"counter"`
			}
			if json.Unmarshal(e, &c) == nil && c.Counter != nil {
				d := drops[o.Rule.Comment]
				d.Packets += c.Counter.Packets
				d.Bytes += c.Counter.Bytes
				drops[o.Rule.Comment] = d
			}
		}
	}
	return drops, nil
}
