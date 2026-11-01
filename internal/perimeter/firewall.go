// Package perimeter runs the node perimeter: an nftables table that drops
// everything except the SPA slot ports and public ports, and grants that
// open service ports to an address after a valid SPA v2 packet.
package perimeter

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
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
	SetSPAPorts(udp, tcp []uint16) error
	SetPublic(ports []Port) error
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

// Ruleset returns the table definition. It replaces any previous version of
// the table atomically.
func (n *NFT) Ruleset() string {
	rate := n.RateLimit
	if rate <= 0 {
		rate = 20
	}
	limit := fmt.Sprintf("limit rate over %d/second burst %d packets", rate, 2*rate)
	lo := `iif "lo" accept`
	if n.FilterLoopback {
		lo = "# loopback filtered (test)"
	}
	return fmt.Sprintf(`table inet %[1]s {}
delete table inet %[1]s
table inet %[1]s {
	set spa_udp { type inet_service; }
	set spa_tcp { type inet_service; }
	set public { type inet_proto . inet_service; }
	set allow4 { type ipv4_addr . inet_proto . inet_service; flags timeout; size 65536; }
	set allow6 { type ipv6_addr . inet_proto . inet_service; flags timeout; size 65536; }
	set rate4 { type ipv4_addr; flags dynamic, timeout; timeout 1m; size 65536; }
	set rate6 { type ipv6_addr; flags dynamic, timeout; timeout 1m; size 65536; }

	chain input {
		type filter hook input priority -10; policy drop;
		%[4]s
		ct state established,related accept
		ct state invalid drop
		icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept

		udp dport @spa_udp update @rate4 { ip saddr %[2]s } drop
		udp dport @spa_udp update @rate6 { ip6 saddr %[2]s } drop
		udp dport @spa_udp log group %[3]d drop

		tcp dport @spa_tcp tcp flags syn update @rate4 { ip saddr %[2]s } drop
		tcp dport @spa_tcp tcp flags syn update @rate6 { ip6 saddr %[2]s } drop
		tcp dport @spa_tcp accept

		meta l4proto . th dport @public accept
		ip saddr . meta l4proto . th dport @allow4 accept
		ip6 saddr . meta l4proto . th dport @allow6 accept
	}
}
`, Table, limit, n.NflogGroup, lo)
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
		elems := make([]string, len(ports))
		for i, p := range ports {
			elems[i] = fmt.Sprintf("%s . %d", p.Proto, p.Num)
		}
		fmt.Fprintf(&b, "add element inet %s public { %s }\n", Table, strings.Join(elems, ", "))
	}
	return n.run(b.String())
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
			parts[i] += fmt.Sprintf(" timeout %ds", int(ttl/time.Second))
		}
	}
	return set, strings.Join(parts, ", ")
}

// Allow opens ports for addr until ttl passes; a repeat resets the timer.
func (n *NFT) Allow(addr netip.Addr, ports []Port, ttl time.Duration) error {
	if len(ports) == 0 {
		return nil
	}
	set, keys := elements(addr, ports, 0)
	_, elems := elements(addr, ports, ttl)
	add := fmt.Sprintf("add element inet %s %s { %s }\n", Table, set, elems)
	if n.destroy {
		// One transaction: the old element (if any) goes, the new timer starts.
		return n.run(fmt.Sprintf("destroy element inet %s %s { %s }\n", Table, set, keys) + add)
	}
	// Older nft and kernels: delete may fail when the element is absent.
	for _, p := range ports {
		_, k := elements(addr, []Port{p}, 0)
		_ = n.run(fmt.Sprintf("delete element inet %s %s { %s }\n", Table, set, k))
	}
	return n.run(add)
}

// Deny closes ports for addr now.
func (n *NFT) Deny(addr netip.Addr, ports []Port) error {
	var firstErr error
	for _, p := range ports {
		set, k := elements(addr, []Port{p}, 0)
		verb := "delete"
		if n.destroy {
			verb = "destroy"
		}
		if err := n.run(fmt.Sprintf("%s element inet %s %s { %s }\n", verb, Table, set, k)); err != nil && n.destroy && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
