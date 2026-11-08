package perimeter

import (
	"fmt"
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
}

// Equal reports whether two policies are the same.
func (e Egress) Equal(o Egress) bool {
	return e.SMTP == o.SMTP && e.BitTorrent == o.BitTorrent && slices.Equal(e.UIDs, o.UIDs)
}

func egressOf(e *perimeterv1.Egress) Egress {
	if e == nil {
		return Egress{}
	}
	uids := slices.Clone(e.Uids)
	slices.Sort(uids)
	return Egress{SMTP: e.Smtp, BitTorrent: e.Bittorrent, UIDs: slices.Compact(uids)}
}

// EgressRules are the comments of the policy's rules, the label values of
// its metrics (spec/egress-policy-v1.md §6).
var EgressRules = []string{"smtp", "bittorrent-tcp", "bittorrent-utp", "bittorrent-tracker", "bittorrent-dht"}

// egressChains are the policy's chains: SetEgress writes them whole.
var egressChains = []string{"egress", "bt_tracker", "bt_utp", "bt_dht"}

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
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s egress_uid\n", Table)
	if len(e.UIDs) > 0 {
		uids := make([]string, len(e.UIDs))
		for i, u := range e.UIDs {
			uids[i] = strconv.FormatUint(uint64(u), 10)
		}
		fmt.Fprintf(&b, "add element inet %s egress_uid { %s }\n", Table, strings.Join(uids, ", "))
	}
	for _, c := range egressChains {
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

// SetEgress puts the egress policy in force in one transaction: a refusal
// leaves it as it was, and nothing else of the table changes. A kernel
// without the inner header base (@ih) gets the TCP handshake by the TCP
// header's length. On a relay it does nothing: no data plane runs there.
func (n *NFT) SetEgress(e Egress) error {
	if n.RelayTo.IsValid() {
		return nil
	}
	if !e.BitTorrent || n.egressDoff {
		return n.run(EgressScript(e, n.egressDoff))
	}
	err := n.run(EgressScript(e, false))
	if err == nil {
		return nil
	}
	if n.run(EgressScript(e, true)) == nil {
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
