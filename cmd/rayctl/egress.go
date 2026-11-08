package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/perimeter"
)

// What rayctl egress asks of the host; tests replace them.
var (
	egressEuid   = os.Geteuid
	egressCheck  = (&perimeter.NFT{}).Check        // the kernel's dry run (nft -c)
	egressBlocks = (&perimeter.NFT{}).EgressBlocks // the rules in force and their counters
)

// egress is rayctl egress (spec/egress-policy-v1.md): the node's egress
// policy, whether rayspa has it in force and, for root, what it blocked;
// block and allow change it, root only, on the node.
func (c *cli) egress(ctx context.Context, args []string) error {
	switch {
	case len(args) == 0 || len(args) == 1 && args[0] == "show":
		return c.egressShow(ctx)
	case len(args) == 2 && (args[0] == "block" || args[0] == "allow") && (args[1] == "bittorrent" || args[1] == "smtp"):
		return c.egressSet(ctx, args[0] == "block", args[1])
	}
	return errUsage
}

func (c *cli) egressSet(ctx context.Context, block bool, part string) error {
	if egressEuid() != 0 {
		return errors.New("rayctl egress " + map[bool]string{true: "block", false: "allow"}[block] + ": root only")
	}
	req := &nodev1.SetEgressRequest{}
	if part == "bittorrent" {
		req.Bittorrent = &block
	} else {
		req.Smtp = &block
	}
	doff := false
	if block {
		// What rayspa will write, through the kernel first (nft -c), as
		// rayctl check does with the table: a refusal changes nothing.
		cur, err := c.c.GetEgress(ctx, connect.NewRequest(&nodev1.GetEgressRequest{}))
		if err != nil {
			return err
		}
		want := perimeter.Egress{SMTP: cur.Msg.GetEgress().GetSmtp() || part == "smtp",
			BitTorrent: cur.Msg.GetEgress().GetBittorrent() || part == "bittorrent", UIDs: cur.Msg.Uids}
		if doff, err = perimeter.CheckEgress(want, egressCheck); err != nil {
			return fmt.Errorf("the kernel does not take the egress policy, nothing changed: %w", err)
		}
	}
	r, err := c.c.SetEgress(ctx, connect.NewRequest(req))
	if err != nil {
		return err
	}
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		switch {
		case part == "bittorrent" && block:
			fmt.Fprintln(w, "BitTorrent blocked on every profile within a second or two: the handshake, uTP, UDP trackers, DHT;")
			fmt.Fprintln(w, "encrypted BitTorrent over TCP and trackers over HTTPS still pass (spec/egress-policy-v1.md §2)")
			if doff {
				fmt.Fprintln(w, "this kernel has no @ih: the handshake is matched after TCP headers of 20 and 32 bytes")
			}
		case part == "bittorrent":
			fmt.Fprintln(w, "BitTorrent allowed on every profile within a second or two")
		case block:
			fmt.Fprintln(w, "SMTP (TCP 25) blocked on every profile within a second or two, connections open to 25 too;")
			fmt.Fprintln(w, "mail clients' 465 and 587 stay open")
		default:
			fmt.Fprintln(w, "SMTP (TCP 25) allowed on every profile within a second or two")
		}
	})
}

func (c *cli) egressShow(ctx context.Context) error {
	r, err := c.c.GetEgress(ctx, connect.NewRequest(&nodev1.GetEgressRequest{}))
	if err != nil {
		return err
	}
	e := r.Msg.GetEgress()
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		state := map[bool]string{true: "blocked", false: "allowed"}
		fmt.Fprintf(w, "bittorrent\t%s\n", state[e.GetBittorrent()])
		fmt.Fprintf(w, "smtp (tcp 25)\t%s\n", state[e.GetSmtp()])
		fmt.Fprintf(w, "covers\tevery profile: the data plane's processes, UIDs %s\n", perimeter.DataPlaneUIDs)
		for _, uid := range r.Msg.Uids {
			// rayd serve -supervise: the data plane runs as rayd.
			fmt.Fprintf(w, "covers\trayd's UID %d (supervised): every process of that user\n", uid)
		}
		if egressEuid() != 0 {
			fmt.Fprintln(w, "in force\tonly root sees it, and the counters")
			return
		}
		blocks, err := egressBlocks()
		fmt.Fprintf(w, "in force\t%s\n", egressInForce(e, blocks, err))
		for _, rule := range perimeter.EgressRules {
			if d, ok := blocks[rule]; ok && err == nil {
				fmt.Fprintf(w, "blocked %s\t%d packets, %d bytes\n", rule, d.Packets, d.Bytes)
			}
		}
	})
}

// egressInForce says whether the rules in the table are the policy's.
func egressInForce(e *nodev1.Egress, blocks map[string]perimeter.Drops, err error) string {
	if err != nil {
		return fmt.Sprintf("unknown: %v (rayspa older than v0.21.0, or not running)", err)
	}
	_, smtp := blocks["smtp"]
	_, bt := blocks["bittorrent-tcp"]
	if smtp != e.GetSmtp() || bt != e.GetBittorrent() {
		return "not yet: rayspa has not applied it (journalctl -u rayspa)"
	}
	return "yes"
}

// egressLine is the policy in a line of rayctl status.
func egressLine(e *nodev1.Egress) string {
	var blocked []string
	if e.GetBittorrent() {
		blocked = append(blocked, "bittorrent")
	}
	if e.GetSmtp() {
		blocked = append(blocked, "smtp (tcp 25)")
	}
	if len(blocked) == 0 {
		return "nothing blocked (rayctl egress)"
	}
	return "blocked: " + strings.Join(blocked, ", ") + " (rayctl egress)"
}
