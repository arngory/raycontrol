package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/perimeter"
)

// What rayctl conn-limit asks of the host; tests replace them.
var (
	connLimitEuid  = os.Geteuid
	connLimitDrops = (&perimeter.NFT{}).InboundDrops // the per-address limit's counters
)

// connLimit is rayctl conn-limit (spec/conn-limit-v1.md §8): whether the
// connection limits are on, their numbers, the conntrack table and the
// guard; on and off change it, root only, on the node.
func (c *cli) connLimit(ctx context.Context, args []string) error {
	switch {
	case len(args) == 0 || len(args) == 1 && args[0] == "show":
		return c.connLimitShow(ctx)
	case len(args) == 1 && (args[0] == "on" || args[0] == "off"):
		return c.connLimitSet(ctx, args[0] == "off")
	}
	return errUsage
}

func (c *cli) connLimitSet(ctx context.Context, off bool) error {
	if connLimitEuid() != 0 {
		return errors.New("rayctl conn-limit " + map[bool]string{true: "off", false: "on"}[off] + ": root only")
	}
	r, err := c.c.SetConnLimit(ctx, connect.NewRequest(&nodev1.SetConnLimitRequest{Off: off}))
	if err != nil {
		return err
	}
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		if off {
			fmt.Fprintln(w, "connection limits off within seconds: naive's per-user limits (its UDP limits from before stay),")
			fmt.Fprintln(w, "and the per-address limit on new inbound TCP and UDP, here and on the node's relays;")
		} else {
			fmt.Fprintln(w, "connection limits on within seconds: naive's per-user limits, and the per-address limit on")
			fmt.Fprintln(w, "new inbound TCP and UDP, here and on the node's relays;")
		}
		fmt.Fprintln(w, "naive reads it without a restart. The conntrack table's size, DNS tunnels without conntrack")
		fmt.Fprintln(w, "and the guard stay either way (spec/conn-limit-v1.md §8)")
	})
}

// The limits' numbers (spec/conn-limit-v1.md §5), for the operator.
var connLimitNumbers = [][2]string{
	{"per user", "naive: TCP 1024 at once, 30 new/s (burst 600, waits 0.5 s), failed dials 5/s (100, in debt);"},
	{"", "UDP 256 streams (the quietest gives way), 100 new destinations/s (200), 1024 pairs, lookups 20/s (100)"},
	{"per address", "new inbound TCP 50/s (1000) from an IPv4 address or a /64, 800/s (16000) from a /48;"},
	{"", "UDP 20/s (200), 320/s (3200) from a /48; admin addresses not counted"},
	{"guard", "new data-plane connections refused above 85 % of the table, again from 70 % after 2 min at least"},
}

func (c *cli) connLimitShow(ctx context.Context) error {
	r, err := c.c.GetConnLimit(ctx, connect.NewRequest(&nodev1.GetConnLimitRequest{}))
	if err != nil {
		return err
	}
	m := r.Msg
	now := time.Now()
	return c.print(m, func(w *tabwriter.Writer) {
		if m.Off {
			fmt.Fprintln(w, "limits\toff (rayctl conn-limit on): no per-user or per-address limits")
		} else {
			fmt.Fprintln(w, "limits\ton (rayctl conn-limit off)")
			for _, n := range connLimitNumbers[:4] {
				fmt.Fprintf(w, "%s\t%s\n", n[0], n[1])
			}
		}
		fmt.Fprintf(w, "%s\t%s\n", connLimitNumbers[4][0], connLimitNumbers[4][1])
		fmt.Fprintf(w, "conntrack\t%s\n", conntrackLine(m.Conntrack))
		fmt.Fprintf(w, "guard\t%s\n", guardLine(m.Guard, now))
		if len(m.Users) == 0 {
			fmt.Fprintln(w, "at a limit\tnobody in 15 min")
		}
		for _, u := range m.Users {
			fmt.Fprintf(w, "at a limit\tu%d (%s: %d in 15 min)\n", u.Id, u.Service, u.Refused)
		}
		bySvc := map[string][]string{}
		var order []string
		for _, x := range m.Refused {
			if x.Total == 0 {
				continue
			}
			if bySvc[x.Service] == nil {
				order = append(order, x.Service)
			}
			bySvc[x.Service] = append(bySvc[x.Service], fmt.Sprintf("%s %d", x.Kind, x.Total))
		}
		for _, svc := range order {
			fmt.Fprintf(w, "refused %s\t%s (since rayd started)\n", svc, strings.Join(bySvc[svc], ", "))
		}
		if connLimitEuid() != 0 {
			fmt.Fprintln(w, "inbound dropped\tonly root sees it")
			return
		}
		drops, err := connLimitDrops()
		if err != nil {
			fmt.Fprintf(w, "inbound dropped\tunknown: %v (rayspa older than v0.24.0, or not running)\n", err)
			return
		}
		fmt.Fprintf(w, "inbound dropped\tTCP %d, UDP %d packets over the per-address limit\n",
			drops["tcp"].Packets, drops["udp"].Packets)
	})
}

// conntrackLine is the table in a line.
func conntrackLine(ct *nodev1.Conntrack) string {
	if ct == nil || ct.Max == 0 {
		return "not read yet (rayd reads it every 15 s)"
	}
	s := fmt.Sprintf("%d of %d (%d%%)", ct.Count, ct.Max, ct.Count*100/ct.Max)
	if ct.DroppedRecent > 0 {
		s += fmt.Sprintf("; %d connections dropped in 15 min: the table was full", ct.DroppedRecent)
	}
	return s + fmt.Sprintf("; dropped %d, early dropped %d since boot", ct.Dropped, ct.EarlyDropped)
}

// guardLine is rayspa's guard in a line.
func guardLine(g *nodev1.ConnGuard, now time.Time) string {
	if g == nil {
		return "no report from rayspa yet (it reports once a minute; rayspa older than v0.24.0 never)"
	}
	ago := func(unix int64) string { return now.Sub(time.Unix(unix, 0)).Round(time.Second).String() }
	var b strings.Builder
	if g.On {
		fmt.Fprintf(&b, "ON for %s: new data-plane connections refused", ago(g.Since))
	} else {
		b.WriteString("off")
		if g.LastOn != 0 {
			fmt.Fprintf(&b, ", last on %s ago", ago(g.LastOn))
		}
	}
	fmt.Fprintf(&b, "; %d switches, %d refused, swept udp %d, tcp-out %d, tcp-in %d", g.Switches, g.Refused, g.SweptUdp, g.SweptTcpOut, g.SweptTcpIn)
	return b.String()
}
