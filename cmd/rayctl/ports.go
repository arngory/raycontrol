package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/hostcheck"
	"github.com/arngory/raycontrol/internal/provision"
)

// ports lists every port the node uses, for a provider's firewall or a
// router's forwarding (GetPorts): what to let in, who reaches it, and
// whether it was chosen at install (-ports) or drawn by the node.
func (c *cli) ports(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	r, err := c.c.GetPorts(ctx, connect.NewRequest(&nodev1.GetPortsRequest{}))
	if connect.CodeOf(err) == connect.CodeUnimplemented {
		return errors.New("the node runs a version before v0.27.0, which does not list its ports: on it, rayctl apply prints the ports a provider's firewall must let in")
	}
	if err != nil {
		return err
	}
	return c.print(r.Msg, func(w *tabwriter.Writer) { printPorts(w, r.Msg.Ports) })
}

// portAccess is what GetPorts' access means, for a person.
var portAccess = map[string]string{
	"everyone": "everyone",
	"spa":      "after the knock",
	"admin":    "admin addresses; after the knock for SSH devices",
	"acme":     "everyone while a certificate is issued (HTTP-01)",
}

func printPorts(w *tabwriter.Writer, ports []*nodev1.NodePort) {
	fmt.Fprintln(w, "PROTO\tPORTS\tNAME\tSET\tREACHED BY\tNOW")
	for _, p := range ports {
		span := strconv.Itoa(int(p.From))
		if p.To != p.From {
			span += "-" + strconv.Itoa(int(p.To))
		}
		access := portAccess[p.Access]
		if access == "" {
			access = p.Access
		}
		now := "-"
		if p.Current != 0 {
			now = fmt.Sprintf("%d until %s", p.Current, time.Unix(p.CurrentUntil, 0).Format("15:04 MST"))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", strings.Join(p.Protos, "+"), span, p.Name, p.Source, access, now)
	}
}

// chosenPorts are the ports a -ports choice names, for the host check.
func chosenPorts(c provision.PortChoice) []hostcheck.ChosenPorts {
	var out []hostcheck.ChosenPorts
	add := func(name string, protos []string, base, n uint16) {
		if n > 0 {
			out = append(out, hostcheck.ChosenPorts{Name: name, Protos: protos, From: base, To: uint16(int(base) + int(n) - 1)})
		}
	}
	add("spa", []string{"tcp", "udp"}, c.SPA.Base, c.SPA.Range)
	add("sub", []string{"tcp", "udp"}, c.Sub, min(c.Sub, 1))
	add("api", []string{"tcp"}, c.API, min(c.API, 1))
	add("rotation", []string{"udp"}, c.Rotation.Base, c.Rotation.Range)
	return out
}
