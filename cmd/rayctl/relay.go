package main

import (
	"context"
	"fmt"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// relay manages the relays in front of the node (spec/relay-v1.md, R6-a):
// their addresses reach the service ports without SPA.
func (c *cli) relay(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "add":
		if len(args) != 2 {
			return errUsage
		}
		r, err := c.c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: args[0], Address: args[1]}))
		if err != nil {
			return err
		}
		fmt.Printf("relay %s (%s) added: it reaches the service ports without SPA, never SSH\n", r.Msg.Relay.Name, r.Msg.Relay.Address)
		return nil
	case "list", "":
		r, err := c.c.ListRelays(ctx, connect.NewRequest(&nodev1.ListRelaysRequest{}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			if len(r.Msg.Relays) == 0 {
				fmt.Fprintln(w, "no relays")
				return
			}
			fmt.Fprintln(w, "NAME\tADDRESS\tADDED")
			for _, r := range r.Msg.Relays {
				fmt.Fprintf(w, "%s\t%s\t%s\n", r.Name, r.Address, time.Unix(r.CreatedAt, 0).UTC().Format(time.DateOnly))
			}
		})
	case "remove":
		if len(args) != 1 {
			return errUsage
		}
		if _, err := c.c.RemoveRelay(ctx, connect.NewRequest(&nodev1.RemoveRelayRequest{Name: args[0]})); err != nil {
			return err
		}
		fmt.Printf("relay %s removed\n", args[0])
		return nil
	}
	return errUsage
}
