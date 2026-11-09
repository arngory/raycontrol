package main

import (
	"context"
	"fmt"
	"text/tabwriter"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// userLAN: rayctl user lan NAME [on|off] (docs/spec/lan-v1.md §1.1), the
// administrator's consent to the user's LAN; without on|off it is shown.
func (c *cli) userLAN(ctx context.Context, args []string) error {
	if len(args) == 1 {
		r, err := c.c.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{}))
		if err != nil {
			return err
		}
		for _, u := range r.Msg.Users {
			if u.Name == args[0] {
				return c.print(u, func(w *tabwriter.Writer) { fmt.Fprintf(w, "%s: LAN %s\n", u.Name, onOff(u.Lan)) })
			}
		}
		return fmt.Errorf("user %q: not found", args[0])
	}
	if len(args) != 2 || (args[1] != "on" && args[1] != "off") {
		return errUsage
	}
	r, err := c.c.SetUserLAN(ctx, connect.NewRequest(&nodev1.SetUserLANRequest{Name: args[0], Lan: args[1] == "on"}))
	if err != nil {
		return err
	}
	u := r.Msg.User
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		if !u.Lan {
			fmt.Fprintf(w, "%s: LAN off; the devices drop it with their next subscription\n", u.Name)
			return
		}
		fmt.Fprintf(w, "%s: LAN on, a new password; each device that shows itself in the client is in it (rayctl device list %s, column LAN)\n",
			u.Name, u.Name)
	})
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
