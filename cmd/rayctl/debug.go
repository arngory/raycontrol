package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// debug opens or closes the debug window (docs/09-observability.md §3):
// rayd, rayspa and niko-server log at debug level until it ends by
// itself. Client addresses then reach the journal.
func (c *cli) debug(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "", "show":
		r, err := c.c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
		if err != nil {
			return err
		}
		if r.Msg.DebugUntil == 0 {
			fmt.Println("debug window closed: the usual levels")
			return nil
		}
		fmt.Printf("debug window open until %s (%s left)\n", clock(r.Msg.DebugUntil),
			time.Until(time.Unix(r.Msg.DebugUntil, 0)).Round(time.Second))
		return nil
	case "on":
		fs := flag.NewFlagSet("debug on", flag.ContinueOnError)
		d := fs.Duration("for", 30*time.Minute, "how long, a day at most; it closes by itself")
		if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *d < time.Minute {
			return errUsage
		}
		r, err := c.c.SetDebug(ctx, connect.NewRequest(&nodev1.SetDebugRequest{Seconds: int64(d.Seconds())}))
		if err != nil {
			return err
		}
		fmt.Printf("debug window open until %s: rayd, rayspa and niko-server log at debug level (Xray stays at warning)\n", clock(r.Msg.Until))
		fmt.Println("the data-plane services restart now and when the window closes; their connections drop")
		fmt.Println("client addresses go to the journal: rayctl debug off when done")
		fmt.Printf("logs of the window: rayctl report -logs debug -since %dm -id <run> -o FILE\n", int((*d + 10*time.Minute).Minutes()))
		return nil
	case "off":
		if len(args) != 0 {
			return errUsage
		}
		if _, err := c.c.SetDebug(ctx, connect.NewRequest(&nodev1.SetDebugRequest{})); err != nil {
			return err
		}
		fmt.Println("debug window closed: the data-plane services restart with the usual levels")
		return nil
	}
	return errUsage
}

// clock is a unix time as UTC and local time of day.
func clock(unix int64) string {
	t := time.Unix(unix, 0)
	return t.UTC().Format("15:04 UTC") + " (" + t.Format("15:04 MST") + ")"
}
