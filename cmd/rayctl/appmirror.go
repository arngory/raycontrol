package main

import (
	"context"
	"fmt"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/appmirror"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// appMirror is rayctl app-mirror: the client's releases kept on the node
// and served to its devices (spec/app-update-v1.md).
func (c *cli) appMirror(ctx context.Context, sub string) error {
	switch sub {
	case "", "show":
		r, err := c.c.GetAppMirror(ctx, connect.NewRequest(&nodev1.GetAppMirrorRequest{}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) { printAppMirror(w, r.Msg) })
	case "on", "off":
		_, err := c.c.SetAppMirror(ctx, connect.NewRequest(&nodev1.SetAppMirrorRequest{Enabled: sub == "on"}))
		if err == nil && sub == "on" {
			fmt.Println("the node checks GitHub for the client's releases now and every ~6 h; its devices see them in the subscription once one is verified (rayctl app-mirror)")
		}
		return err
	}
	return errUsage
}

func printAppMirror(w *tabwriter.Writer, m *nodev1.GetAppMirrorResponse) {
	state := "off"
	if m.Enabled {
		state = "on"
	}
	fmt.Fprintf(w, "mirror\t%s\n", state)
	if m.Checked != 0 {
		fmt.Fprintf(w, "checked\t%s\n", time.Unix(m.Checked, 0).UTC().Format(time.RFC3339))
	} else if m.Enabled {
		fmt.Fprintf(w, "checked\tnot yet\n")
	}
	if m.Error != "" {
		fmt.Fprintf(w, "last error\t%s\n", m.Error)
	}
	for _, r := range m.Releases {
		kind := "stable"
		if r.Prerelease {
			kind = "pre-release"
		}
		fmt.Fprintf(w, "%s %s\t%s, %d files, %.1f MB, verified %s\n", r.App, r.Tag, kind, r.Files, float64(r.Bytes)/1e6,
			time.Unix(r.Verified, 0).UTC().Format(time.RFC3339))
	}
	if m.Enabled && len(m.Releases) == 0 {
		fmt.Fprintf(w, "releases\tnone yet\n")
	}
	if m.Enabled {
		fmt.Fprintf(w, "downloads\t%d now (at most %d at once, one a device)\n", m.Downloads, appmirror.PerNode)
	}
}
