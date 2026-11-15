package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// versions is what rayctl version says: this rayctl's version, the one
// installed on this host (a node or a relay), and, through -remote, the
// node's. Empty: not known here.
type versions struct {
	Rayctl    string `json:"rayctl"`
	Installed string `json:"installed,omitempty"`
	Node      string `json:"node,omitempty"`
}

// versionCmd is rayctl version. On a Linux host the installed version is
// rayd's (rayd version, which needs no root; a node and a relay have rayd
// alike); through -remote, the node's, from its status. It needs neither:
// off a node it says this rayctl's version alone.
func (c *cli) versionCmd(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errUsage
	}
	v := versions{Rayctl: version}
	switch {
	case c.identity != nil:
		r, err := c.c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
		if err != nil {
			return fmt.Errorf("rayctl %s; the node's version: %w", version, err)
		}
		v.Node = nodeupdate.Printable(r.Msg.Version)
	case thisOS == nodeOS:
		v.Installed = raydVersion()
	}
	return v.write(os.Stdout, c.json)
}

// write prints v as text, or as a JSON object.
func (v versions) write(w io.Writer, asJSON bool) error {
	if asJSON {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	}
	fmt.Fprintf(w, "rayctl     %s\n", v.Rayctl)
	if v.Installed != "" {
		fmt.Fprintf(w, "installed  %s (rayd on this host)\n", v.Installed)
	}
	if v.Node != "" {
		fmt.Fprintf(w, "node       %s (its status, through the API)\n", v.Node)
	}
	return nil
}
