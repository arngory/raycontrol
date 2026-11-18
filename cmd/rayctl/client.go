package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/clientver"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// clientCmd is rayctl client: the node's minimum client version
// (spec/client-min-v1.md).
func (c *cli) clientCmd(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "", "show":
		if len(args) != 0 {
			return errUsage
		}
		r, err := c.c.GetClientPolicy(ctx, connect.NewRequest(&nodev1.GetClientPolicyRequest{}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) { printClientPolicy(w, r.Msg) })
	case "min":
		return c.clientMin(ctx, args)
	}
	return errUsage
}

// clientMin: rayctl client min PRODUCT VERSION|none [-from DATE] [-unknown
// allow|refuse] [-yes].
func (c *cli) clientMin(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return errUsage
	}
	product, version := args[0], args[1]
	fs := flag.NewFlagSet("client min", flag.ContinueOnError)
	from := fs.String("from", "", "the day it starts, YYYY-MM-DD (UTC midnight); until then clients are only told")
	unknown := fs.String("unknown", "allow", "clients that name no version: allow or refuse")
	yes := fs.Bool("yes", false, "refuse clients that name no version, though released Niko up to 1.58 then deletes the node's profiles")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || (*unknown != "allow" && *unknown != "refuse") {
		return errUsage
	}
	p := &nodev1.ClientPolicy{}
	if version != "none" {
		if _, err := clientver.ParseVersion(version); err != nil {
			return err
		}
		p.Min = map[string]string{product: version}
		if *from != "" {
			t, err := time.Parse(time.DateOnly, *from)
			if err != nil {
				return fmt.Errorf("-from %q: want YYYY-MM-DD", *from)
			}
			p.From = t.Unix()
		}
		if *unknown == "refuse" {
			if !*yes {
				return errors.New("-unknown refuse: Niko up to 1.58 names no version, and on such an answer it deletes " +
					"the node's profiles; it can still update through the node's mirror (rayctl app-mirror on), but the " +
					"user's changes to those profiles are lost (spec/client-min-v1.md §4, §9.1). Add -yes to do it anyway")
			}
			p.RefuseUnknown = true
		}
	}
	// One product's minimum at a time: the others the node keeps as they are.
	cur, err := c.c.GetClientPolicy(ctx, connect.NewRequest(&nodev1.GetClientPolicyRequest{}))
	if err != nil {
		return err
	}
	min := map[string]string{}
	for k, v := range cur.Msg.GetPolicy().GetMin() {
		if k != product {
			min[k] = v
		}
	}
	for k, v := range p.Min {
		min[k] = v
	}
	if len(min) > 0 {
		p.Min = min
		if version == "none" { // the other products keep their start and unknown
			p.From, p.RefuseUnknown = cur.Msg.GetPolicy().GetFrom(), cur.Msg.GetPolicy().GetRefuseUnknown()
		}
	}
	r, err := c.c.SetClientPolicy(ctx, connect.NewRequest(&nodev1.SetClientPolicyRequest{Policy: p}))
	if err != nil {
		return err
	}
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		printPolicy(w, r.Msg.Policy)
		if len(r.Msg.Policy.GetMin()) > 0 {
			fmt.Fprintln(w, "clients get it with their next subscription; a refused one keeps the way to update (rayctl app-mirror)")
		}
	})
}

func printClientPolicy(w *tabwriter.Writer, m *nodev1.GetClientPolicyResponse) {
	printPolicy(w, m.Policy)
	if len(m.Clients) == 0 {
		return
	}
	fmt.Fprintln(w, "devices by the client they last named (30 days)")
	for _, c := range m.Clients {
		name := c.Client
		if name == "" {
			name = "none named"
		}
		fmt.Fprintf(w, "  %s\t%d\n", name, c.Devices)
	}
}

func printPolicy(w *tabwriter.Writer, p *nodev1.ClientPolicy) {
	if len(p.GetMin()) == 0 {
		fmt.Fprintln(w, "minimum client\tnone (rayctl client min niko VERSION)")
		return
	}
	for product, v := range p.GetMin() {
		fmt.Fprintf(w, "minimum %s\t%s\n", product, v)
	}
	if p.GetFrom() != 0 {
		fmt.Fprintf(w, "from\t%s\n", time.Unix(p.GetFrom(), 0).UTC().Format(time.DateOnly))
	}
	unknown := "allowed"
	if p.GetRefuseUnknown() {
		unknown = "refused"
	}
	fmt.Fprintf(w, "clients naming no version\t%s\n", unknown)
}

// clientName is what rayctl's subscription requests name themselves
// (client-min-v1 §1): "rayctl/0.31.3" for a release; a build without a
// release version names none. A node's minimum names products, and rayctl
// is none of them: probe and knock see what the node serves.
func clientName() string {
	v := strings.TrimPrefix(version, "v")
	if _, err := clientver.ParseVersion(v); err != nil {
		return ""
	}
	return "rayctl/" + v
}
