package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"slices"
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
// allow|refuse [-yes]]. The policy holds one start and one rule for
// clients that name no version, shared by every product's minimum: what
// a flag does not say stays as it is.
func (c *cli) clientMin(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return errUsage
	}
	product, version := args[0], args[1]
	if !clientver.ValidProduct(product) {
		return fmt.Errorf("product %q: a name of [a-z][a-z0-9-]{0,15}, such as niko", product)
	}
	fs := flag.NewFlagSet("client min", flag.ContinueOnError)
	from := fs.String("from", "", "the day it starts, YYYY-MM-DD (UTC midnight), or now; unset: as it was, or now for the first minimum")
	unknown := fs.String("unknown", "", "clients that name no version: allow or refuse; unset: as it was (allow at first)")
	yes := fs.Bool("yes", false, "refuse clients that name no version, though released Niko up to 1.58 then deletes the node's profiles")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || (*unknown != "" && *unknown != "allow" && *unknown != "refuse") {
		return errUsage
	}
	cur, err := c.c.GetClientPolicy(ctx, connect.NewRequest(&nodev1.GetClientPolicyRequest{}))
	if err != nil {
		return err
	}
	old := cur.Msg.GetPolicy()
	p := &nodev1.ClientPolicy{Min: map[string]string{}, From: old.GetFrom(), RefuseUnknown: old.GetRefuseUnknown()}
	for k, v := range old.GetMin() {
		if k != product {
			p.Min[k] = v
		}
	}
	if version == "none" {
		if *from != "" || *unknown != "" || *yes {
			return errors.New("rayctl client min PRODUCT none takes no flags")
		}
		if _, ok := old.GetMin()[product]; !ok {
			return fmt.Errorf("the node has no minimum for %s", product)
		}
	} else {
		if _, err := clientver.ParseVersion(version); err != nil {
			return err
		}
		p.Min[product] = version
		switch {
		case *from == "now":
			p.From = 0
		case *from != "":
			t, err := time.Parse(time.DateOnly, *from)
			if err != nil {
				return fmt.Errorf("-from %q: want YYYY-MM-DD or now", *from)
			}
			p.From = t.Unix()
		case len(old.GetMin()) == 0:
			p.From = 0
		}
		switch *unknown {
		case "allow":
			p.RefuseUnknown = false
		case "refuse":
			if !*yes && !old.GetRefuseUnknown() {
				return errors.New("-unknown refuse: Niko up to 1.58 names no version, and on such an answer it deletes " +
					"the node's profiles; it can still update through the node's mirror (rayctl app-mirror on), but the " +
					"user's changes to those profiles are lost (spec/client-min-v1.md §4, §9.1). Add -yes to do it anyway")
			}
			p.RefuseUnknown = true
		}
	}
	r, err := c.c.SetClientPolicy(ctx, connect.NewRequest(&nodev1.SetClientPolicyRequest{Policy: p}))
	if err != nil {
		return err
	}
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		printPolicy(w, r.Msg.Policy)
		others := len(r.Msg.Policy.GetMin()) > 1
		if others && r.Msg.Policy.GetFrom() != old.GetFrom() {
			fmt.Fprintln(w, "the start is every product's: it moved for the other minimums too")
		}
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
	products := slices.Sorted(maps.Keys(p.GetMin()))
	for _, product := range products {
		fmt.Fprintf(w, "minimum %s\t%s\n", product, p.GetMin()[product])
	}
	if f := time.Unix(p.GetFrom(), 0).UTC(); p.GetFrom() != 0 && f.Equal(f.Truncate(24*time.Hour)) {
		fmt.Fprintf(w, "from\t%s\n", f.Format(time.DateOnly))
	} else if p.GetFrom() != 0 {
		fmt.Fprintf(w, "from\t%s\n", f.Format(time.RFC3339))
	}
	unknown := "allowed"
	if p.GetRefuseUnknown() {
		unknown = "refused"
	}
	fmt.Fprintf(w, "clients naming no version\t%s\n", unknown)
}

// clientName is what rayctl's requests name themselves (client-min-v1
// §1): "rayctl/0.31.3" for a release, "rayctl/0.0.0-dev" for a build
// without one. A node's minimum names products, and rayctl is none of
// them: probe, knock and remote enroll see what the node serves, even
// where clients that name nothing are refused.
func clientName() string {
	v := strings.TrimPrefix(version, "v")
	if _, err := clientver.ParseVersion(v); err != nil {
		v = "0.0.0-dev"
	}
	return "rayctl/" + v
}
