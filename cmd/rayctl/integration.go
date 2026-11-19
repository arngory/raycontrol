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
)

// integrationCmd: rayctl integration status | set support-notes on|off |
// set mass-limit N | limits [ROLE|DEVICE_ID] [read=… write=… heavy=…
// inflight=…] [-reset] (docs/spec/integrations-v1.md §11).
func (c *cli) integrationCmd(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "", "status":
		if len(args) != 0 {
			return errUsage
		}
		r, err := c.integrationSettings(ctx)
		if err != nil {
			return err
		}
		return c.print(r, func(w *tabwriter.Writer) { printIntegrations(w, r, time.Now()) })
	case "set":
		if len(args) != 2 {
			return errUsage
		}
		req := &nodev1.SetIntegrationSettingsRequest{}
		switch args[0] {
		case "support-notes":
			on, err := parseOnOff(args[1])
			if err != nil {
				return err
			}
			req.SupportNotes = &on
		case "mass-limit":
			n, err := strconv.ParseUint(args[1], 10, 32)
			if err != nil {
				return fmt.Errorf("mass-limit %q: a number of deletions and disables an hour, 0 for every one to need confirm", args[1])
			}
			limit := uint32(n)
			req.MassLimit = &limit
		default:
			return errUsage
		}
		_, err := c.c.SetIntegrationSettings(ctx, connect.NewRequest(req))
		return integrationErr(err)
	case "limits":
		return c.integrationLimits(ctx, args)
	}
	return errUsage
}

// integrationSettings asks the node, saying so when it is too old.
func (c *cli) integrationSettings(ctx context.Context) (*nodev1.GetIntegrationSettingsResponse, error) {
	r, err := c.c.GetIntegrationSettings(ctx, connect.NewRequest(&nodev1.GetIntegrationSettingsRequest{}))
	if err != nil {
		return nil, integrationErr(err)
	}
	return r.Msg, nil
}

// integrationErr names a node older than integrations.
func integrationErr(err error) error {
	if connect.CodeOf(err) == connect.CodeUnimplemented {
		return errors.New("the node is older than this rayctl: it has no integrations' settings")
	}
	return err
}

func parseOnOff(s string) (bool, error) {
	switch s {
	case "on":
		return true, nil
	case "off":
		return false, nil
	}
	return false, fmt.Errorf("%q: on or off", s)
}

// integrationLimits: rayctl integration limits shows the limits in force;
// with a role or a device ID and rates it sets them, with -reset it takes
// them back to the default (root on the node).
func (c *cli) integrationLimits(ctx context.Context, args []string) error {
	if len(args) == 0 {
		r, err := c.integrationSettings(ctx)
		if err != nil {
			return err
		}
		return c.print(r, func(w *tabwriter.Writer) { printLimits(w, r.Limits) })
	}
	target := &nodev1.IntegrationLimitsFor{}
	if args[0] == "billing" || args[0] == "support" {
		target.Role = args[0]
	} else {
		target.DeviceId = args[0]
	}
	req := &nodev1.SetIntegrationSettingsRequest{Limits: target}
	limits := &nodev1.IntegrationLimits{}
	given := false
	for _, a := range args[1:] {
		if a == "-reset" || a == "--reset" {
			req.ToDefault = true
			continue
		}
		key, value, ok := strings.Cut(a, "=")
		if !ok {
			return errUsage
		}
		given = true
		var err error
		switch key {
		case "read":
			limits.Read, err = parseRate(value)
		case "write":
			limits.Write, err = parseRate(value)
		case "heavy":
			limits.Heavy, err = parseRate(value)
		case "inflight":
			var n uint64
			n, err = strconv.ParseUint(value, 10, 32)
			limits.Inflight = uint32(n)
		default:
			return fmt.Errorf("%q: read, write, heavy or inflight", key)
		}
		if err != nil {
			return fmt.Errorf("%s=%s: %w", key, value, err)
		}
	}
	if given == req.ToDefault {
		return fmt.Errorf("%w: rates or -reset", errUsage)
	}
	if given {
		target.Limits = limits
	}
	_, err := c.c.SetIntegrationSettings(ctx, connect.NewRequest(req))
	return integrationErr(err)
}

// parseRate reads "BURST,N/s" (or /m, /h): a token bucket.
func parseRate(s string) (*nodev1.Rate, error) {
	b, r, ok := strings.Cut(s, ",")
	n, per, ok2 := strings.Cut(r, "/")
	if !ok || !ok2 {
		return nil, errors.New("BURST,N/s, /m or /h, such as 100,10/s")
	}
	burst, err := strconv.ParseUint(b, 10, 32)
	if err != nil {
		return nil, err
	}
	count, err := strconv.ParseUint(n, 10, 32)
	if err != nil {
		return nil, err
	}
	mult := map[string]uint64{"s": 3600, "m": 60, "h": 1}[per]
	if mult == 0 || count*mult > 1<<32-1 {
		return nil, errors.New("a rate a second (s), minute (m) or hour (h)")
	}
	return &nodev1.Rate{Burst: uint32(burst), PerHour: uint32(count * mult)}, nil //nolint:gosec // G115: checked above
}

// rateText is a rate as rayctl takes it.
func rateText(r *nodev1.Rate) string {
	switch {
	case r == nil:
		return "-"
	case r.PerHour%3600 == 0:
		return fmt.Sprintf("%d,%d/s", r.Burst, r.PerHour/3600)
	case r.PerHour%60 == 0:
		return fmt.Sprintf("%d,%d/m", r.Burst, r.PerHour/60)
	}
	return fmt.Sprintf("%d,%d/h", r.Burst, r.PerHour)
}

func printLimits(w *tabwriter.Writer, limits []*nodev1.IntegrationLimitsFor) {
	fmt.Fprintln(w, "FOR\tREAD\tWRITE\tHEAVY\tINFLIGHT\tSET")
	for _, l := range limits {
		who := l.Role
		if l.DeviceId != "" {
			who = "device " + l.DeviceId
		}
		set := "default"
		if l.Set {
			set = "root"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n", who, rateText(l.Limits.GetRead()), rateText(l.Limits.GetWrite()),
			rateText(l.Limits.GetHeavy()), l.Limits.GetInflight(), set)
	}
}

func printIntegrations(w *tabwriter.Writer, r *nodev1.GetIntegrationSettingsResponse, now time.Time) {
	notes := "off"
	if r.SupportNotes {
		notes = "on"
	}
	fmt.Fprintf(w, "support-notes %s; traffic counting %s\n", notes, r.TrafficCounting)
	fmt.Fprintf(w, "mass actions: %d of %d in the last hour; %d refused since rayd started\n", r.MassActions, r.MassLimit, r.MassRefused)
	fmt.Fprintln(w, "\nDEVICE\tUSER/NAME\tROLE\tLAST CALL\tCALLS\tDENIED\tLIMITED")
	for _, d := range r.Devices {
		last := "-"
		if d.LastCall != 0 {
			last = now.Sub(time.Unix(d.LastCall, 0)).Round(time.Second).String() + " ago"
		}
		fmt.Fprintf(w, "%s\t%s/%s\t%s\t%s\t%d\t%d\t%d\n", d.Id, d.User, d.Name, d.Role, last, d.Calls, d.Denied, d.Limited)
	}
	fmt.Fprintln(w)
	printLimits(w, r.Limits)
}

// trafficCmd: rayctl traffic counting [on|auto] (integrations-v1 §2.4).
func (c *cli) trafficCmd(ctx context.Context, sub string, args []string) error {
	if sub != "counting" || len(args) > 1 {
		return errUsage
	}
	if len(args) == 0 {
		r, err := c.integrationSettings(ctx)
		if err != nil {
			return err
		}
		return c.print(r, func(w *tabwriter.Writer) { fmt.Fprintf(w, "traffic counting %s\n", r.TrafficCounting) })
	}
	if args[0] != "on" && args[0] != "auto" {
		return errUsage
	}
	mode := args[0]
	_, err := c.c.SetIntegrationSettings(ctx, connect.NewRequest(&nodev1.SetIntegrationSettingsRequest{TrafficCounting: &mode}))
	if err != nil {
		return integrationErr(err)
	}
	warn("inner and REALITY restart once if this turned the counting on or off, and their connections drop")
	return nil
}
