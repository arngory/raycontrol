package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// userLimit: rayctl user limit NAME 50G|off [-period monthly|none]
// [-reset-day N] (docs/spec/traffic-limit-v1.md §3.5). The size may be
// left out to change the period or the reset day alone.
func (c *cli) userLimit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("user limit", flag.ContinueOnError)
	period := fs.String("period", "", "monthly or none (the user's whole time)")
	resetDay := fs.Int("reset-day", 0, "monthly: the day the count starts again, 00:00 UTC, 1 to 28")
	if err := need(args, 1); err != nil {
		return err
	}
	req := &nodev1.SetUserTrafficRequest{Name: args[0]}
	rest := args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		size := rest[0]
		rest = rest[1:]
		var n int64
		if !strings.EqualFold(size, "off") {
			var err error
			if n, err = parseBytes(size); err != nil {
				return err
			}
		}
		req.LimitBytes = &n
	}
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 {
		return errUsage
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "period":
			req.Period = period
		case "reset-day":
			d := int32(*resetDay) //nolint:gosec // G115: checked by rayd, 1..28
			req.ResetDay = &d
		}
	})
	if req.LimitBytes == nil && req.Period == nil && req.ResetDay == nil {
		return errUsage
	}
	var note string
	if req.LimitBytes != nil {
		note = c.countingWarning(ctx, req.Name, *req.LimitBytes > 0)
	}
	r, err := c.c.SetUserTraffic(ctx, connect.NewRequest(req))
	if err != nil {
		return err
	}
	warn(note)
	u := r.Msg.User
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		if u.TrafficLimitBytes == 0 {
			fmt.Fprintf(w, "%s has no traffic limit now\n", u.Name)
			return
		}
		fmt.Fprintf(w, "%s: %s, %s, %s\n", u.Name, usedOf(u), periodOf(u), stateOf(u, time.Now()))
	})
}

// userUsage: rayctl user usage [NAME], the users with a limit.
func (c *cli) userUsage(ctx context.Context, args []string) error {
	if len(args) > 1 {
		return errUsage
	}
	r, err := c.c.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{}))
	if err != nil {
		return err
	}
	var list []*nodev1.User
	for _, u := range r.Msg.Users {
		if len(args) == 1 && u.Name != args[0] {
			continue
		}
		if u.TrafficLimitBytes > 0 || len(args) == 1 {
			list = append(list, u)
		}
	}
	if len(args) == 1 && len(list) == 0 {
		return fmt.Errorf("user %q: not found", args[0])
	}
	now := time.Now()
	return c.print(&nodev1.ListUsersResponse{Users: list}, func(w *tabwriter.Writer) {
		if len(list) == 0 {
			fmt.Fprintln(w, "no user has a traffic limit (rayctl user limit NAME 50G)")
			return
		}
		fmt.Fprintln(w, "USER\tUSED\tLIMIT\tPERIOD\tSINCE\tRESET\tSTATE")
		for _, u := range list {
			if u.TrafficLimitBytes == 0 {
				fmt.Fprintf(w, "%s\t-\t-\t-\t-\t-\t%s\n", u.Name, stateOf(u, now))
				continue
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", u.Name, humanBytes(u.TrafficUsedBytes), formatBytes(u.TrafficLimitBytes),
				periodOf(u), whenUTC(u.TrafficPeriodStart), whenUTC(u.TrafficNextReset), stateOf(u, now))
		}
	})
}

// countingWarning is what the first limit, or the last one going, does to
// the node: Xray's inner and REALITY count users' bytes only while some
// user has a limit, and restart once when that changes (§5). Asked before
// the change, said after it went through ("" for nothing to say).
func (c *cli) countingWarning(ctx context.Context, name string, setting bool) string {
	r, err := c.c.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{}))
	if err != nil {
		return ""
	}
	limited, others := 0, 0 // users with a limit, and of them not this one
	for _, u := range r.Msg.Users {
		if u.TrafficLimitBytes > 0 {
			limited++
			if u.Name != name {
				others++
			}
		}
	}
	s, err := c.c.ListServices(ctx, connect.NewRequest(&nodev1.ListServicesRequest{}))
	if err != nil {
		return ""
	}
	xray := false
	for _, svc := range s.Msg.Services {
		xray = xray || svc.Enabled && (svc.Kind == "inner" || svc.Kind == "reality")
	}
	switch {
	case !xray:
	case setting && limited == 0:
		return "the first traffic limit turns counting on: inner and REALITY restart once, and their connections drop"
	case !setting && limited == 1 && others == 0:
		return "the last traffic limit went, and counting with it: inner and REALITY restart once, and their connections drop"
	}
	return ""
}

// warn tells the operator on standard error.
func warn(msg string) {
	if msg != "" {
		fmt.Fprintln(os.Stderr, "rayctl: "+msg)
	}
}

// usedOf is a user's count for user list: "12.0G/50G", "-" without a
// limit, with "(over)" once the node took the user off for it.
func usedOf(u *nodev1.User) string {
	if u.TrafficLimitBytes == 0 {
		return "-"
	}
	s := humanBytes(u.TrafficUsedBytes) + "/" + formatBytes(u.TrafficLimitBytes)
	if u.TrafficExhausted {
		s += " (over)"
	}
	return s
}

func periodOf(u *nodev1.User) string {
	if u.TrafficPeriod == "monthly" {
		return "monthly, day " + strconv.Itoa(int(u.TrafficResetDay))
	}
	return u.TrafficPeriod
}

// stateOf is a user's state in the order of rayd's metrics: disabled,
// expired, over the limit (exhausted: rayd says so of live users only).
func stateOf(u *nodev1.User, now time.Time) string {
	switch {
	case !u.Enabled:
		return "disabled"
	case u.ExpiresAt != 0 && u.ExpiresAt <= now.Unix():
		return "expired"
	case u.TrafficExhausted:
		return "exhausted"
	}
	return "active"
}

// humanBytes is a count with one decimal: 512, 1.5K, 12.0G.
func humanBytes(n int64) string {
	for _, u := range units {
		if n >= u.mult {
			return strconv.FormatFloat(float64(n)/float64(u.mult), 'f', 1, 64) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10)
}

// whenUTC is a moment in UTC, as resets fall (00:00 UTC); "-" for none.
func whenUTC(unix int64) string {
	if unix == 0 {
		return "-"
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04Z")
}
