package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/hostcheck"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// check tells whether this host can run a node: what is required (the
// install refuses without it), what is advised, what only a probe from
// outside shows (docs/08-decisions.md, R4-24). It changes nothing and
// needs no rayd: the bootstrap runs it before it installs anything. When
// rayd runs, its last check of the DNS zones comes too (Internet), which
// never counts as a failure.
func (c *cli) check(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	host := fs.String("host", "", "public address clients will use")
	domain := fs.String("domain", "", "base domain: certificates from Let's Encrypt")
	services := fs.String("services", "", "services the install sets up: dnstt and masterdns need UDP 53")
	// The install's other flags, so that the bootstrap passes its arguments
	// to both as they are (a flag install has and check not failed the
	// bootstrap: review of -name).
	defineInstallFlags(fs)
	allowV0 := fs.Bool("allow-v0", false, "raycontrol v0 goes next (bootstrap.sh -remove-v0): it and the ports it holds are not failures")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	return hostCheck(ctx, os.Stdout, hostcheck.Options{Host: *host, Domain: *domain, Services: splitList(*services), AllowV0: *allowV0,
		ICMP: c.icmpOn(ctx)}, false, c.json, c.internetChecks(ctx)...)
}

// icmpOn reports whether rayd has a naive service that carries ICMP
// (icmp=on): its group must be allowed ICMP sockets. False when rayd does
// not answer (before the install).
func (c *cli) icmpOn(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := c.c.ListServices(ctx, connect.NewRequest(&nodev1.ListServicesRequest{}))
	if err != nil {
		return false
	}
	for _, s := range r.Msg.Services {
		if s.Enabled && provision.NaiveICMP(store.Service{Kind: s.Kind, Settings: s.SettingsJson}) {
			return true
		}
	}
	return false
}

// internetChecks is rayd's last check of the DNS zones as results of the
// Internet level; none when rayd does not answer (before the install) or
// has not checked yet.
func (c *cli) internetChecks(ctx context.Context) []hostcheck.Result {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := c.c.CheckDNSZones(ctx, connect.NewRequest(&nodev1.CheckDNSZonesRequest{}))
	if err != nil || r.Msg.CheckedAt == 0 {
		return nil
	}
	ago := time.Since(time.Unix(r.Msg.CheckedAt, 0))
	if ago < time.Minute {
		ago = ago.Round(time.Second)
	} else {
		ago = ago.Round(time.Minute)
	}
	var rs []hostcheck.Result
	for _, z := range r.Msg.Zones {
		res := hostcheck.Result{Level: hostcheck.Internet, Name: "DNS zone " + z.Zone + " (" + z.Service + ")", OK: z.Error == "",
			Detail: z.Summary + " (" + ago.String() + " ago)"}
		if !res.OK {
			res.Detail, res.Fix = z.Error, "rayctl dns check -now"
			for _, s := range []*nodev1.DNSCheckStep{z.Parent, z.Front} {
				if s.GetState() == "fail" && s.GetFix() != "" {
					res.Fix = s.Fix
					break
				}
			}
		}
		rs = append(rs, res)
	}
	return rs
}

// hostCheck runs the checks and prints them, all or (quiet) only what
// failed; it returns an error when a required check failed. extra are
// results found elsewhere (Internet).
func hostCheck(ctx context.Context, w io.Writer, o hostcheck.Options, quiet, asJSON bool, extra ...hostcheck.Result) error {
	rs := append(hostcheck.System().Check(ctx, o), extra...)
	failed := hostcheck.Failed(rs)
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rs); err != nil {
			return err
		}
	} else {
		hostcheck.Report(w, rs, quiet)
		if !quiet && len(failed) == 0 {
			warned := 0
			for _, r := range rs {
				if !r.OK && r.Level == hostcheck.Advised {
					warned++
				}
			}
			fmt.Fprintf(w, "This host can run a node (%d advised %s not met).\n", warned, map[bool]string{true: "item", false: "items"}[warned == 1])
		}
	}
	if len(failed) > 0 {
		return errors.New(map[bool]string{true: "a required check failed", false: fmt.Sprintf("%d required checks failed", len(failed))}[len(failed) == 1] +
			": this host cannot run a node; nothing was changed")
	}
	return nil
}

// defineInstallFlags puts install's flags that fs lacks on it, as ones the
// check takes and does not use.
func defineInstallFlags(fs *flag.FlagSet) {
	all := flag.NewFlagSet("install", flag.ContinueOnError)
	installFlags(all)
	all.VisitAll(func(f *flag.Flag) {
		if fs.Lookup(f.Name) != nil {
			return
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			fs.Bool(f.Name, false, "as for install; not used by the check")
			return
		}
		fs.String(f.Name, "", "as for install; not used by the check")
	})
}
