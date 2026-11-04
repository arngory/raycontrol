package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/arngory/raycontrol/internal/hostcheck"
)

// check tells whether this host can run a node: what is required (the
// install refuses without it), what is advised, what only a probe from
// outside shows (docs/08-decisions.md, R4-24). It changes nothing and
// needs no rayd: the bootstrap runs it before it installs anything.
func (c *cli) check(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	host := fs.String("host", "", "public address clients will use")
	domain := fs.String("domain", "", "base domain: certificates from Let's Encrypt")
	services := fs.String("services", "", "services the install sets up: dnstt and masterdns need UDP 53")
	// The install's other flags, so that the bootstrap passes its arguments
	// to both as they are.
	for _, f := range []string{"admin", "packages", "cloudflare-token-file", "dataplane"} {
		fs.String(f, "", "as for install; not used by the check")
	}
	fs.Bool("checked", false, "as for install; not used by the check")
	allowV0 := fs.Bool("allow-v0", false, "raycontrol v0 goes next (bootstrap.sh -remove-v0): it and the ports it holds are not failures")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	return hostCheck(ctx, os.Stdout, hostcheck.Options{Host: *host, Domain: *domain, Services: splitList(*services), AllowV0: *allowV0},
		false, c.json)
}

// hostCheck runs the checks and prints them, all or (quiet) only what
// failed; it returns an error when a required check failed.
func hostCheck(ctx context.Context, w io.Writer, o hostcheck.Options, quiet, asJSON bool) error {
	rs := hostcheck.System().Check(ctx, o)
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
				if !r.OK {
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
