package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/arngory/raycontrol/internal/dnscheck"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// dns manages the node's DNS provider (docs/08-decisions.md, R4-10).
func (c *cli) dns(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "", "status":
		r, err := c.c.GetDNS(ctx, connect.NewRequest(&nodev1.GetDNSRequest{}))
		if err != nil {
			return err
		}
		return c.printDNS(r.Msg, r.Msg.Status)
	case "cloudflare":
		fs := flag.NewFlagSet("dns cloudflare", flag.ContinueOnError)
		file := fs.String("token-file", "", "file with the API token (default: asked for, not echoed)")
		if err := fs.Parse(args); err != nil {
			return errUsage
		}
		token, err := readToken(*file)
		if err != nil {
			return err
		}
		r, err := c.c.SetDNSProvider(ctx, connect.NewRequest(&nodev1.SetDNSProviderRequest{Provider: "cloudflare", Token: token}))
		if err != nil {
			return err
		}
		return c.printDNS(r.Msg, r.Msg.Status)
	case "check":
		fs := flag.NewFlagSet("dns check", flag.ContinueOnError)
		now := fs.Bool("now", false, "check now instead of showing rayd's last check (at most once per 30 s)")
		resolvers := fs.String("resolver", "", "ask these resolvers, now: "+strings.Join(dnscheck.ResolverNames(), ", ")+", udp:IP or tcp:IP")
		if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
			return errUsage
		}
		r, err := c.c.CheckDNSZones(ctx, connect.NewRequest(&nodev1.CheckDNSZonesRequest{Now: *now, Resolvers: splitList(*resolvers)}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) { printDNSCheck(w, r.Msg, time.Now()) })
	case "sync":
		r, err := c.c.SyncDNS(ctx, connect.NewRequest(&nodev1.SyncDNSRequest{}))
		if err != nil {
			return err
		}
		return c.printDNS(r.Msg, r.Msg.Status)
	case "remove":
		fs := flag.NewFlagSet("dns remove", flag.ContinueOnError)
		keep := fs.Bool("keep-records", false, "forget the provider, leave the records in the zone")
		if err := fs.Parse(args); err != nil {
			return errUsage
		}
		r, err := c.c.RemoveDNS(ctx, connect.NewRequest(&nodev1.RemoveDNSRequest{KeepRecords: *keep}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			for _, rec := range r.Msg.Removed {
				fmt.Fprintln(w, "removed", rec)
			}
			fmt.Fprintln(w, "the node has no DNS provider now")
		})
	}
	return errUsage
}

func (c *cli) printDNS(msg proto.Message, st *nodev1.DNSStatus) error {
	return c.print(msg, func(w *tabwriter.Writer) {
		if st.Provider == "" {
			fmt.Fprintln(w, "provider\tnone: records by hand, certificates through HTTP-01 (rayctl dns cloudflare sets one up)")
		} else {
			fmt.Fprintf(w, "provider\t%s, zone %s\n", st.Provider, st.Zone)
		}
		fmt.Fprintln(w, "\nTYPE\tNAME\tCONTENT")
		for _, r := range st.Records {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Type, r.Name, r.Content)
		}
		for _, ch := range st.Changes {
			fmt.Fprintln(w, "\n"+ch)
		}
		for _, p := range st.Problems {
			fmt.Fprintln(w, "\nproblem:", p)
		}
	})
}

// printDNSCheck shows a check of the DNS zones: per zone the parent, the
// front and the backend, then a row per resolver, and what did not go
// well under it.
func printDNSCheck(w io.Writer, m *nodev1.CheckDNSZonesResponse, now time.Time) {
	ago := func(unix int64) string { return now.Sub(time.Unix(unix, 0)).Round(time.Second).String() }
	next := ""
	if m.NextAt != 0 {
		next = ", next in " + time.Unix(m.NextAt, 0).Sub(now).Round(time.Second).String()
	}
	if m.CheckedAt == 0 {
		fmt.Fprintf(w, "no check yet%s: rayctl dns check -now\n", next)
		return
	}
	fmt.Fprintf(w, "checked %s ago in %.1f s%s\n", ago(m.CheckedAt), float64(m.DurationMs)/1000, next)
	if m.Limited {
		fmt.Fprintln(w, "this is the last check: a new one at most every 30 s")
	}
	if len(m.Resolvers) > 0 {
		fmt.Fprintln(w, "resolvers:", strings.Join(m.Resolvers, ", "))
	}
	if len(m.Zones) == 0 {
		fmt.Fprintln(w, "no DNS tunnel zones")
	}
	for _, z := range m.Zones {
		ns := ""
		if z.Ns != "" {
			ns = ", NS " + z.Ns
		}
		state := z.State
		if z.Error != "" {
			state = "FAILED: " + z.Error
		}
		fmt.Fprintf(w, "\n%s (%s %s)%s: %s\n", z.Zone, z.Kind, z.Service, ns, state)
		for _, s := range []struct {
			name string
			step *nodev1.DNSCheckStep
		}{{"parent", z.Parent}, {"front", z.Front}, {"backend", z.Backend}} {
			if s.step.GetState() == "" || (s.step.GetState() == "skip" && s.step.GetDetail() == "") {
				continue
			}
			fmt.Fprintf(w, "  %-5s %-8s %s\n", s.step.State, s.name, s.step.Detail)
			if s.step.State != "ok" && s.step.Fix != "" {
				fmt.Fprintf(w, "                 → %s\n", s.step.Fix)
			}
		}
		if len(z.Resolvers) == 0 {
			continue
		}
		if !z.Delegated {
			fmt.Fprintln(w, "  resolvers not asked: the parent does not delegate the zone to the node")
			continue
		}
		// A step's state, the time instead of ok for the probe that
		// proves the way.
		cell := func(s *nodev1.DNSCheckStep, rtt bool) string {
			switch {
			case s.GetState() == "" || s.GetState() == "skip":
				return "-"
			case rtt && s.State == "ok" && s.RttMs > 0:
				return strconv.Itoa(int(s.RttMs)) + "ms"
			}
			return s.State
		}
		var notes []string
		note := func(r *nodev1.DNSResolverCheck, what string, s *nodev1.DNSCheckStep) {
			if s.GetState() != "ok" && s.GetDetail() != "" {
				notes = append(notes, r.Resolver+" "+what+": "+s.Detail)
			}
		}
		if z.Kind == "dnstt" {
			fmt.Fprintln(w, "  RESOLVER\tSOA\tSMALL\tLARGE\tEDNS\t0x20\tEGRESS")
		} else {
			fmt.Fprintln(w, "  RESOLVER\tANSWER")
		}
		for _, r := range z.Resolvers {
			if z.Kind != "dnstt" {
				fmt.Fprintf(w, "  %s\t%s\n", r.Resolver, cell(r.Small, true))
				note(r, "answer", r.Small)
				continue
			}
			edns, mixed, egress := "-", "-", "-"
			if r.Small.GetState() == "ok" {
				edns, mixed, egress = strconv.Itoa(int(r.Edns)), map[bool]string{true: "yes", false: "no"}[r.CaseRandomized], r.Egress
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Resolver, cell(r.Soa, false), cell(r.Small, true), cell(r.Large, false), edns, mixed, egress)
			note(r, "SOA", r.Soa)
			note(r, "small probe", r.Small)
			note(r, "large probe", r.Large)
		}
		for _, n := range notes {
			fmt.Fprintln(w, "  → "+n)
		}
	}
}

// readToken reads the Cloudflare token (readSecret).
func readToken(file string) (string, error) {
	t, err := readSecret("Cloudflare API token (Zone.DNS:Edit and Zone.Zone:Read on the node's zone): ", file, false)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(t), nil
}

// terminal reports whether f is a terminal.
func terminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// readSecret reads a secret from a file, or from the terminal without echo
// (twice with confirm), never from the command line (shell history, ps).
// Only the line end is cut off.
func readSecret(prompt, file string, confirm bool) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file) //nolint:gosec // G304: the operator's file
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	in := bufio.NewReader(os.Stdin)
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	terminal := err == nil
	ask := func(prompt string) (string, error) {
		if terminal {
			fmt.Fprint(os.Stderr, prompt)
			quiet := *old
			quiet.Lflag &^= unix.ECHO
			if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err == nil {
				defer func() {
					_ = unix.IoctlSetTermios(fd, unix.TCSETS, old)
					fmt.Fprintln(os.Stderr)
				}()
			}
		}
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		if line = strings.TrimRight(line, "\r\n"); line == "" {
			return "", errors.New("nothing entered")
		}
		return line, nil
	}
	secret, err := ask(prompt)
	if err != nil || !confirm || !terminal {
		return secret, err
	}
	again, err := ask("Again: ")
	if err != nil {
		return "", err
	}
	if again != secret {
		return "", errors.New("the two entries differ")
	}
	return secret, nil
}
