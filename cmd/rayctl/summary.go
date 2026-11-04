package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/asn"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/summary"
)

// summaryCmd is rayctl summary: the client summaries (R4-21), an optional
// metric of how the node's profiles fare in the networks its clients use.
func (c *cli) summaryCmd(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "", "show":
		fs := flag.NewFlagSet("summary show", flag.ContinueOnError)
		days := fs.Int("days", summary.Window, "days to count, 1 to 30")
		if err := fs.Parse(args); err != nil {
			return errUsage
		}
		r, err := c.c.GetSummary(ctx, connect.NewRequest(&nodev1.GetSummaryRequest{Days: uint32(*days)}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) { printSummary(w, r.Msg) })
	case "on", "off":
		_, err := c.c.SetSummary(ctx, connect.NewRequest(&nodev1.SetSummaryRequest{Enabled: sub}))
		if err == nil && sub == "on" {
			fmt.Println("the node takes client reports; hints go to networks with at least", summary.K, "reports")
		}
		return err
	case "api":
		if len(args) < 1 {
			return errUsage
		}
		provider := args[0]
		fs := flag.NewFlagSet("summary api", flag.ContinueOnError)
		file := fs.String("token-file", "", "file with the API token (default: asked for, not echoed)")
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}
		token := ""
		if provider != "none" {
			t, err := readSecret(provider+" API token: ", *file, false)
			if err != nil {
				return err
			}
			token = strings.TrimSpace(t)
		}
		_, err := c.c.SetSummary(ctx, connect.NewRequest(&nodev1.SetSummaryRequest{Api: provider, Token: token}))
		if err == nil && provider != "none" {
			fmt.Printf("%s answers for addresses the databases miss, asked by network (/24, /48), never by address\n", provider)
		}
		return err
	case "db":
		return c.summaryDB(args)
	}
	return errUsage
}

// summaryDB puts an MMDB file the operator downloaded (IPinfo Lite with
// their own token, GeoLite2 ASN with their own key) in front of the
// release's database; -remove takes it away. On the node, as root.
func (c *cli) summaryDB(args []string) error {
	if c.identity != nil {
		return errors.New("summary db works on the node itself, not through -remote")
	}
	fs := flag.NewFlagSet("summary db", flag.ContinueOnError)
	remove := fs.Bool("remove", false, "remove the imported database: the release's is used again")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if err := needRoot(); err != nil {
		return err
	}
	if *remove {
		if err := os.Remove(summary.OperatorDB); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		fmt.Println("removed", summary.OperatorDB)
		return nil
	}
	if fs.NArg() != 1 {
		return errUsage
	}
	built, kind, err := asn.Check(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("%s is not a database the node can read: %w", fs.Arg(0), err)
	}
	b, err := os.ReadFile(fs.Arg(0)) //nolint:gosec // G304: the operator's file
	if err != nil {
		return err
	}
	// Next to the target, then renamed: rayd sees a whole file or none.
	tmp := summary.OperatorDB + ".new"
	if err := os.WriteFile(tmp, b, 0o640); err != nil { //nolint:gosec // G306: rayd's group reads it
		return err
	}
	if err := run("chown", "rayd:rayd", tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, summary.OperatorDB); err != nil {
		return err
	}
	fmt.Printf("%s (%s, built %s) in %s; rayd uses it within a minute\n", filepath.Base(fs.Arg(0)), kind, built.UTC().Format("2006-01-02"), summary.OperatorDB)
	if time.Since(built) > 30*24*time.Hour {
		fmt.Println("warning: the database is over 30 days old; some licences (GeoLite2) require a newer one")
	}
	return nil
}

func printSummary(w *tabwriter.Writer, m *nodev1.GetSummaryResponse) {
	state := "off"
	if m.Enabled {
		state = "on"
	}
	api := m.Api
	if api == "" {
		api = "none"
	}
	fmt.Fprintf(w, "reports\t%s\nonline lookup\t%s\n", state, api)
	for _, d := range m.Dbs {
		if !d.Present {
			fmt.Fprintf(w, "%s database\tnone (%s)\n", d.Role, d.Path)
			continue
		}
		built := time.Unix(d.Built, 0).UTC()
		age := ""
		if time.Since(built) > 30*24*time.Hour {
			age = " — over 30 days old"
		}
		fmt.Fprintf(w, "%s database\t%s, built %s%s\n", d.Role, d.Type, built.Format("2006-01-02"), age)
	}
	fmt.Fprintf(w, "\nlast %d days, networks with at least %d reports:\n", m.Days, m.K)
	if len(m.Networks) == 0 {
		fmt.Fprintln(w, "  none yet")
	}
	for _, n := range m.Networks {
		fmt.Fprintf(w, "\nAS%d\t%s\t%s\t%d reports\t%s\n", n.Asn, n.Name, n.Country, n.Reports, counts(n.Nets))
		if len(n.UdpMtu) > 0 {
			fmt.Fprintf(w, "  udp mtu\t%s\n", counts(n.UdpMtu))
		}
		for _, s := range n.Services {
			fmt.Fprintf(w, "  %s (%d)\t%s\tudp %s\tmbps %s\tstall KiB %s\n", s.Name, s.Id, counts(s.Results), counts(s.Udp), counts(s.Mbps), counts(s.StallKib))
		}
	}
	fmt.Fprintf(w, "\nfrom smaller networks\t%d reports\n", m.OtherReports)
}

func counts(m map[string]int64) string {
	if len(m) == 0 {
		return "-"
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, fmt.Sprintf("%s:%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}
