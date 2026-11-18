package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/stats"
)

// stats writes the node's statistics over a window as JSON
// (spec/stats-v1.md): what rayd sampled, and on the node as root the
// versions of the binaries and the journal's counts. No names, addresses,
// domains or keys: it is made to be passed on.
func (c *cli) stats(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	last := fs.Duration("last", time.Hour, "the window: 5m to 2h")
	id := fs.String("id", "", "the run ID to file it under, the client's test run's (default: a new one)")
	out := fs.String("o", "", "write to this file (mode 0600) instead of the screen")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return errUsage
	}
	if *last < stats.MinWindow || *last > stats.MaxWindow {
		return fmt.Errorf("-last: %v to %v", stats.MinWindow, stats.MaxWindow)
	}
	if *id == "" {
		*id = reportID()
	} else if !stats.ValidRun(*id) {
		return errors.New("-id: letters, digits, '.', '-' and '_', at most 64")
	}
	resp, err := c.c.GetStats(ctx, connect.NewRequest(&nodev1.GetStatsRequest{LastSeconds: int64(last.Seconds())}))
	if err != nil {
		return err
	}
	var r stats.Report
	if err := json.Unmarshal(resp.Msg.Json, &r); err != nil {
		return fmt.Errorf("the node's report: %w", err)
	}
	r.Run = *id
	// On the node itself: the versions of the binaries rayd runs, and the
	// journal's counts by unit (root reads it).
	if c.identity == nil && thisOS == nodeOS {
		r.Node.NikoServer = binaryVersion(deploy.DefaultBinaries.NikoServer)
		r.Node.Xray = binaryVersion(deploy.DefaultBinaries.Xray)
		if os.Geteuid() == 0 {
			if units, err := c.journalUnits(ctx); err == nil {
				r.Journal, err = journalCounts(ctx, r.From, r.To, units)
				if err != nil {
					r.Partial = true
					r.Why = append(r.Why, "the journal unread: "+err.Error())
				}
			}
		}
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *out == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	if err := os.WriteFile(*out, b, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "stats %s written to %s\n", *id, *out)
	return nil
}

// binaryVersion is a binary's "version" line, cut to its first two words
// ("niko-server v0.18.3", "Xray 26.11.9"); "" when it does not run.
func binaryVersion(path string) string {
	line := firstLine(path, "version")
	f := strings.Fields(line)
	if len(f) < 2 || strings.Contains(line, "no such file") || strings.Contains(line, "not found") {
		return ""
	}
	return f[0] + " " + f[1]
}

// journalUnits maps the node's units to what a report calls them: rayd,
// rayspa and the fixed niko- units as they are, a service's unit by its
// kind#n.
func (c *cli) journalUnits(ctx context.Context) (map[string]string, error) {
	resp, err := c.c.ListServices(ctx, connect.NewRequest(&nodev1.ListServicesRequest{}))
	if err != nil {
		return nil, err
	}
	refs := make([]stats.ServiceRef, 0, len(resp.Msg.Services))
	for _, s := range resp.Msg.Services {
		refs = append(refs, stats.ServiceRef{ID: int64(s.Id), Name: s.Name, Kind: s.Kind})
	}
	units := map[string]string{"rayd.service": "rayd", "rayspa.service": "rayspa"}
	for name, id := range stats.ServiceIDs(refs) {
		units["niko-"+name+".service"] = id
	}
	return units, nil
}

// journalUnitGlobs are the units journalCounts reads: what rayctl report
// reads.
var journalUnitGlobs = []string{"rayd", "rayspa", "niko-*"}

// journalCounts counts the journal's entries at warning and worse from
// `from` to `to`, by unit (as units names it; another unit as "other")
// and priority: no text of any entry.
func journalCounts(ctx context.Context, from, to time.Time, units map[string]string) ([]stats.JournalCount, error) {
	args := []string{"--no-pager", "-o", "json", "--output-fields=_SYSTEMD_UNIT,PRIORITY", "-p", "warning",
		"--since", "@" + strconv.FormatInt(from.Unix(), 10), "--until", "@" + strconv.FormatInt(to.Unix()+1, 10)}
	for _, u := range journalUnitGlobs {
		args = append(args, "-u", u)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", args...) //nolint:gosec // G204: journalctl with flags of its own and times
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	out, scanErr := countJournal(stdout, units)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("journalctl: %w: %s", err, firstLineOf(stderr.String()))
	}
	return out, scanErr
}

// countJournal counts journalctl -o json's entries by unit and priority:
// the two fields only, never a message.
func countJournal(r io.Reader, units map[string]string) ([]stats.JournalCount, error) {
	counts := map[[2]string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var e struct {
			Unit     string `json:"_SYSTEMD_UNIT"`
			Priority string `json:"PRIORITY"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		unit, ok := units[e.Unit]
		if !ok {
			unit = journalUnitOther(e.Unit)
		}
		counts[[2]string{unit, priorityName(e.Priority)}]++
	}
	out := make([]stats.JournalCount, 0, len(counts))
	for k, n := range counts {
		out = append(out, stats.JournalCount{Unit: k[0], Priority: k[1], Entries: n})
	}
	slices.SortFunc(out, func(a, b stats.JournalCount) int {
		if a.Unit != b.Unit {
			return strings.Compare(a.Unit, b.Unit)
		}
		return strings.Compare(a.Priority, b.Priority)
	})
	return out, sc.Err()
}

// journalUnitOther names a unit the node's services do not: raycontrol's
// fixed niko- units (the fronts, Xray's) keep their name, the rest is
// "other".
func journalUnitOther(unit string) string {
	base := strings.TrimSuffix(filepath.Base(unit), ".service")
	switch base {
	case "niko-front", "niko-reality", "niko-inner", "niko-dns", "niko-edge-api":
		return base
	}
	return "other"
}

// priorityName is syslog's name of a journal priority.
func priorityName(p string) string {
	switch p {
	case "0":
		return "emerg"
	case "1":
		return "alert"
	case "2":
		return "crit"
	case "3":
		return "err"
	case "4":
		return "warning"
	}
	return "other"
}

func firstLineOf(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
