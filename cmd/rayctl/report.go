package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/hostcheck"
	"github.com/arngory/raycontrol/internal/redact"
)

// report writes what an issue needs and nothing a user must keep: versions,
// the system, the host checks, unit states, counts without names, and the
// warnings of the last day, all redacted (docs/09-observability.md, R4-4).
// It runs locally and sends nothing anywhere; the operator reads it and
// decides what to share.
func (c *cli) report(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	out := fs.String("o", "", "write to this file instead of the screen")
	logs := fs.String("logs", "warning", "journal priority to include: warning, info, debug (rayd and rayspa run with -debug) or none")
	since := fs.String("since", "24h", "how far back the journal goes")
	id := fs.String("id", "", "report ID to reuse, so that reports for one issue match (default: a new random one)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	w := io.Writer(os.Stdout)
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if *id == "" {
		*id = reportID()
	}

	// The node's own names go through the redactor like secrets do.
	var names []string
	st, stErr := c.c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
	if stErr == nil {
		names = append(names, st.Msg.Host)
	}
	// A full host name says where the node is; a single label (node, vps,
	// ubuntu) is a common word and stays.
	if b, err := os.ReadFile("/etc/hostname"); err == nil {
		if h := strings.TrimSpace(string(b)); strings.Contains(h, ".") {
			names = append(names, h, domainOf(h))
		}
	}
	services, svcErr := c.c.ListServices(ctx, connect.NewRequest(&nodev1.ListServicesRequest{}))
	if svcErr == nil {
		for _, s := range services.Msg.Services {
			for _, key := range []string{"zone", "sni"} {
				if v := jsonField(s.SettingsJson, key); v != "" {
					names = append(names, domainOf(v))
				}
			}
		}
	}
	red := redact.New(names...)
	p := func(format string, a ...any) { fmt.Fprint(w, red.String(fmt.Sprintf(format, a...))) }

	p("raycontrol report %s, %s\n", *id, time.Now().UTC().Format("2006-01-02"))
	p("Redacted: addresses (tokens valid in this report only), the node's names, keys, IDs, links.\n")
	p("Read it before you share it.\n\n")

	p("== versions\n")
	p("rayctl\t%s\n", version)
	for _, cmd := range [][]string{{deploy.DefaultBinaries.Rayd, "version"}, {deploy.DefaultBinaries.Rayspa, "version"},
		{deploy.DefaultBinaries.NikoServer, "version"}, {deploy.DefaultBinaries.Xray, "version"}} {
		p("%s\t%s\n", filepath.Base(cmd[0]), firstLine(cmd[0], cmd[1:]...))
	}

	p("\n== system\n")
	id2, ver := hostcheck.System().OSRelease()
	p("os\t%s %s\nkernel\t%s\narch\t%s\nsystemd\t%s\nnft\t%s\n", id2, ver, firstLine("uname", "-r"), firstLine("uname", "-m"),
		firstLine("systemctl", "--version"), firstLine("nft", "--version"))
	p("selinux\t%s\nfirewalld\t%s\nufw\t%s\n", firstLine("getenforce"), firstLine("systemctl", "is-active", "firewalld"), firstLine("ufw", "status"))
	// The host check without its network lookups: the report stays offline.
	rs := hostcheck.System().Check(ctx, hostcheck.Options{})
	p("checks\t%s\n", map[bool]string{true: "ok", false: "failed"}[len(hostcheck.Failed(rs)) == 0])
	for _, r := range rs {
		if !r.OK {
			p("%s\t%s: %s\n", r.Level, r.Name, r.Detail)
		}
	}

	p("\n== node\n")
	if stErr != nil {
		p("rayd\tunreachable: %v\n", stErr)
	} else {
		p("users\t%d\nservices\t%d\nactive devices\t%d\n", st.Msg.Users, st.Msg.Services, st.Msg.ActiveDevices)
	}
	if svcErr == nil {
		kinds := map[string]int{}
		for _, s := range services.Msg.Services {
			if s.Enabled {
				kinds[s.Kind]++
			}
		}
		var list []string
		for k, n := range kinds {
			list = append(list, fmt.Sprintf("%s:%d", k, n))
		}
		sort.Strings(list)
		p("kinds\t%s\n", strings.Join(list, " "))
	}

	if d, err := c.c.GetDNS(ctx, connect.NewRequest(&nodev1.GetDNSRequest{})); err == nil {
		provider := d.Msg.Status.Provider
		if provider == "" {
			provider = "none"
		}
		p("dns provider\t%s, %d records needed, %d problems\n", provider, len(d.Msg.Status.Records), len(d.Msg.Status.Problems))
	}
	// The zones rayd checks from the node, without their names.
	if stErr == nil {
		zones, failing := 0, 0
		for _, l := range st.Msg.Loops {
			if strings.HasPrefix(l.Name, "dns-zone ") {
				zones++
				if l.Failing {
					failing++
				}
			}
		}
		if zones > 0 {
			p("dns zones\t%d checked from the node, %d failing\n", zones, failing)
		}
	}

	p("\n== units\n")
	units, _ := filepath.Glob("/etc/systemd/system/niko-*.service")
	units = append([]string{"rayd.service", "rayspa.service"}, units...)
	for _, u := range units {
		u = filepath.Base(u)
		p("%s\t%s\t%s\trestarts %s\n", u, firstLine("systemctl", "is-active", u), firstLine("systemctl", "is-enabled", u),
			firstLine("systemctl", "show", "-P", "NRestarts", u))
	}
	p("perimeter table\t%s\n", map[bool]string{true: "present", false: "missing"}[exec.Command("nft", "list", "table", "inet", "raycontrol").Run() == nil])
	// Packets dropped before reassembly and conntrack (R4-9): fragments,
	// IP options, IPv6 extension headers, impossible TCP flags.
	if out, err := exec.Command("nft", "list", "chain", "inet", "raycontrol", "early").Output(); err == nil {
		total := 0
		for _, m := range regexp.MustCompile(`counter packets (\d+)`).FindAllSubmatch(out, -1) {
			n, _ := strconv.Atoi(string(m[1]))
			total += n
		}
		p("early drops\t%d\n", total)
	}

	if j, err := deploy.OpenJournal(""); err == nil && j.Exists() {
		counts := map[string]int{}
		for _, ch := range j.Changes {
			counts[ch.Kind]++
		}
		p("install journal\t%v\n", counts)
	}

	if *logs != "none" {
		prio := map[string]string{"warning": "warning", "info": "info", "debug": "debug"}[*logs]
		if prio == "" {
			return errUsage
		}
		p("\n== journal (%s and worse, last %s)\n", prio, *since)
		args := []string{"--no-pager", "-o", "short-iso", "-p", prio, "--since", "-" + *since, "-u", "rayd", "-u", "rayspa", "-u", "niko-*"}
		if out, err := exec.Command("journalctl", args...).Output(); err == nil { //nolint:gosec // G204: fixed flags, priority from a fixed set
			sc := bufio.NewScanner(strings.NewReader(string(out)))
			for sc.Scan() {
				p("%s\n", sc.Text())
			}
		}
	}
	if *out != "" {
		fmt.Printf("report %s written to %s; read it before you share it\n", *id, *out)
	}
	return nil
}

func reportID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return "r-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// firstLine runs a command and returns the first line of its output.
func firstLine(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput() //nolint:gosec // G204: fixed commands
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if line == "" && err != nil {
		return "-"
	}
	return line
}

// jsonField reads a string field of a settings object without a schema.
func jsonField(settings, key string) string {
	i := strings.Index(settings, `"`+key+`":"`)
	if i < 0 {
		return ""
	}
	rest := settings[i+len(key)+4:]
	v, _, _ := strings.Cut(rest, `"`)
	return v
}

// domainOf returns the registrable part of a name: its last two labels.
func domainOf(name string) string {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) <= 2 {
		return name
	}
	return strings.Join(labels[len(labels)-2:], ".")
}
