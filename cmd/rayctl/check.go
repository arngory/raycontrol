package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/deploy"
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
		ICMP: c.icmpOn(ctx)}, false, c.json, slices.Concat(c.internetChecks(ctx), misnamedResults(c.misnamed(ctx)), c.reservedResults(ctx),
		conntrackResults(conntrackPaths{}))...)
}

// conntrackPaths are where conntrackResults looks (tests give their own).
type conntrackPaths struct {
	max, meminfo string
	modprobe     []string   // globs of modprobe.d files
	euid         func() int // os.Geteuid when nil
}

// conntrackResults says whether the conntrack table has the size raycontrol
// gives it for this host's memory (spec/conn-limit-v1.md §6.1), or why it
// cannot: a container, where only the host sets it, or an "options
// nf_conntrack hashsize=" line, with which the kernel takes 8 × hashsize at
// the module's load (apply leaves the line alone).
func conntrackResults(p conntrackPaths) []hostcheck.Result {
	if p.max == "" {
		p = conntrackPaths{max: "/proc/sys/net/netfilter/nf_conntrack_max", meminfo: "/proc/meminfo",
			modprobe: []string{"/etc/modprobe.d/*.conf", "/run/modprobe.d/*.conf", "/usr/lib/modprobe.d/*.conf", "/lib/modprobe.d/*.conf"}}
	}
	res := hostcheck.Result{Level: hostcheck.Advised, Name: "conntrack table", OK: true}
	var mem uint64
	if b, err := os.ReadFile(p.meminfo); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
				mem, _ = strconv.ParseUint(f[1], 10, 64)
			}
		}
	}
	want := deploy.ConntrackSize(mem)
	b, err := os.ReadFile(p.max)
	live, perr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	switch {
	case err != nil || perr != nil:
		res.Detail = "nf_conntrack is not loaded yet: rayctl apply loads it at boot (" + deploy.ModulesLoad + ") and sizes the table"
	case live >= want:
		res.Detail = fmt.Sprintf("%s %d (raycontrol's for %d MiB: %d)", deploy.ConntrackMaxKey, live, mem>>10, want)
	default:
		// Opening it for writing changes nothing and tells whether it may
		// change here: as root (anyone else may not write it anywhere), or
		// on a read-only /proc/sys.
		f, werr := os.OpenFile(p.max, os.O_WRONLY, 0)
		if werr == nil {
			f.Close()
			res.Detail = fmt.Sprintf("%s %d: rayctl apply raises it to %d for %d MiB", deploy.ConntrackMaxKey, live, want, mem>>10)
			break
		}
		euid := p.euid
		if euid == nil {
			euid = os.Geteuid
		}
		if euid() != 0 && !errors.Is(werr, syscall.EROFS) {
			res.Detail = fmt.Sprintf("%s %d: rayctl apply raises it to %d for %d MiB if it may change here (in a container it may not): "+
				"run rayctl check as root to know", deploy.ConntrackMaxKey, live, want, mem>>10)
			break
		}
		res.OK = false
		res.Detail = fmt.Sprintf("%s is %d and cannot be changed here (a container: only the host sets it); raycontrol would set %d for %d MiB. "+
			"One user can fill %d entries (spec/conn-limit-v1.md §1.2); the guard refuses the data plane's new connections from 85 %%",
			deploy.ConntrackMaxKey, live, want, mem>>10, live)
		res.Fix = "ask the host's provider for a bigger nf_conntrack_max, or run the node on a VM"
	}
	for _, g := range p.modprobe {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			b, err := os.ReadFile(f) //nolint:gosec // G304: modprobe.d
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				fl := strings.Fields(line)
				if len(fl) >= 3 && fl[0] == "options" && fl[1] == "nf_conntrack" && slices.ContainsFunc(fl[2:], func(o string) bool {
					return strings.HasPrefix(o, "hashsize=")
				}) {
					return append([]hostcheck.Result{res}, hostcheck.Result{Level: hostcheck.Advised, Name: "conntrack hashsize", OK: false,
						Detail: f + " sets the module's hashsize: the kernel then takes nf_conntrack_max = 8 × hashsize at boot, " +
							"and raycontrol's size of the table may not hold (it leaves the line alone)",
						Fix: "remove the line, or set " + deploy.ConntrackMaxKey + " yourself in a sysctl file that sorts after " + deploy.ConntrackSysctl})
				}
			}
		}
	}
	return []hostcheck.Result{res}
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

// reservedPortsFile is where the kernel says which ports are reserved.
var reservedPortsFile = "/proc/sys/net/ipv4/ip_local_reserved_ports"

// reservedResults says whether the node's ports (rayd's deploy inputs)
// are reserved (deploy.ReservePorts): one that is not, an outgoing
// connection may take, and the listen on it fails while it holds it. None
// when rayd does not answer (before the install).
func (c *cli) reservedResults(ctx context.Context) []hostcheck.Result {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := c.c.GetDeployInputs(ctx, connect.NewRequest(&nodev1.GetDeployInputsRequest{}))
	if err != nil {
		return nil
	}
	in, err := api.DeployInputs(r.Msg)
	if err != nil {
		return nil
	}
	res := hostcheck.Result{Level: hostcheck.Advised, Name: "reserved ports", OK: true, Detail: "SPA's and the services' ports are kept from outgoing connections"}
	live, err := os.ReadFile(reservedPortsFile)
	missing := ""
	if err == nil {
		missing, err = deploy.MissingReserved(string(live), in.HostPorts)
	}
	switch {
	case err != nil:
		res.OK, res.Detail = false, err.Error()
	case missing != "":
		res.OK, res.Detail = false, fmt.Sprintf("%s lacks %s: an outgoing connection may hold one, and the listen on it fails meanwhile", deploy.ReservedPortsKey, missing)
	}
	if !res.OK {
		res.Fix = "rayctl apply reserves them (" + deploy.PortsSysctl + "); a sysctl file that sorts after it must not set " + deploy.ReservedPortsKey
	}
	return []hostcheck.Result{res}
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
