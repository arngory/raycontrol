// Package hostcheck tells whether a host can run a node, and how well:
// what is required (without it the node does not work, and the install
// refuses before it changes anything), what is advised (the node works,
// worse), and what only a probe from outside shows (docs/08-decisions.md,
// R4-24).
package hostcheck

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/legacy"
	"github.com/arngory/raycontrol/internal/perimeter"
)

// Level says what a failed check means.
type Level int

const (
	// Required: without it the node does not work; the install refuses.
	Required Level = iota
	// Advised: the node works without it, worse.
	Advised
	// Internet: what the node sees of itself from outside once it runs
	// (rayd's check of its DNS zones). Shown, never a failure of the host:
	// the check and the install go on as before.
	Internet
)

func (l Level) String() string {
	switch l {
	case Required:
		return "required"
	case Internet:
		return "internet"
	}
	return "advised"
}

// MarshalJSON writes the level as its name.
func (l Level) MarshalJSON() ([]byte, error) { return json.Marshal(l.String()) }

// Result is one check.
type Result struct {
	Level  Level  `json:"level"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"` // what was found
	Fix    string `json:"fix,omitempty"`    // what to do when it failed
}

// Options are the plans the checks depend on.
type Options struct {
	Host     string   // the public address clients use
	Domain   string   // with a domain, certificates come from Let's Encrypt
	Services []string // what the install sets up: DNS tunnels need UDP 53
	// AllowV0: raycontrol v0 is about to go (bootstrap -remove-v0 checks
	// the rest first): it is not a failure, nor are the ports its Xray and
	// Hysteria2 hold.
	AllowV0 bool
}

// Host is what the checks look at; System is this machine, tests replace
// the parts.
type Host struct {
	Root     string // prefix of /proc, /sys, /etc, /lib, /run, /var: "" on the host
	Run      func(ctx context.Context, stdin, name string, args ...string) ([]byte, error)
	LookPath func(name string) error
	Euid     func() int
	Free     func(path string) (bytes uint64, err error)
	Addrs    func() ([]netip.Addr, error)
	CPUs     func() int
	// Reach fetches a URL (Let's Encrypt); nil skips that check.
	Reach func(ctx context.Context, url string) error
	// Sandbox runs the checks that start transient units (systemd-run):
	// the sandbox of the units and their IP firewall.
	Sandbox bool
}

// System is this machine.
func System() *Host {
	return &Host{
		Run: func(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			if stdin != "" {
				cmd.Stdin = strings.NewReader(stdin)
			}
			return cmd.CombinedOutput()
		},
		LookPath: func(name string) error { _, err := exec.LookPath(name); return err },
		Euid:     os.Geteuid,
		Free: func(path string) (uint64, error) {
			var st syscall.Statfs_t
			if err := syscall.Statfs(path, &st); err != nil {
				return 0, err
			}
			return st.Bavail * uint64(st.Bsize), nil //nolint:gosec // G115: block sizes are positive
		},
		Addrs: func() ([]netip.Addr, error) {
			as, err := net.InterfaceAddrs()
			var out []netip.Addr
			for _, a := range as {
				if p, err := netip.ParsePrefix(a.String()); err == nil {
					out = append(out, p.Addr())
				}
			}
			return out, err
		},
		CPUs: func() int { return numCPU() },
		Reach: func(ctx context.Context, url string) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()
			if resp.StatusCode >= 400 {
				return fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			return nil
		},
		Sandbox: true,
	}
}

// Thresholds. The node with every service takes about 240 MiB at rest
// (docs/10-quickstart-debian13.md, §0), the system 150–250 MiB besides.
const (
	MinMemoryMiB  = 400
	GoodMemoryMiB = 900
	MinFreeMiB    = 500
	GoodFreeMiB   = 2048
	// UDPBuffer is what the sysctl file sets for QUIC.
	UDPBuffer = 16 << 20
)

// tested are the systems the install test runs on (docs/08-decisions.md,
// R2-1).
var tested = map[string][]string{"debian": {"12", "13"}, "ubuntu": {"24.04"}, "rocky": {"9", "10"}}

// minSystemd is the first systemd with every hardening directive the units
// use (ProtectClock=).
const minSystemd = 245

// letsEncrypt is the ACME directory the node orders certificates from.
const letsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// Check runs every check.
func (h *Host) Check(ctx context.Context, o Options) []Result {
	var rs []Result
	add := func(r Result) { rs = append(rs, r) }
	req := func(name string, ok bool, detail, fix string) {
		add(Result{Level: Required, Name: name, OK: ok, Detail: detail, Fix: fix})
	}
	adv := func(name string, ok bool, detail, fix string) {
		add(Result{Level: Advised, Name: name, OK: ok, Detail: detail, Fix: fix})
	}

	// Required.
	req("root", h.Euid() == 0, "", "run as root")
	systemd := h.exists("/run/systemd/system")
	sdVersion := 0
	if out, err := h.Run(ctx, "", "systemctl", "--version"); err == nil {
		if f := strings.Fields(string(out)); len(f) > 1 {
			sdVersion, _ = strconv.Atoi(f[1])
		}
	}
	switch {
	case !systemd:
		req("systemd", false, "systemd is not running", "a system with systemd as init: Debian, Ubuntu, Rocky Linux")
	case sdVersion > 0 && sdVersion < minSystemd:
		req("systemd", false, fmt.Sprintf("systemd %d", sdVersion), fmt.Sprintf("systemd %d or newer: a newer release of the system", minSystemd))
	default:
		req("systemd", true, fmt.Sprintf("systemd %d", sdVersion), "")
	}
	req("D-Bus", h.exists("/run/dbus/system_bus_socket"), "", "the system bus must run: rayd talks to systemd over it (apt install dbus)")
	var missing []string
	for _, c := range []string{"nft", "systemctl", "systemd-run", "useradd", "groupadd", "usermod", "runuser", "systemd-tmpfiles", "sysctl"} {
		if h.LookPath(c) != nil {
			missing = append(missing, c)
		}
	}
	req("commands", len(missing) == 0, strings.Join(missing, ", ")+map[bool]string{true: "", false: " missing"}[len(missing) == 0],
		"install them (nft: apt install nftables; the rest come with the base system)")
	if out, _ := h.Run(ctx, "", "systemctl", "show", "-P", "LoadState", "polkit.service"); strings.TrimSpace(string(out)) == "loaded" {
		req("polkit", true, "", "")
	} else {
		req("polkit", false, "not installed", "apt install polkitd (dnf install polkit): rayd restarts data-plane units through it")
	}
	kernel := strings.TrimSpace(h.read("/proc/sys/kernel/osrelease"))
	if !slices.Contains(missing, "nft") {
		// A dry run in the kernel: nft and the kernel must support every
		// expression of the table (inet nat, maps, dynamic sets, NFLOG).
		out, err := h.Run(ctx, (&perimeter.NFT{NflogGroup: 7}).Ruleset(), "nft", "-c", "-f", "-")
		req("nftables", err == nil, map[bool]string{true: "the perimeter table loads in kernel " + kernel,
			false: "kernel " + kernel + " cannot load the perimeter table: " + firstLines(out, 3)}[err == nil],
			"kernel 5.2 or newer with nftables (NAT, sets, NFLOG); in a container its host must load the modules")
		if err == nil {
			// The egress policy whole (rayctl egress block): the node works
			// without it, so advised.
			doff, err := perimeter.CheckEgress(perimeter.Egress{SMTP: true, BitTorrent: true}, func(script string) ([]byte, error) {
				return h.Run(ctx, script, "nft", "-c", "-f", "-")
			})
			detail := "the BitTorrent and SMTP filter loads (rayctl egress)"
			if doff {
				detail += "; no @ih in this kernel: the handshake by the TCP header's length"
			}
			if err != nil {
				detail = "kernel " + kernel + " cannot load the BitTorrent and SMTP filter: " + err.Error()
			}
			adv("egress policy", err == nil, detail, "a newer kernel with nftables' raw payload matches: without it rayctl egress block refuses")
		}
	}
	if h.Sandbox && systemd && !slices.Contains(missing, "systemd-run") {
		ok, detail := h.sandbox(ctx)
		req("systemd sandbox", ok, detail,
			"namespaces must work in the units: a VM, or in LXC nesting=1 (Proxmox: Options → Features → Nesting)")
	}
	memMiB := h.memoryMiB()
	req("memory", memMiB >= MinMemoryMiB, fmt.Sprintf("%d MiB", memMiB), fmt.Sprintf("%d MiB at least", MinMemoryMiB))
	minFree := uint64(0)
	var freeDetail []string
	for _, p := range []string{"/usr/local", "/var/lib"} {
		free, err := h.Free(filepath.Join(h.Root, p))
		if err != nil {
			continue
		}
		if minFree == 0 || free < minFree {
			minFree = free
		}
		freeDetail = append(freeDetail, fmt.Sprintf("%s %d MiB free", p, free>>20))
	}
	if len(freeDetail) > 0 {
		req("disk", minFree>>20 >= MinFreeMiB, strings.Join(freeDetail, ", "), fmt.Sprintf("%d MiB free at least", MinFreeMiB))
	}
	// raycontrol v0 (ray.sh): its Xray holds 443 and its table drops what
	// the node serves (R4-26).
	lh := &legacy.Host{Root: h.Root, LookPath: h.LookPath,
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return h.Run(ctx, "", name, args...)
		}}
	switch f := lh.Detect(ctx); {
	case f.Any() && o.AllowV0:
		adv("raycontrol v0", true, fmt.Sprintf("ray.sh is installed and goes next (%d items)", len(f.Items)), "")
	case f.Any():
		req("raycontrol v0", false, fmt.Sprintf("ray.sh is installed (%d items: %s, …)", len(f.Items), f.Items[0]),
			"bash bootstrap.sh -remove-v0 with the same arguments backs it up and removes only what it installed (on a node: rayctl legacy -remove)")
	default:
		req("raycontrol v0", true, "not installed", "")
	}
	listeners := h.listeners()
	// The node's own processes, by their binary (a name such as xray is
	// anyone's); with AllowV0 also v0's, which go before the install.
	ours := func(l listener) bool {
		return strings.HasPrefix(l.exe, deploy.DataPlaneDir+"/") || l.exe == deploy.DefaultBinaries.Rayd ||
			o.AllowV0 && slices.Contains(legacy.Binaries(), l.exe)
	}
	for _, p := range []struct {
		proto string
		port  uint16
	}{{"tcp", 443}, {"udp", 443}} {
		others := others(listeners, p.proto, p.port, ours)
		req(fmt.Sprintf("port %s %d", p.proto, p.port), len(others) == 0, describe(others),
			"stop and disable what listens there (systemctl disable --now nginx): the node serves 443 itself")
	}
	if slices.ContainsFunc(o.Services, func(s string) bool { return s == "dnstt" || s == "masterdns" || s == "slipstream" }) {
		// systemd-resolved's stub shares the port with the front (both
		// bind with SO_REUSEADDR, niko-server v0.8.2); anything else
		// keeps it.
		others := others(listeners, "udp", 53, func(l listener) bool {
			stub := l.addr.Addr() == netip.MustParseAddr("127.0.0.53") || l.addr.Addr() == netip.MustParseAddr("127.0.0.54")
			return ours(l) || l.comm == "systemd-resolve" && stub
		})
		req("port udp 53", len(others) == 0, describe(others),
			"stop what listens there (bind9, dnsmasq, unbound): the DNS tunnels answer on UDP 53")
	}

	// Advised.
	switch virt, container := h.virt(ctx); {
	case container:
		adv("virtualization", false, "container ("+virt+"): the kernel is the host's",
			"a VM (KVM) is advised: in a container kernel updates, modules and global settings belong to the provider")
	default:
		adv("virtualization", true, virt, "")
	}
	if id, ver := h.OSRelease(); isTested(id, ver) {
		adv("system", true, id+" "+ver, "")
	} else {
		adv("system", false, id+" "+ver+" is not among the tested systems", "Debian 12/13, Ubuntu 24.04 or Rocky Linux 9/10")
	}
	adv("memory", memMiB >= GoodMemoryMiB, fmt.Sprintf("%d MiB", memMiB),
		"1 GiB or more; with every service the node takes about 240 MiB besides the system")
	cpus := h.CPUs()
	adv("processors", cpus >= 2, fmt.Sprintf("%d", cpus),
		"2 or more: Hysteria2 carries about 250–300 Mbit/s per core")
	if len(freeDetail) > 0 {
		adv("disk", minFree>>20 >= GoodFreeMiB, strings.Join(freeDetail, ", "),
			"2 GiB free: an update keeps the previous release for the rollback")
	}
	if out, err := h.Run(ctx, "", "timedatectl", "show", "-p", "NTPSynchronized", "--value"); err == nil && strings.TrimSpace(string(out)) == "yes" {
		adv("clock", true, "synchronized", "")
	} else {
		adv("clock", false, "not synchronized over NTP", "apt install systemd-timesyncd (or chrony): SPA slots and certificates go by the clock")
	}
	adv("BBR", h.bbr(kernel), "", "a kernel with tcp_bbr: TCP holds up worse on lossy links without it")
	adv("UDP buffers", h.udpBuffers(), "", "net.core.rmem_max and wmem_max must be raisable: QUIC (Hysteria2, naive) is slower with small buffers")
	if h.Sandbox && systemd && !slices.Contains(missing, "systemd-run") {
		ok, detail := h.ipFirewall(ctx)
		adv("unit IP firewall", ok, detail, "cgroup v2 with BPF: without it IPAddressDeny= is ignored and the backends keep only their own address checks")
	}
	for _, w := range updateWarnings(h.Root, kernel) {
		adv("updates", false, w.detail, w.fix)
	}
	if p := deploy.ResolverProblem(h.Root); p != "" {
		adv("resolver", false, p, "a resolv.conf the services can read, with a nameserver line: rayd resolves the ACME and Cloudflare names itself")
	} else {
		adv("resolver", true, "", "")
	}
	if p := deploy.SandboxResolverProblem(h.Root); p != "" {
		adv("resolver in the sandbox", false, p, "Hysteria2 and Yggdrasil's peers look names up from units that deny loopback and private ranges, all but systemd-resolved's stub")
	}
	addrs, _ := h.Addrs()
	v6 := slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Is6() && a.IsGlobalUnicast() && !a.IsPrivate() })
	adv("IPv6", v6, map[bool]string{true: "a public address", false: "none"}[v6], "an IPv6 address reaches clients on networks without IPv4 more directly")
	if a, err := netip.ParseAddr(o.Host); err == nil {
		local := slices.Contains(addrs, a.Unmap())
		adv("public address", true, map[bool]string{true: o.Host + " is on an interface",
			false: o.Host + " is not on an interface: behind 1:1 NAT (cloud), fine if the provider passes every port to the host"}[local], "")
	}
	if o.Domain != "" {
		if others := others(listeners, "tcp", 80, ours); len(others) > 0 {
			adv("port tcp 80", false, describe(others), "without Cloudflare the ACME window takes TCP 80 for a few minutes per certificate")
		}
		if h.Reach != nil {
			rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			err := h.Reach(rctx, letsEncrypt)
			cancel()
			adv("Let's Encrypt", err == nil, map[bool]string{true: "reachable", false: fmt.Sprint(err)}[err == nil],
				"the node orders its certificates there: outbound HTTPS must work")
		}
	}
	return rs
}

// Failed returns the required checks that failed.
func Failed(rs []Result) []Result {
	var out []Result
	for _, r := range rs {
		if r.Level == Required && !r.OK {
			out = append(out, r)
		}
	}
	return out
}

// Outside is what no check on the host can see.
const Outside = "Only a probe from outside shows the provider's firewall, UDP filtered on the way and blocks of the address: " +
	"after the install, rayctl probe -channel from another machine."

// Report writes the results: all of them, or (quiet) only the required
// checks that failed.
func Report(w io.Writer, rs []Result, quiet bool) {
	levels := []Level{Required, Advised, Internet}
	if quiet {
		levels = levels[:1]
	}
	for _, level := range levels {
		title := map[Level]string{Required: "Required: without these the node does not work",
			Advised:  "Advised: the node works without them, worse",
			Internet: "Internet: the node's DNS zones as rayd last checked them (rayctl dns check)"}[level]
		printed := false
		for _, r := range rs {
			if r.Level != level || (quiet && r.OK) {
				continue
			}
			if !printed {
				fmt.Fprintln(w, title)
				printed = true
			}
			mark := "ok  "
			if !r.OK {
				mark = map[Level]string{Required: "FAIL", Advised: "warn", Internet: "FAIL"}[level]
			}
			line := "  " + mark + "  " + r.Name
			if r.Detail != "" {
				line += ": " + r.Detail
			}
			fmt.Fprintln(w, line)
			if !r.OK && r.Fix != "" {
				fmt.Fprintln(w, "          → "+r.Fix)
			}
		}
	}
	if !quiet {
		fmt.Fprintln(w, Outside)
	}
}

func (h *Host) path(p string) string { return filepath.Join(h.Root, p) }

func (h *Host) exists(p string) bool { _, err := os.Stat(h.path(p)); return err == nil }

func (h *Host) read(p string) string {
	b, _ := os.ReadFile(h.path(p))
	return string(b)
}

func (h *Host) memoryMiB() int {
	for _, l := range strings.Split(h.read("/proc/meminfo"), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
			kib, _ := strconv.Atoi(f[1])
			return kib / 1024
		}
	}
	return 0
}

// sandbox runs /bin/true in a transient unit with the units' hardening.
func (h *Host) sandbox(ctx context.Context) (bool, string) {
	args := []string{"--wait", "--quiet", "--collect"}
	for _, p := range deploy.Sandbox() {
		args = append(args, "-p", p)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := h.Run(ctx, "", "systemd-run", append(args, "/bin/true")...)
	if err != nil {
		return false, "a unit with the node's sandbox does not start: " + firstLines(out, 2)
	}
	return true, "namespaces, seccomp and the read-only system work in units"
}

// ipFirewall checks that IPAddressDeny= holds: a unit denied localhost
// tries this process's listener.
func (h *Host) ipFirewall(ctx context.Context) (bool, string) {
	if h.LookPath("bash") != nil || h.LookPath("timeout") != nil {
		return true, "not checked (no bash or timeout)"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return true, "not checked: " + err.Error()
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Refused (EPERM) or dropped (the connect hangs until timeout): both
	// mean the filter holds; only a connection that opens means it does not.
	_, err = h.Run(ctx, "", "systemd-run", "--wait", "--quiet", "--collect", "-p", "IPAddressDeny=localhost",
		"timeout", "5", "bash", "-c", fmt.Sprintf("exec 3<>/dev/tcp/127.0.0.1/%d", port))
	if err == nil {
		return false, "IPAddressDeny= is not enforced"
	}
	return true, "IPAddressDeny= holds"
}

func (h *Host) virt(ctx context.Context) (name string, container bool) {
	if out, err := h.Run(ctx, "", "systemd-detect-virt", "-c"); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" && v != "none" {
			return v, true
		}
	}
	out, _ := h.Run(ctx, "", "systemd-detect-virt", "-v")
	v := strings.TrimSpace(string(out))
	if v == "" || v == "none" {
		return "no virtualization detected", false
	}
	return v, false
}

// bbr reports whether the kernel has BBR loaded, built in or as a module.
func (h *Host) bbr(kernel string) bool {
	if strings.Contains(h.read("/proc/sys/net/ipv4/tcp_available_congestion_control"), "bbr") {
		return true
	}
	if kernel == "" {
		return false
	}
	dir := filepath.Join("/lib/modules", kernel)
	if strings.Contains(h.read(filepath.Join(dir, "modules.builtin")), "tcp_bbr.ko") {
		return true
	}
	return strings.Contains(h.read(filepath.Join(dir, "modules.dep")), "tcp_bbr.ko")
}

// udpBuffers reports whether the buffers are large already or can be
// raised (a container keeps /proc/sys read-only). Nothing is written.
func (h *Host) udpBuffers() bool {
	big := true
	for _, k := range []string{"rmem_max", "wmem_max"} {
		v, _ := strconv.Atoi(strings.TrimSpace(h.read("/proc/sys/net/core/" + k)))
		big = big && v >= UDPBuffer
	}
	if big {
		return true
	}
	f, err := os.OpenFile(h.path("/proc/sys/net/core/rmem_max"), os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// OSRelease reads ID and VERSION_ID of /etc/os-release.
func (h *Host) OSRelease() (id, version string) {
	sc := bufio.NewScanner(strings.NewReader(h.read("/etc/os-release")))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	return id, version
}

func isTested(id, version string) bool {
	for _, v := range tested[id] {
		// Rocky's VERSION_ID carries the minor release: "10.0".
		if version == v || (id == "rocky" && strings.HasPrefix(version, v+".")) {
			return true
		}
	}
	return false
}

type warning struct{ detail, fix string }

// updateWarnings says when the host runs behind its own fixes: a newer
// kernel installed but not booted, a reboot asked for, no automatic
// security updates. Remote bugs in the network stack are fixed in the
// kernel; the perimeter limits what reaches it, it does not replace the
// fix (docs/08-decisions.md, R4-9).
func updateWarnings(root, running string) []warning {
	var out []warning
	if entries, err := os.ReadDir(filepath.Join(root, "/lib/modules")); err == nil && running != "" {
		newest := running
		for _, e := range entries {
			if e.IsDir() && VersionLess(newest, e.Name()) {
				newest = e.Name()
			}
		}
		if newest != running {
			out = append(out, warning{fmt.Sprintf("kernel %s is installed but %s is running", newest, running), "reboot to run the fixes"})
		}
	}
	if _, err := os.Stat(filepath.Join(root, "/var/run/reboot-required")); err == nil {
		out = append(out, warning{"the system asks for a reboot (/var/run/reboot-required)", "reboot"})
	}
	auto := false
	if b, err := os.ReadFile(filepath.Join(root, "/etc/apt/apt.conf.d/20auto-upgrades")); err == nil { //nolint:gosec // G304: a fixed path under root
		_, err := os.Stat(filepath.Join(root, "/usr/bin/unattended-upgrade"))
		auto = err == nil && strings.Contains(string(b), `Unattended-Upgrade "1"`)
	}
	for _, timer := range []string{"dnf-automatic-install.timer", "dnf-automatic.timer"} {
		if _, err := os.Stat(filepath.Join(root, "/etc/systemd/system/timers.target.wants", timer)); err == nil {
			auto = true
		}
	}
	if !auto {
		out = append(out, warning{"security updates are not installed automatically",
			"apt install unattended-upgrades; or dnf install dnf-automatic && systemctl enable --now dnf-automatic-install.timer"})
	}
	return out
}

// VersionLess compares kernel versions (6.1.0-28-amd64, 5.14.0-427.el9):
// runs of digits as numbers, the rest as text.
func VersionLess(a, b string) bool {
	pa, pb := versionParts.FindAllString(a, -1), versionParts.FindAllString(b, -1)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] == pb[i] {
			continue
		}
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		if ea == nil && eb == nil {
			return na < nb
		}
		return pa[i] < pb[i]
	}
	return len(pa) < len(pb)
}

var versionParts = regexp.MustCompile(`\d+|\D+`)

func firstLines(b []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "; ")
}
