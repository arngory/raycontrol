// Package deploy describes what root installs on a node for the current
// services: system users with fixed UIDs, systemd units and a few system
// files. Socket permissions follow IPC.md in arngory/niko: a process that
// connects to another one's socket joins that process's group.
package deploy

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/site"
	"github.com/arngory/raycontrol/internal/store"
)

// Binaries are the executables the units start.
type Binaries struct {
	Rayd       string
	Rayspa     string
	NikoServer string
	Xray       string
	Slipstream string // slipstream-server (spec/slipstream-v1.md)
}

// DefaultBinaries are the install locations. The data plane has a
// directory of its own: an Xray or a niko-server the host already has in
// /usr/local/bin, for other software, is never replaced.
var DefaultBinaries = Binaries{
	Rayd:       "/usr/local/bin/rayd",
	Rayspa:     "/usr/local/bin/rayspa",
	NikoServer: DataPlaneDir + "/niko-server",
	Xray:       DataPlaneDir + "/xray",
	Slipstream: DataPlaneDir + "/slipstream-server",
}

// DataPlaneDir holds the data-plane binaries raycontrol installs.
const DataPlaneDir = "/usr/local/libexec/raycontrol"

// DataDir holds the data a release ships: the AS database of the client
// summaries (IPinfo Lite, R4-21) and the notice of its licence.
const DataDir = "/usr/local/share/raycontrol"

// DataFiles are the files of DataDir, by their names in the release.
var DataFiles = []string{"ipinfo_lite.mmdb", "NOTICE"}

// Paths of the control plane on an installed node.
const (
	StateDir = "/var/lib/raycontrol"
	DB       = StateDir + "/rayd.db"
	// RayspaState is the last snapshot rayspa applied, its start until rayd
	// or the exit answers.
	RayspaState = "/var/lib/rayspa/snapshot.pb"
	// HardeningSysctl is the network hardening every raycontrol host gets.
	HardeningSysctl = "/etc/sysctl.d/90-raycontrol.conf"
	// RelaySysctl turns forwarding on, on a relay host only.
	RelaySysctl = "/etc/sysctl.d/91-raycontrol-relay.conf"
	Socket      = "/run/raycontrol/rayd.sock"
	AdminGroup  = "raycontrol"
)

// SystemUser is a system user (with a group of the same name).
type SystemUser struct {
	Name        string
	UID         int
	ExtraGroups []string
}

// File is a file root writes.
type File struct {
	Path    string
	Mode    uint32
	Content []byte
}

// Plan is the full deployment.
type Plan struct {
	Users    []SystemUser
	Files    []File
	Units    []string // enabled and kept running, in start order
	Warnings []string
	// HostPorts are the ports clients reach (firewalld, ufw).
	HostPorts []PortRange
	// FrontDNS: the front answers DNS tunnels on UDP 53.
	FrontDNS bool
	// ICMP: a naive service carries ping and traceroute (icmp=on,
	// spec/icmp-v1.md); the data plane's groups must be in
	// net.ipv4.ping_group_range (Host.Apply widens it).
	ICMP bool
	// Conntrack: Host.Apply sizes the conntrack table and shortens its
	// times (spec/conn-limit-v1.md §6.1). A node's plan has it.
	Conntrack bool
	// Processes are the data-plane units as plain processes, in start
	// order, and Dirs the directories they share: what rayd serve
	// -supervise runs where there is no systemd (tests, containers).
	Processes []Process
	Dirs      []string
}

// Process is a data-plane unit without systemd. It comes from the unit's
// own lines, so the two cannot drift apart; the user, the groups and the
// sandbox of the unit are not applied.
type Process struct {
	Unit  string
	Args  []string // ExecStart
	Needs string   // ConditionPathExists: not started until it exists
	Dir   string   // RuntimeDirectory: created empty at each start
	// Copies are the credentials root copies in before the start
	// (ExecStartPre=+rayd credential), source and destination.
	Copies [][2]string
}

// hardening applies to every unit.
const hardening = `NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
Restart=always
RestartSec=2
`

// Sandbox is the hardening every unit has, as KEY=VALUE: the host check
// runs a transient unit with it (and PrivateNetwork, which the unix-only
// backends add) before the install.
func Sandbox() []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(hardening), "\n") {
		if !strings.HasPrefix(l, "Restart") {
			out = append(out, l)
		}
	}
	return append(out, "PrivateNetwork=yes")
}

type unit struct {
	name        string
	description string
	after       []string
	service     []string // lines of [Service] before the hardening block
	// needs is the file the process reads: until rayd has rendered it, the
	// unit is skipped instead of failing (rayd starts it then).
	needs string
	// unitLines are more lines of [Unit] (dependencies).
	unitLines []string
	// wantedBy is the unit enabling it pulls in: multi-user.target if empty.
	wantedBy string
}

func (u unit) file() File {
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by raycontrol; changes are overwritten by rayctl apply.\n[Unit]\nDescription=%s\n", u.description)
	after := append([]string{"network-online.target"}, u.after...)
	// No start rate limit: Restart= keeps trying every RestartSec, e.g. until
	// rayd has rendered a file the process needs.
	fmt.Fprintf(&b, "Wants=network-online.target\nAfter=%s\nStartLimitIntervalSec=0\n", strings.Join(after, " "))
	if u.needs != "" {
		fmt.Fprintf(&b, "ConditionPathExists=%s\n", u.needs)
	}
	for _, l := range u.unitLines {
		b.WriteString(l + "\n")
	}
	b.WriteString("\n[Service]\n")
	for _, l := range u.service {
		b.WriteString(l + "\n")
	}
	b.WriteString(hardening)
	wantedBy := u.wantedBy
	if wantedBy == "" {
		wantedBy = "multi-user.target"
	}
	fmt.Fprintf(&b, "\n[Install]\nWantedBy=%s\n", wantedBy)
	return File{Path: "/etc/systemd/system/" + u.name, Mode: 0o644, Content: []byte(b.String())}
}

// process is the unit as a plain process (Plan.Processes).
func (u unit) process() Process {
	pr := Process{Unit: u.name, Needs: u.needs}
	for _, l := range u.service {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "ExecStart":
			pr.Args = strings.Fields(v)
		case "ExecStartPre":
			if src, dst, ok := copyOf(v); ok {
				pr.Copies = append(pr.Copies, [2]string{src, dst})
			}
		case "RuntimeDirectory":
			// Relative to /run, unless the paths are elsewhere.
			if !path.IsAbs(v) {
				v = path.Join("/run", v)
			}
			pr.Dir = v
		}
	}
	return pr
}

func groups(gs []string) string {
	if len(gs) == 0 {
		return ""
	}
	return "SupplementaryGroups=" + strings.Join(gs, " ")
}

// Build returns the deployment for the inputs: in from InputsOf on rayd's
// side, or from rayd through GetDeployInputs on root's (rayctl apply),
// where p and bin are root's own. A service that fails its checks
// (CheckService) is left out with a warning; what remains goes into the
// units from the templates below and nothing else.
func Build(in Inputs, p render.Paths, bin Binaries) Plan {
	plan := Plan{Conntrack: true}
	services, warnings := in.checked()
	plan.Warnings = warnings
	var inner *ServiceInput
	var dns, reality, sites, hysteria, naives, yggs []ServiceInput
	for i, s := range services {
		switch {
		case s.Kind == "inner":
			inner = &services[i]
		case s.Kind == "site":
			sites = append(sites, s)
		case provision.DNSTunnel(s.Kind):
			dns = append(dns, s)
		case s.Kind == "reality":
			reality = append(reality, s)
		case render.IsHysteria(s.Kind):
			hysteria = append(hysteria, s)
		case s.Kind == "naive":
			naives = append(naives, s)
		case s.Kind == "yggdrasil":
			yggs = append(yggs, s)
		case s.Kind == "doh":
			// rayd serves it (serveDoH), behind the front: its socket
			// directory is below, no unit of its own.
		case s.UID != 0:
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("service %s (%s) is not deployed by this version", s.Name, s.Kind))
		}
	}
	// A slipstream server takes its settings as arguments: without them,
	// or without the inner stage, it has no unit (Render leaves it out of
	// the front too).
	dns = slices.DeleteFunc(dns, func(s ServiceInput) bool {
		if s.Kind != "slipstream" {
			return false
		}
		if inner == nil {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("service %s (slipstream) needs the inner stage", s.Name))
			return true
		}
		if s.SlipstreamError != "" {
			plan.Warnings = append(plan.Warnings, s.SlipstreamError)
			return true
		}
		if _, err := slipstreamArgs(s, inner.Name, p); err != nil {
			plan.Warnings = append(plan.Warnings, err.Error())
			return true
		}
		return false
	})
	hasFront := in.Front
	// Credentials are copied in from rendered files by root, from a
	// directory rayd cannot change (copyIn).
	anchor := renderedAnchor(p)

	var raydGroups []string
	var units []unit
	// frontIn lets a service write its sockets for the front (ProtectSystem
	// makes /run read-only past RuntimeDirectory).
	frontIn := func(s ServiceInput) string { return "ReadWritePaths=" + p.FrontDir(s.Name) }
	// innerHidden: the tunnels into inner are in its group for its socket,
	// not for its config, which holds its decryption seed and every user's
	// credential (review).
	innerHidden := func() string {
		if inner == nil {
			return ""
		}
		return "InaccessiblePaths=-" + path.Join(p.Rendered, inner.Name)
	}

	// Xray processes: the inner stage and REALITY. The API socket lives
	// apart: only rayd may reach it (tmpfiles below).
	xrayUnit := func(s ServiceInput, description string, caps string) unit {
		g := render.GroupName(s.Name)
		return unit{
			name:        render.UnitName(s.Name),
			description: description,
			needs:       path.Join(p.Rendered, s.Name, "xray.json"),
			service: []string{
				"User=" + g, "Group=" + g,
				"ExecStart=" + bin.Xray + " run -c " + path.Join(p.Rendered, s.Name, "xray.json"),
				"RuntimeDirectory=" + strings.TrimPrefix(path.Join(p.Run, s.Name), "/run/"),
				"RuntimeDirectoryMode=0710",
				"ReadWritePaths=" + path.Dir(p.APISocket(s.Name)),
				"UMask=0007",
				caps,
				"CapabilityBoundingSet=" + strings.TrimPrefix(caps, "AmbientCapabilities="),
				"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
			},
		}
	}
	var xrays []ServiceInput
	if inner != nil {
		g := render.GroupName(inner.Name)
		raydGroups = append(raydGroups, g)
		plan.Users = append(plan.Users, SystemUser{Name: g, UID: inner.UID})
		units = append(units, xrayUnit(*inner, "raycontrol inner stage "+inner.Name+" (Xray, VLESS with ML-KEM-768)", ""))
		xrays = append(xrays, *inner)
	}
	// The decoy site (interim, until niko-server has its site backend): rayd
	// site on a unix socket, the self-steal target of REALITY.
	for _, s := range sites {
		g := render.GroupName(s.Name)
		raydGroups = append(raydGroups, g)
		plan.Users = append(plan.Users, SystemUser{Name: g, UID: s.UID})
		dir := path.Join(p.Rendered, s.Name)
		key := p.Credential(s.Name, render.SiteKey)
		args := " site -answer " + s.Answer
		if s.Answer == site.AnswerPages {
			args += " -root " + path.Join(dir, render.SiteRoot)
		}
		units = append(units, unit{
			name:        render.UnitName(s.Name),
			description: "raycontrol decoy site " + s.Name,
			needs:       path.Join(dir, render.SiteChain),
			service: []string{
				"User=" + g, "Group=" + g,
				copyIn(bin.Rayd, anchor, renderedOwner, g, path.Join(dir, render.SiteKey), key),
				"ExecStart=" + bin.Rayd + args + " -chain " + path.Join(dir, render.SiteChain) +
					" -key " + key + " -socket " + p.SiteSocket(s.Name),
				"RuntimeDirectory=" + strings.TrimPrefix(path.Join(p.Run, s.Name), "/run/"),
				"RuntimeDirectoryMode=0710",
				"UMask=0007",
				"CapabilityBoundingSet=",
				// A unix socket only: REALITY brings the connections.
				"PrivateNetwork=yes",
				"RestrictAddressFamilies=AF_UNIX",
			},
		})
	}
	for _, s := range reality {
		g := render.GroupName(s.Name)
		raydGroups = append(raydGroups, g)
		var extra []string
		if s.Site != "" {
			extra = []string{render.GroupName(s.Site)} // reaches the site socket
		}
		plan.Users = append(plan.Users, SystemUser{Name: g, UID: s.UID, ExtraGroups: extra})
		caps := ""
		if !in.FrontTCP {
			caps = "AmbientCapabilities=CAP_NET_BIND_SERVICE" // binds TCP 443 itself (R2-7)
		}
		u := xrayUnit(s, "raycontrol REALITY "+s.Name+" (Xray, VLESS + REALITY + Vision, ML-KEM-768)", caps)
		if in.FrontTCP {
			u.service = append(u.service, frontIn(s)) // the front connects to reality.sock
		}
		units = append(units, u)
		xrays = append(xrays, s)
	}

	// Channel probes through naive and Hysteria2 (R4-16): the probe name
	// leads to the subscription endpoint on loopback, its port only (checked
	// in the process; systemd lets loopback through for it).
	probeArg, probeAllow := "", ""
	if port := in.SubscriptionPort; port > 0 && port <= 65535 {
		probeArg = fmt.Sprintf(" -probe 127.0.0.1:%d", port)
		probeAllow = "IPAddressAllow=127.0.0.1"
	}

	// Hysteria2 behind udpmux (R3-4): niko-server backends on the front's
	// datagrams; they go out to public addresses only. They look names up
	// with the host's resolver: systemd-resolved's stub on loopback stays
	// in reach (stubAllow; the perimeter lets port 53 only through there).
	for _, s := range hysteria {
		g := render.GroupName(s.Name)
		raydGroups = append(raydGroups, g)
		plan.Users = append(plan.Users, SystemUser{Name: g, UID: s.UID})
		dir := path.Join(p.Rendered, s.Name)
		creds := []string{copyIn(bin.Rayd, anchor, renderedOwner,
			g, path.Join(dir, render.HysteriaKey), p.Credential(s.Name, render.HysteriaKey))}
		if s.Kind == "hy2-obfs" {
			creds = append(creds, copyIn(bin.Rayd, anchor, renderedOwner,
				g, path.Join(dir, render.HysteriaObfs), p.Credential(s.Name, render.HysteriaObfs)))
		}
		units = append(units, unit{
			name:        render.UnitName(s.Name),
			description: "niko-server backend " + s.Name + " (Hysteria2, " + s.Kind + ")",
			needs:       path.Join(dir, "backend.json"),
			service: append([]string{
				"User=" + g, "Group=" + g,
				"ExecStart=" + bin.NikoServer + " backend -c " + path.Join(dir, "backend.json"),
				"RuntimeDirectory=" + strings.TrimPrefix(path.Join(p.Run, s.Name), "/run/"),
				"RuntimeDirectoryMode=0710",
				frontIn(s), // the front connects to packet.sock
				"UMask=0007",
				"CapabilityBoundingSet=",
				"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
				denyLocal,
				probeAllow, // the probe name's address (R4-16); the process checks the rest
				stubAllow,
			}, creds...),
		})
	}

	// naive (R2-14): rayd naive behind the site, which passes its name on.
	// It exits to the internet and nowhere else: not the node itself, not
	// local networks (also checked in the process, address by address).
	frontUID := ""
	if p.Supervised {
		frontUID = fmt.Sprintf(" -front-uid %d", p.PeerUID(render.FrontUID))
	}
	for _, s := range naives {
		g := render.GroupName(s.Name)
		raydGroups = append(raydGroups, g)
		plan.Users = append(plan.Users, SystemUser{Name: g, UID: s.UID})
		dir := path.Join(p.Rendered, s.Name)
		key := p.Credential(s.Name, render.NaiveKey)
		answer := site.Answer404
		for _, x := range sites {
			// The site's answer, except pages: their files are the site's own.
			if x.Name == s.Site && x.Answer != site.AnswerPages {
				answer = x.Answer
			}
		}
		icmp := ""
		if s.ICMP {
			// ping and traceroute (spec/icmp-v1.md): ICMP datagram sockets,
			// which AF_INET and AF_INET6 cover; apply lets the group open them.
			icmp = " -icmp"
			plan.ICMP = true
		}
		units = append(units, unit{
			name:        render.UnitName(s.Name),
			description: "raycontrol naive " + s.Name + " (HTTP/2 and HTTP/3, X25519MLKEM768)",
			needs:       path.Join(dir, render.NaiveChain),
			service: []string{
				"User=" + g, "Group=" + g,
				copyIn(bin.Rayd, anchor, renderedOwner, g, path.Join(dir, render.NaiveKey), key),
				// The stats socket (traffic-limit-v1 §2.3) in the runtime
				// directory, as Hysteria2's: rayd's group passes through.
				"ExecStart=" + bin.Rayd + " naive -answer " + answer + " -users " + path.Join(dir, render.NaiveUsers) +
					" -chain " + path.Join(dir, render.NaiveChain) + " -key " + key + " -socket " + p.NaiveSocket(s.Name) +
					" -quic-socket " + p.NaiveQUICSocket(s.Name) + " -stats-socket " + p.StatsSocket(s.Name) +
					" -conn-limit " + path.Join(dir, render.NaiveConnLimit) + probeArg + frontUID + icmp,
				"RuntimeDirectory=" + strings.TrimPrefix(path.Join(p.Run, s.Name), "/run/"),
				"RuntimeDirectoryMode=0710",
				"ReadWritePaths=" + path.Dir(p.NaiveSocket(s.Name)),
				"UMask=0007",
				"CapabilityBoundingSet=",
				"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
				denyLocal,
				probeAllow,
			},
		})
	}

	for _, s := range dns {
		g := render.GroupName(s.Name)
		// The process: niko-server's backend, or the slipstream server
		// with its arguments (it reads no config file), which needs its
		// certificate.
		needs := path.Join(p.Rendered, s.Name, "backend.json")
		exec := bin.NikoServer + " backend -c " + needs
		description := "niko-server backend " + s.Name + " (" + s.Kind + ")"
		if s.Kind == "slipstream" {
			args, _ := slipstreamArgs(s, inner.Name, p) // checked above
			needs = path.Join(p.Rendered, s.Name, render.SlipstreamCert)
			exec = bin.Slipstream + " " + strings.Join(args, " ")
			description = "slipstream server " + s.Name + " (behind the DNS front)"
		}
		raydGroups = append(raydGroups, g)
		var extra []string
		if inner != nil {
			extra = []string{render.GroupName(inner.Name)}
		}
		plan.Users = append(plan.Users, SystemUser{Name: g, UID: s.UID, ExtraGroups: extra})
		// Secrets: copied by root into the runtime directory, readable by the
		// service user only. Not LoadCredential=: systemd does not set up
		// credentials in containers (Docker, LXC), and the copy keeps them
		// from everyone but the service user (R2-9).
		// By kind, not from this render's files: a service that failed to
		// render keeps its earlier key, and its unit must still copy it.
		// dnsseal-v1's keys are not among them: the backend reads them in
		// place, in a file of the service group, as dnsauth's.
		secret := render.DNSSecret(s.Kind)
		if s.Kind == "slipstream" {
			secret = render.SlipstreamKey
		}
		creds := []string{copyIn(bin.Rayd, anchor, renderedOwner,
			g, path.Join(p.Rendered, s.Name, secret), p.Credential(s.Name, secret))}
		after := []string{}
		if inner != nil {
			after = append(after, render.UnitName(inner.Name))
		}
		units = append(units, unit{
			name:        render.UnitName(s.Name),
			description: description,
			needs:       needs,
			after:       after,
			service: append([]string{
				"User=" + g, "Group=" + g, groups(extra), innerHidden(),
				"ExecStart=" + exec,
				"RuntimeDirectory=" + strings.TrimPrefix(path.Join(p.Run, s.Name), "/run/"),
				"RuntimeDirectoryMode=0710",
				frontIn(s), // the front connects to packet.sock
				"UMask=0007",
				"CapabilityBoundingSet=",
				// Only unix sockets: the front brings the packets, inner takes the streams.
				"PrivateNetwork=yes",
				"RestrictAddressFamilies=AF_UNIX",
			}, creds...),
		})
	}

	// Yggdrasil (R4-15): a niko-server backend on the streams the front
	// passes by name; its mesh address leads to inner only. Unix sockets
	// only: the yggdrasil-go core and the netstack live in the process.
	// Until its site has a certificate the files are not there, and the unit
	// waits for them (ConditionPathExists); rayd starts it once they are.
	for _, s := range yggs {
		dir := path.Join(p.Rendered, s.Name)
		g := render.GroupName(s.Name)
		raydGroups = append(raydGroups, g)
		var extra []string
		if inner != nil {
			extra = []string{render.GroupName(inner.Name)}
		}
		plan.Users = append(plan.Users, SystemUser{Name: g, UID: s.UID, ExtraGroups: extra})
		var creds []string
		for _, name := range []string{render.YggdrasilTLSKey, render.YggdrasilNodeKey} {
			creds = append(creds, copyIn(bin.Rayd, anchor, renderedOwner,
				g, path.Join(dir, name), p.Credential(s.Name, name)))
		}
		var after []string
		if inner != nil {
			after = append(after, render.UnitName(inner.Name))
		}
		// With public peers (P-14, R4-18) the core dials them: the internet
		// only, like the other backends that go out; otherwise no network.
		network := []string{"PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX"}
		if s.PublicPeers {
			network = []string{
				"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
				denyLocal,
				stubAllow, // peers by name
			}
		}
		units = append(units, unit{
			name:        render.UnitName(s.Name),
			description: "niko-server backend " + s.Name + " (Yggdrasil, TLS links with X25519MLKEM768 into inner)",
			needs:       path.Join(dir, "backend.json"),
			after:       after,
			service: append([]string{
				"User=" + g, "Group=" + g, groups(extra), innerHidden(),
				"ExecStart=" + bin.NikoServer + " backend -c " + path.Join(dir, "backend.json"),
				"RuntimeDirectory=" + strings.TrimPrefix(path.Join(p.Run, s.Name), "/run/"),
				"RuntimeDirectoryMode=0710",
				frontIn(s), // the front connects to fd.sock
				"UMask=0007",
				"CapabilityBoundingSet=",
			}, append(network, creds...)...),
		})
	}

	if hasFront {
		// rayd writes the front config and sets its group.
		raydGroups = append(raydGroups, render.GroupName("front"))
		// In no service group: the front reaches their sockets through
		// their FrontDir, not their files (S-1).
		plan.Users = append(plan.Users, SystemUser{Name: render.GroupName("front"), UID: render.FrontUID})
		var after []string
		for _, s := range dns {
			after = append(after, render.UnitName(s.Name))
		}
		if in.FrontTCP {
			for _, s := range reality {
				after = append(after, render.UnitName(s.Name))
			}
		}
		for _, s := range hysteria {
			after = append(after, render.UnitName(s.Name))
		}
		for _, s := range yggs {
			after = append(after, render.UnitName(s.Name))
		}
		// The front's credentials, copied in by root, readable by the front
		// only: the dnsprobe-v1 key and the salamander passwords of
		// hy2-obfs. Only what this render wrote: a service that could not
		// be rendered leaves none, and an install of a missing file would
		// keep the whole front down (Q-1).
		var frontCreds []string
		cred := func(rendered bool, src, dst string) {
			if rendered {
				frontCreds = append(frontCreds, copyIn(bin.Rayd, anchor, renderedOwner, "niko-front", src, dst))
			}
		}
		cred(in.DNSProbeKey, path.Join(p.Rendered, "front", render.DNSProbeKeyFile), p.FrontDNSProbe())
		for _, s := range hysteria {
			if s.Kind == "hy2-obfs" {
				cred(s.Salamander, path.Join(p.Rendered, "front", s.Name+".salamander"), p.FrontSalamander(s.Name))
			}
		}
		units = append(units, unit{
			name:        render.UnitName("front"),
			description: "niko-server front (multiplexers)",
			needs:       path.Join(p.Rendered, "front", "front.json"),
			after:       after,
			service: append([]string{
				"User=niko-front", "Group=niko-front",
				"ExecStart=" + bin.NikoServer + " front -c " + path.Join(p.Rendered, "front", "front.json"),
				"RuntimeDirectory=" + strings.TrimPrefix(path.Join(p.Run, "front"), "/run/"),
				// The front group (rayd) passes through to the stats
				// socket; the credentials in it are the front's alone
				// (0400).
				"RuntimeDirectoryMode=0710",
				"AmbientCapabilities=CAP_NET_BIND_SERVICE",
				"CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
				"UMask=0007",
				"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
			}, frontCreds...),
		})
	}

	sort.Strings(raydGroups)
	plan.Users = append(plan.Users,
		SystemUser{Name: "rayd", UID: render.RaydUID, ExtraGroups: raydGroups},
		SystemUser{Name: "rayspa", UID: render.RayspaUID},
	)
	control := []unit{
		{
			name:        "rayd.service",
			description: "raycontrol node daemon",
			service: []string{
				"User=rayd", "Group=rayd", groups(raydGroups),
				"ExecStart=" + bin.Rayd + " serve -db " + DB + " -socket " + Socket + " -rendered " + p.Rendered,
				"StateDirectory=raycontrol",
				"StateDirectoryMode=0711",
				"RuntimeDirectory=raycontrol",
				"RuntimeDirectoryMode=0755",
				"UMask=0027",
				"CapabilityBoundingSet=",
				// AF_NETLINK: sock_diag, the node's view of a device's
				// connections for probes (R4-16); read-only, no capability.
				"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
			},
		},
		{
			name:        "rayspa.service",
			description: "raycontrol perimeter (nftables, SPA v2)",
			// After the host firewalls: their start may flush the ruleset.
			after: []string{"rayd.service", "nftables.service", "firewalld.service", "ufw.service"},
			service: []string{
				"User=rayspa", "Group=rayspa",
				"ExecStart=" + bin.Rayspa + " run -socket " + Socket + " -state " + RayspaState,
				// The last snapshot: SPA keys and the admin addresses, rayspa's only.
				"StateDirectory=rayspa", "StateDirectoryMode=0700",
				"AmbientCapabilities=CAP_NET_ADMIN",
				"CapabilityBoundingSet=CAP_NET_ADMIN",
				"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
			},
		},
	}
	for i, u := range append(control, units...) {
		u.service = slices.DeleteFunc(u.service, func(s string) bool { return s == "" })
		// What the checks above let through cannot break the unit's lines;
		// if Build ever let something through, the unit stays out.
		if err := u.check(); err != nil {
			plan.Warnings = append(plan.Warnings, err.Error())
			continue
		}
		plan.Files = append(plan.Files, u.file())
		plan.Units = append(plan.Units, u.name)
		if i >= len(control) {
			plan.Processes = append(plan.Processes, u.process())
		}
	}
	// The update by request (spec/node-update-v1.md): rayd writes the
	// request, the path unit sees it, the service runs rayctl as root.
	// The service is not one of plan.Units: apply must never start it.
	plan.Files = append(plan.Files,
		File{Path: "/etc/systemd/system/" + nodeupdate.PathUnit, Mode: 0o644, Content: []byte(updatePath)},
		File{Path: "/etc/systemd/system/" + nodeupdate.ServiceUnit, Mode: 0o644, Content: []byte(updateService)},
	)
	plan.Units = append(plan.Units, nodeupdate.PathUnit)

	var tmp tmpfiles
	tmp.dir(p.Run, "0755", "root", "root")
	for _, s := range xrays {
		// setgid: the API socket Xray creates inherits the rayd group.
		tmp.dir(path.Dir(p.APISocket(s.Name)), "2750", render.GroupName(s.Name), "rayd")
	}
	// Sockets the front passes connections and datagrams to (R2-15), each
	// in a directory of the service user and the front's group: the front
	// reaches them and nothing else of the services (S-1).
	for _, s := range services {
		if s.Kind == "doh" {
			tmp.dir(path.Dir(p.DoHSocket(s.Name)), "2750", "rayd", render.GroupName("front"))
		}
	}
	for _, s := range slices.Concat(naives, dns, hysteria, yggs) {
		tmp.dir(p.FrontDir(s.Name), "2750", render.GroupName(s.Name), render.GroupName("front"))
	}
	if in.FrontTCP {
		for _, s := range reality {
			tmp.dir(p.FrontDir(s.Name), "2750", render.GroupName(s.Name), render.GroupName("front"))
		}
	}
	plan.Dirs = tmp.dirs
	plan.Warnings = append(plan.Warnings, tmp.warnings...)
	plan.Files = append(plan.Files,
		File{Path: tmpfilesConf, Mode: 0o644, Content: []byte(tmp.String())},
		File{Path: "/etc/polkit-1/rules.d/50-raycontrol.rules", Mode: 0o644, Content: []byte(polkitRule)},
		File{Path: HardeningSysctl, Mode: 0o644, Content: []byte(sysctl)},
	)
	// The front answers the DNS tunnels on UDP 53, beside systemd-resolved's
	// stub, which keeps 127.0.0.53 and 127.0.0.54 (niko-server v0.8.2): when
	// its rendered config listens there (a tunnel that did not render is
	// not there).
	plan.FrontDNS = in.Front && in.FrontDNS
	// rayd's own warnings last, as GetDeployment always gave them.
	plan.Warnings = append(plan.Warnings, in.Warnings...)
	return plan
}

// slipstreamArgs are a slipstream server's arguments from its settings,
// checked again (render.SlipstreamArgs reads them from the service's
// JSON).
func slipstreamArgs(s ServiceInput, inner string, p render.Paths) ([]string, error) {
	settings, err := json.Marshal(s.Slipstream)
	if err != nil {
		return nil, err
	}
	return render.SlipstreamArgs(render.Service{Service: store.Service{Kind: s.Kind, Name: s.Name, Settings: string(settings)}}, inner, p)
}

// tmpfiles is the tmpfiles.d file of the plan, and the directories it makes.
type tmpfiles struct {
	strings.Builder
	dirs     []string
	warnings []string
}

// dir adds a directory: d PATH MODE USER GROUP. A field that would break
// the line (white space, a control character) leaves it out, said.
func (t *tmpfiles) dir(p, mode, user, group string) {
	if t.Len() == 0 {
		t.WriteString("# Generated by raycontrol.\n")
	}
	for _, f := range []string{p, mode, user, group} {
		if strings.ContainsFunc(f, spaceOrControl) {
			t.warnings = append(t.warnings, fmt.Sprintf("tmpfiles line for %q left out: a field would break it", p))
			return
		}
	}
	fmt.Fprintf(t, "d %s %s %s %s -\n", p, mode, user, group)
	t.dirs = append(t.dirs, p)
}

// token reports whether s is one field of a line: not empty, no white
// space or control characters.
func token(s string) bool { return s != "" && !strings.ContainsFunc(s, spaceOrControl) }

func spaceOrControl(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }

// tokenKeys are the unit settings whose value is one field (a name, a
// path, a mode): white space there would split it.
var tokenKeys = map[string]bool{
	"User": true, "Group": true, "ConditionPathExists": true, "ReadWritePaths": true, "InaccessiblePaths": true,
	"RuntimeDirectory": true, "RuntimeDirectoryMode": true, "StateDirectory": true, "StateDirectoryMode": true,
	"UMask": true, "PartOf": true, "Requisite": true,
}

// check refuses a unit whose values would break its lines
// (spec/apply-plan-v1.md §4.1, step 2): a line break or another control
// character anywhere, white space in a name or a path. The services are
// checked before (CheckService): this catches Build itself.
func (u unit) check() error {
	bad := func(s string) bool { return strings.ContainsFunc(s, unicode.IsControl) }
	ok := token(u.name) && !bad(u.description) && (u.needs == "" || token(u.needs)) && (u.wantedBy == "" || token(u.wantedBy))
	for _, a := range u.after {
		ok = ok && token(a)
	}
	for _, l := range slices.Concat(u.unitLines, u.service) {
		k, v, found := strings.Cut(l, "=")
		ok = ok && found && token(k) && !bad(v) && (!tokenKeys[k] || v == "" || token(v))
	}
	if !ok {
		return fmt.Errorf("unit %q left out: a value would break its lines", u.name)
	}
	return nil
}

// stubAllow lets a unit that denies loopback reach systemd-resolved's stub
// (127.0.0.53, and 127.0.0.54 without its DNSSEC and search handling), where
// /etc/resolv.conf points on most hosts: niko-server resolves with the
// host's resolver. A provider's resolver in a private range stays out of
// reach (on some clouds it is the metadata server):
// deploy.SandboxResolverProblem warns. naive and Xray ask public resolvers
// themselves. Whatever else listens on any address answers there too: the
// perimeter's output chain lets the data plane reach port 53 only.
const stubAllow = "IPAddressAllow=127.0.0.53 127.0.0.54"

// denyLocal keeps a unit that goes out from the node itself and from local
// networks: the internet only.
const denyLocal = "IPAddressDeny=localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7"

// ResolvedDropIn is where installs before v0.11 turned systemd-resolved's
// stub off for the DNS tunnels; Apply removes it (giveBackStub).
const ResolvedDropIn = "/etc/systemd/resolved.conf.d/raycontrol.conf"

// updatePath and updateService run an update the node asked for: an
// admin's over the API or rayd's own for a patch release, once root
// allowed it (rayctl update remote|auto, a file of root's). rayd has no
// privileges and writes only the request; rayctl update -request checks it
// again (root's policy, signed releases only, never back) and does the
// update as by hand. No sandbox: it installs the node. A runner killed on
// the way (the timeout, a shutdown) leaves its status failed
// (ExecStopPost), not running.
const updatePath = `# Generated by raycontrol; changes are overwritten by rayctl apply.
[Unit]
Description=raycontrol: an update the node asked for (spec/node-update-v1.md)

[Path]
PathExists=` + nodeupdate.RequestFile + `

[Install]
WantedBy=multi-user.target
`

const updateService = `# Generated by raycontrol; changes are overwritten by rayctl apply.
[Unit]
Description=raycontrol update by request (rayctl update -request)
Wants=network-online.target
After=network-online.target rayd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/rayctl update -request
ExecStopPost=-/usr/local/bin/rayctl update -request-ended
TimeoutStartSec=50min
StateDirectory=raycontrol-update
StateDirectoryMode=0755
`

// polkitRule lets rayd restart data-plane units after it re-renders their
// configs, and nothing else.
const polkitRule = `// Generated by raycontrol.
polkit.addRule(function(action, subject) {
	if (action.id == "org.freedesktop.systemd1.manage-units" && subject.user == "rayd") {
		var unit = action.lookup("unit");
		var verb = action.lookup("verb");
		if (unit && /^niko-[a-z0-9-]+\.service$/.test(unit) &&
		    (verb == "restart" || verb == "try-restart" || verb == "reload-or-restart")) {
			return polkit.Result.YES;
		}
	}
});
`

const sysctl = `# Generated by raycontrol (docs/08-decisions.md, J-4).
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# QUIC (Hysteria2, naive-quic) wants large UDP buffers.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
# Less for strangers to steer (docs/08-decisions.md, R4-9): no source
# routes, no redirects, SYN cookies under a flood, no bogus ICMP errors.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
`
