package deploy

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/site"
)

// legacyBuild is Build as it was before Inputs (v0.20.1, with naive's
// ICMP of spec/icmp-v1.md, which came beside Inputs), kept as the
// oracle of TestBuildFromInputs: the plan rayctl now builds from rayd's
// inputs must be the plan rayd built from its model, byte for byte, so
// that nothing changes on a node. Two changes only, made in both on
// purpose: the credentials are copied in by rayd's credential command,
// not by install(1) (copyIn, spec/apply-plan-v1.md §6, 3), and naive
// gives its users' bytes on a stats socket (traffic-limit-v1 §2.3).
// Remove it with GetDeployment's files (§4.1, step 8).
func legacyBuild(m render.Model, files []render.File, p render.Paths, bin Binaries) Plan {
	plan := Plan{Conntrack: true}
	var inner *render.Service
	var dns, reality, sites, hysteria, naives, yggs []render.Service
	for i, s := range m.Services {
		switch {
		case s.Kind == "inner":
			inner = &m.Services[i]
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
	dns = slices.DeleteFunc(dns, func(s render.Service) bool {
		if s.Kind != "slipstream" {
			return false
		}
		if inner == nil {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("service %s (slipstream) needs the inner stage", s.Name))
			return true
		}
		if _, err := render.SlipstreamArgs(s, inner.Name, p); err != nil {
			plan.Warnings = append(plan.Warnings, err.Error())
			return true
		}
		return false
	})
	// The front's config, not any file of the front's: a slipstream service
	// that failed to render still refreshes its keys file there (review).
	frontConfig := path.Join(p.Rendered, "front", "front.json")
	hasFront := slices.ContainsFunc(files, func(f render.File) bool { return f.Path == frontConfig })
	anchor := renderedAnchor(p) // decision 3, the one change since v0.20.1

	var raydGroups []string
	var units []unit
	// frontIn lets a service write its sockets for the front (ProtectSystem
	// makes /run read-only past RuntimeDirectory).
	frontIn := func(s render.Service) string { return "ReadWritePaths=" + p.FrontDir(s.Name) }
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
	xrayUnit := func(s render.Service, description string, caps string) unit {
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
	var xrays []render.Service
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
		answer := provision.SiteAnswer(s.Service)
		args := " site -answer " + answer
		if answer == site.AnswerPages {
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
		var rs render.RealitySettings
		_ = json.Unmarshal([]byte(s.Settings), &rs)
		var extra []string
		if rs.Site != "" {
			extra = []string{render.GroupName(rs.Site)} // reaches the site socket
		}
		plan.Users = append(plan.Users, SystemUser{Name: g, UID: s.UID, ExtraGroups: extra})
		caps := ""
		if !m.FrontTCP {
			caps = "AmbientCapabilities=CAP_NET_BIND_SERVICE" // binds TCP 443 itself (R2-7)
		}
		u := xrayUnit(s, "raycontrol REALITY "+s.Name+" (Xray, VLESS + REALITY + Vision, ML-KEM-768)", caps)
		if m.FrontTCP {
			u.service = append(u.service, frontIn(s)) // the front connects to reality.sock
		}
		units = append(units, u)
		xrays = append(xrays, s)
	}

	// Channel probes through naive and Hysteria2 (R4-16): the probe name
	// leads to the subscription endpoint on loopback, its port only (checked
	// in the process; systemd lets loopback through for it).
	probeArg, probeAllow := "", ""
	if port := m.SubscriptionPort(); port != 0 {
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
				"IPAddressDeny=localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7",
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
		for _, x := range m.Services {
			// The site's answer, except pages: their files are the site's own.
			if x.Kind == "site" && x.Name == provision.SiteOf(s.Service) && provision.SiteAnswer(x.Service) != site.AnswerPages {
				answer = provision.SiteAnswer(x.Service)
			}
		}
		icmp := ""
		if provision.NaiveICMP(s.Service) {
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
				"IPAddressDeny=localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7",
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
			args, _ := render.SlipstreamArgs(s, inner.Name, p) // checked above
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
		if st, _, err := render.YggdrasilNode(s); err == nil && len(st.Peers) > 0 {
			network = []string{
				"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
				"IPAddressDeny=localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7",
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
		if m.FrontTCP {
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
		rendered := map[string]bool{}
		for _, f := range files {
			rendered[f.Path] = true
		}
		var frontCreds []string
		cred := func(src, dst string) {
			if rendered[src] {
				frontCreds = append(frontCreds, copyIn(bin.Rayd, anchor, renderedOwner, "niko-front", src, dst))
			}
		}
		cred(path.Join(p.Rendered, "front", render.DNSProbeKeyFile), p.FrontDNSProbe())
		for _, s := range hysteria {
			if s.Kind == "hy2-obfs" {
				cred(path.Join(p.Rendered, "front", s.Name+".salamander"), p.FrontSalamander(s.Name))
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

	tmp := "# Generated by raycontrol.\nd " + p.Run + " 0755 root root -\n"
	for _, s := range xrays {
		// setgid: the API socket Xray creates inherits the rayd group.
		tmp += fmt.Sprintf("d %s 2750 %s rayd -\n", path.Dir(p.APISocket(s.Name)), render.GroupName(s.Name))
	}
	// Sockets the front passes connections and datagrams to (R2-15), each
	// in a directory of the service user and the front's group: the front
	// reaches them and nothing else of the services (S-1).
	for _, s := range m.Services {
		if s.Kind == "doh" {
			tmp += fmt.Sprintf("d %s 2750 rayd %s -\n", path.Dir(p.DoHSocket(s.Name)), render.GroupName("front"))
		}
	}
	for _, s := range slices.Concat(naives, dns, hysteria, yggs) {
		tmp += fmt.Sprintf("d %s 2750 %s %s -\n", p.FrontDir(s.Name), render.GroupName(s.Name), render.GroupName("front"))
	}
	if m.FrontTCP {
		for _, s := range reality {
			tmp += fmt.Sprintf("d %s 2750 %s %s -\n", p.FrontDir(s.Name), render.GroupName(s.Name), render.GroupName("front"))
		}
	}
	for _, l := range strings.Split(tmp, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "d" {
			plan.Dirs = append(plan.Dirs, f[1])
		}
	}
	plan.Files = append(plan.Files,
		File{Path: "/etc/tmpfiles.d/raycontrol.conf", Mode: 0o644, Content: []byte(tmp)},
		File{Path: "/etc/polkit-1/rules.d/50-raycontrol.rules", Mode: 0o644, Content: []byte(polkitRule)},
		File{Path: HardeningSysctl, Mode: 0o644, Content: []byte(sysctl)},
	)
	// The front answers the DNS tunnels on UDP 53, beside systemd-resolved's
	// stub, which keeps 127.0.0.53 and 127.0.0.54 (niko-server v0.8.2): when
	// its rendered config listens there (a tunnel that did not render is
	// not there).
	front := path.Join(p.Rendered, "front", "front.json")
	for _, f := range files {
		if f.Path == front {
			var c struct {
				DNS *struct {
					Listen []string `json:"listen"`
				} `json:"dns"`
			}
			plan.FrontDNS = json.Unmarshal(f.Content, &c) == nil && c.DNS != nil && len(c.DNS.Listen) > 0
		}
	}
	return plan
}
