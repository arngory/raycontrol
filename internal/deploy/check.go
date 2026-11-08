package deploy

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// Check is the last barrier before root installs a plan
// (spec/apply-plan-v1.md §2.2, §3.2): what root writes, whom it creates,
// what it starts, against a closed list of the node's layout
// (render.DefaultPaths, DefaultBinaries). Host.Apply checks every plan
// before it changes anything. The plans are rayctl's own (Build from
// checked inputs, RelayPlan): this catches Build, should it ever let
// through what rayd gave it.
//
// Files: the units of rayd, rayspa, niko-<name> and the relay's probe,
// the update's two units, tmpfiles, polkit, two sysctl files, two firewall
// files; mode 0644 or 0755, nothing else (no setuid, setgid or sticky
// bit). Fixed files must be as rayctl writes them; units only have the
// lines of their templates; tmpfiles only directories under the data
// plane's runtime directory. Users: rayd, rayspa, niko-<name> with their
// UIDs, in niko-* groups only. Units: only those whose files the plan has.
func (p Plan) Check() error {
	users := map[string]bool{}
	uids := map[int]bool{}
	for _, u := range p.Users {
		if err := checkUser(u); err != nil {
			return err
		}
		if users[u.Name] || uids[u.UID] {
			return fmt.Errorf("user %s or UID %d twice", u.Name, u.UID)
		}
		users[u.Name], uids[u.UID] = true, true
	}
	for _, u := range p.Users {
		for _, g := range u.ExtraGroups {
			if !strings.HasPrefix(g, "niko-") || !users[g] {
				return fmt.Errorf("user %s in group %q: only the plan's niko-* groups", u.Name, g)
			}
		}
	}
	for _, r := range p.HostPorts {
		if err := r.Check(); err != nil {
			return err
		}
	}
	firewall := map[string][]byte{}
	for _, f := range FirewallFiles(p.HostPorts) {
		firewall[f.Path] = f.Content
	}
	fixed := map[string]string{
		HardeningSysctl: sysctl,
		RelaySysctl:     relaySysctl,
		"/etc/polkit-1/rules.d/50-raycontrol.rules":     polkitRule,
		"/etc/systemd/system/" + nodeupdate.PathUnit:    updatePath,
		"/etc/systemd/system/" + nodeupdate.ServiceUnit: updateService,
	}
	files := map[string]bool{}
	for _, f := range p.Files {
		if files[f.Path] {
			return fmt.Errorf("%s twice", f.Path)
		}
		files[f.Path] = true
		if f.Mode != 0o644 && f.Mode != 0o755 {
			return fmt.Errorf("%s: mode %#o, want 0644 or 0755", f.Path, f.Mode)
		}
		var err error
		want, isFixed := fixed[f.Path]
		fw, isFirewall := firewall[f.Path]
		unit, isUnit := strings.CutPrefix(f.Path, "/etc/systemd/system/")
		switch {
		case isFixed:
			if string(f.Content) != want {
				err = errors.New("not as rayctl writes it")
			}
		case isFirewall:
			if !bytes.Equal(f.Content, fw) {
				err = errors.New("not the host ports'")
			}
		case f.Path == tmpfilesConf:
			err = checkTmpfiles(string(f.Content), users)
		case isUnit && unitUser(unit) != "":
			err = checkUnit(unit, string(f.Content), users)
		default:
			err = errors.New("not a file raycontrol installs")
		}
		if err != nil {
			return fmt.Errorf("%s: %w", f.Path, err)
		}
	}
	seen := map[string]bool{}
	for _, u := range p.Units {
		switch {
		case seen[u]:
			return fmt.Errorf("unit %s twice", u)
		case u == nodeupdate.ServiceUnit:
			return fmt.Errorf("unit %s: started by its path unit only", u)
		case !files["/etc/systemd/system/"+u]:
			return fmt.Errorf("unit %q: not one of the plan's files", u)
		}
		seen[u] = true
	}
	return nil
}

// tmpfilesConf is the plan's tmpfiles.d file.
const tmpfilesConf = "/etc/tmpfiles.d/raycontrol.conf"

// checkUser checks a system user of a plan: its name, UID and groups.
func checkUser(u SystemUser) error {
	want := map[string]int{"rayd": render.RaydUID, "rayspa": render.RayspaUID, render.GroupName("front"): render.FrontUID}
	uid, fixed := want[u.Name]
	name, isService := strings.CutPrefix(u.Name, "niko-")
	switch {
	case fixed && u.UID != uid:
		return fmt.Errorf("user %s: UID %d, want %d", u.Name, u.UID, uid)
	case fixed:
	case !isService || store.CheckProcessName(name) != nil:
		return fmt.Errorf("user %q: not one of raycontrol's", u.Name)
	case u.UID < store.FirstServiceUID || u.UID > store.LastServiceUID:
		return fmt.Errorf("user %s: UID %d outside %d-%d", u.Name, u.UID, store.FirstServiceUID, store.LastServiceUID)
	}
	return nil
}

// unitUser is the user a unit of raycontrol's runs as, or "" for a unit
// that is not one Check takes (the update's two units are fixed files).
func unitUser(unit string) string {
	switch unit {
	case "rayd.service", RelayProbeUnit:
		return "rayd"
	case "rayspa.service":
		return "rayspa"
	}
	name, ok := strings.CutSuffix(unit, ".service")
	if s, isService := strings.CutPrefix(name, "niko-"); ok && isService && (s == "front" || store.CheckProcessName(s) == nil) {
		return name
	}
	return ""
}

// unitDirs are the runtime and state directories a unit may have.
func unitDirs(unit string) (runtime, state string) {
	switch unit {
	case "rayd.service":
		return "raycontrol", "raycontrol"
	case "rayspa.service":
		return "rayspa", "rayspa"
	case RelayProbeUnit:
		return "rayd-relay", "rayd-relay"
	}
	return strings.TrimPrefix(path.Join(render.DefaultPaths.Run, strings.TrimSuffix(strings.TrimPrefix(unit, "niko-"), ".service")), "/run/"), ""
}

// unitCommand is the kind of command a unit runs (commands).
func unitCommand(unit string) string {
	switch {
	case unit == "niko-front.service":
		return "front"
	case strings.HasPrefix(unit, "niko-"):
		return "service"
	}
	return unit
}

// commands are the binaries and subcommands each kind of unit may start
// (ExecStart's first two words), as Build and RelayPlan write them.
var commands = map[string][]string{
	"rayd.service":   {DefaultBinaries.Rayd + " serve"},
	"rayspa.service": {DefaultBinaries.Rayspa + " run"},
	RelayProbeUnit:   {DefaultBinaries.Rayd + " relay"},
	"front":          {DefaultBinaries.NikoServer + " front"},
	"service": {DefaultBinaries.Xray + " run", DefaultBinaries.Rayd + " site", DefaultBinaries.Rayd + " naive",
		DefaultBinaries.NikoServer + " backend", DefaultBinaries.Slipstream + " --front-socket"},
}

// execWord is a word of a command line: what systemd would neither split
// nor expand (no ;, quotes, $, \, %).
var execWord = regexp.MustCompile(`^[A-Za-z0-9_./:,=+@-]+$`)

// words reports whether each of f is one execWord.
func words(f []string) bool {
	return !slices.ContainsFunc(f, func(w string) bool { return !execWord.MatchString(w) })
}

// hardeningLines are the hardening block's settings, each wanted once in
// every unit, with its value.
var hardeningLines = func() map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(hardening), "\n") {
		k, v, _ := strings.Cut(l, "=")
		m[k] = v
	}
	return m
}()

// under reports whether p is a clean absolute path below dir.
func under(p, dir string) bool {
	return path.IsAbs(p) && path.Clean(p) == p && strings.HasPrefix(p, dir+"/") && token(p)
}

// checkUnit checks a unit file of a plan line by line against the
// templates of Build and RelayPlan: only their settings, with values of
// their forms, the user its name says, the hardening block whole.
func checkUnit(unit, content string, users map[string]bool) error {
	user := unitUser(unit)
	runtimeDir, stateDir := unitDirs(unit)
	isNiko := strings.HasPrefix(unit, "niko-")
	service := strings.TrimSuffix(strings.TrimPrefix(unit, "niko-"), ".service")
	rendered := render.DefaultPaths.Rendered
	oneOf := func(v string, ok ...string) bool { return slices.Contains(ok, v) }
	fieldsOf := func(v string, ok func(string) bool) bool {
		f := strings.Split(v, " ")
		return len(f) > 0 && !slices.ContainsFunc(f, func(s string) bool { return !ok(s) })
	}
	group := func(g string) bool { return strings.HasPrefix(g, "niko-") && users[g] }
	afterUnit := func(u string) bool {
		return oneOf(u, "network-online.target", "rayd.service", "rayspa.service", "nftables.service", "firewalld.service", "ufw.service") ||
			strings.HasPrefix(u, "niko-") && unitUser(u) != ""
	}
	caps := func(v string) bool {
		return v == "" || v == "CAP_NET_BIND_SERVICE" && isNiko || v == "CAP_NET_ADMIN" && unit == "rayspa.service"
	}
	var copies [][2]string // user, destination of each copy
	check := map[string]map[string]func(string) bool{
		"[Unit]": {
			"Description":           func(string) bool { return true },
			"Wants":                 func(v string) bool { return v == "network-online.target" },
			"After":                 func(v string) bool { return fieldsOf(v, afterUnit) },
			"StartLimitIntervalSec": func(v string) bool { return v == "0" },
			"ConditionPathExists":   func(v string) bool { return under(v, rendered) },
			"PartOf":                func(v string) bool { return unit == RelayProbeUnit && v == "rayspa.service" },
			"Requisite":             func(v string) bool { return unit == RelayProbeUnit && v == "rayspa.service" },
		},
		"[Service]": {
			"User":                func(v string) bool { return v == user },
			"Group":               func(v string) bool { return v == user },
			"SupplementaryGroups": func(v string) bool { return fieldsOf(v, group) },
			// The unit's command, by its binary and subcommand; words only
			// (no ;, quotes, $ or \ for systemd to split or expand).
			"ExecStart": func(v string) bool {
				f := strings.Split(v, " ")
				return len(f) >= 2 && slices.Contains(commands[unitCommand(unit)], f[0]+" "+f[1]) && words(f)
			},
			// Only rayd's credential copy: from the unit's own rendered
			// directory (rayd's files), or the relay's bundle (root's) for
			// the relay's two units.
			"ExecStartPre": func(v string) bool {
				f := strings.Split(v, " ")
				if len(f) != 7 || f[0] != "+"+DefaultBinaries.Rayd || f[1] != CredentialCommand || !words(f) {
					return false
				}
				anchor, rel, owner, dst := f[2], f[3], f[4], f[6]
				src := path.Join(anchor, rel)
				// Clean paths only: a destination ending in /.. or /. is
				// refused here, not at the start (rayd credential would).
				if path.IsAbs(rel) || path.Clean(rel) != rel || strings.HasPrefix(rel, "../") || path.Clean(anchor) != anchor || path.Clean(dst) != dst {
					return false
				}
				switch anchor {
				case renderedAnchor(render.DefaultPaths):
					if !isNiko || owner != renderedOwner || path.Dir(src) != path.Join(rendered, service) {
						return false
					}
				case path.Dir(RelayBundle):
					if unit != "rayspa.service" && unit != RelayProbeUnit || owner != bundleOwner || src != RelayBundle {
						return false
					}
				default:
					return false
				}
				copies = append(copies, [2]string{f[5], dst})
				return true
			},
			"RuntimeDirectory":      func(v string) bool { return v == runtimeDir },
			"RuntimeDirectoryMode":  func(v string) bool { return oneOf(v, "0700", "0710", "0755") },
			"StateDirectory":        func(v string) bool { return stateDir != "" && v == stateDir },
			"StateDirectoryMode":    func(v string) bool { return oneOf(v, "0700", "0711") },
			"ReadWritePaths":        func(v string) bool { return under(v, render.DefaultPaths.Run) },
			"InaccessiblePaths":     func(v string) bool { return strings.HasPrefix(v, "-") && under(v[1:], rendered) },
			"UMask":                 func(v string) bool { return oneOf(v, "0007", "0027") },
			"AmbientCapabilities":   caps,
			"CapabilityBoundingSet": caps,
			"RestrictAddressFamilies": func(v string) bool {
				return fieldsOf(v, func(f string) bool { return oneOf(f, "AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK") })
			},
			"IPAddressDeny":  func(v string) bool { return v == strings.TrimPrefix(denyLocal, "IPAddressDeny=") },
			"IPAddressAllow": func(v string) bool { return oneOf(v, "127.0.0.1", strings.TrimPrefix(stubAllow, "IPAddressAllow=")) },
			"PrivateNetwork": func(v string) bool { return v == "yes" },
		},
		"[Install]": {
			"WantedBy": func(v string) bool {
				return v == "multi-user.target" || unit == RelayProbeUnit && v == "rayspa.service"
			},
		},
	}
	for k, v := range hardeningLines {
		check["[Service]"][k] = func(got string) bool { return got == v }
	}
	once := map[string]int{}
	section := ""
	for i, l := range strings.Split(content, "\n") {
		switch {
		case strings.ContainsFunc(l, unicode.IsControl) || strings.ContainsAny(l, `%\`):
			return fmt.Errorf("line %d: a control character, a specifier or a continuation", i+1)
		case l == "" || strings.HasPrefix(l, "# Generated by raycontrol"):
			continue
		case check[l] != nil:
			section = l
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		ok := check[section][k]
		if ok == nil || !ok(v) {
			return fmt.Errorf("line %d: %q is not in the unit's template", i+1, l)
		}
		once[k]++
	}
	for _, k := range slices.Concat([]string{"User", "Group", "ExecStart"}, slices.Collect(maps.Keys(hardeningLines))) {
		if once[k] != 1 {
			return fmt.Errorf("%s %d times, want once", k, once[k])
		}
	}
	for _, k := range []string{"RuntimeDirectory", "StateDirectory", "SupplementaryGroups"} {
		if once[k] > 1 {
			return fmt.Errorf("%s %d times", k, once[k])
		}
	}
	if !users[user] {
		return fmt.Errorf("its user %s is not the plan's", user)
	}
	// A copy is for the unit's own user, into its own runtime directory.
	for _, c := range copies {
		if c[0] != user || once["RuntimeDirectory"] != 1 || path.Dir(c[1]) != path.Join("/run", runtimeDir) || !token(path.Base(c[1])) {
			return fmt.Errorf("a credential for %s at %s: not the unit's user and runtime directory", c[0], c[1])
		}
	}
	return nil
}

// checkTmpfiles checks the tmpfiles.d file of a plan: only directories
// (d) of the data plane's runtime directory and one level below it, with
// the modes and owners Build gives them. A d line also sets the mode and
// owner of a directory that is there: whose a directory becomes is
// checked against its name.
func checkTmpfiles(content string, users map[string]bool) error {
	run := render.DefaultPaths.Run
	front := render.GroupName("front")
	for i, l := range strings.Split(content, "\n") {
		if l == "" || i == 0 && l == "# Generated by raycontrol." {
			continue
		}
		f := strings.Split(l, " ")
		ok := len(f) == 6 && f[0] == "d" && f[5] == "-" && !strings.ContainsAny(l, `%\`) && !strings.ContainsFunc(l, unicode.IsControl)
		if ok && f[1] == run {
			ok = f[2] == "0755" && f[3] == "root" && f[4] == "root"
		} else if ok {
			ok = under(f[1], run) && path.Dir(f[1]) == run && f[2] == "2750"
			base := path.Base(f[1])
			api, isAPI := strings.CutSuffix(base, "-api")
			in, isIn := strings.CutSuffix(base, "-in")
			switch {
			case isAPI: // Xray's API socket: the service's, rayd's group
				ok = ok && f[3] == render.GroupName(api) && users[f[3]] && f[4] == "rayd"
			case isIn: // what the front passes: the service's, the front's group
				ok = ok && f[3] == render.GroupName(in) && users[f[3]] && f[4] == front
			default: // DoH's socket: rayd's, the front's group; no unit's runtime directory
				ok = ok && store.CheckProcessName(base) == nil && !users[render.GroupName(base)] && f[3] == "rayd" && f[4] == front
			}
		}
		if !ok {
			return fmt.Errorf("line %d: %q: only directories of %s", i+1, l, run)
		}
	}
	return nil
}
