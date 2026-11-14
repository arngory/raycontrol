package provision

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// settingPorts keeps the ports chosen at install (PortChoice.String).
const settingPorts = "ports_chosen"

// Span is a range of ports, [Base, Base+Range); Range 0 is none.
type Span struct{ Base, Range uint16 }

func (s Span) last() int { return int(s.Base) + int(s.Range) - 1 }

func (s Span) overlaps(o Span) bool {
	return s.Range > 0 && o.Range > 0 && int(s.Base) <= o.last() && int(o.Base) <= s.last()
}

func (s Span) String() string {
	if s.Range == 1 {
		return strconv.Itoa(int(s.Base))
	}
	return strconv.Itoa(int(s.Base)) + "-" + strconv.Itoa(s.last())
}

// PortChoice are the ports an operator chose at install (rayctl install
// -ports, docs/18-platforms-and-hosts.md §6), for a provider's firewall or
// a NAT that forwards only some ports. What is not chosen is random as
// before. They are chosen once: a client learns every one of them from
// its device bundle, and a port that moved would strand it.
type PortChoice struct {
	SPA      Span   // the knock: UDP and the TCP carrier
	Sub      uint16 // the subscription: TCP and the UDP echo of probes
	API      uint16 // the remote API, TCP: taken when the api service is made
	Rotation Span   // where the UDP rotation ranges of services are carved
	NoRotate bool   // rotation=off: services made later get none
}

// Zero reports whether nothing was chosen.
func (c PortChoice) Zero() bool { return c == PortChoice{} }

// String is the choice as -ports takes it, in a fixed order.
func (c PortChoice) String() string {
	var out []string
	if c.SPA.Range > 0 {
		out = append(out, "spa="+c.SPA.String())
	}
	if c.Sub != 0 {
		out = append(out, "sub="+strconv.Itoa(int(c.Sub)))
	}
	if c.API != 0 {
		out = append(out, "api="+strconv.Itoa(int(c.API)))
	}
	switch {
	case c.NoRotate:
		out = append(out, "rotation=off")
	case c.Rotation.Range > 0:
		out = append(out, "rotation="+c.Rotation.String())
	}
	return strings.Join(out, ",")
}

// spans are the chosen ports as ranges, by name.
func (c PortChoice) spans() map[string]Span {
	m := map[string]Span{}
	if c.SPA.Range > 0 {
		m["spa"] = c.SPA
	}
	if c.Sub != 0 {
		m["sub"] = Span{c.Sub, 1}
	}
	if c.API != 0 {
		m["api"] = Span{c.API, 1}
	}
	if c.Rotation.Range > 0 {
		m["rotation"] = c.Rotation
	}
	return m
}

// MinChosenPort: a chosen port is not a privileged one, which are the
// fixed ports' (443, 53, 80) and those of other software.
const MinChosenPort = 1024

// ParsePorts reads -ports: name=port or name=first-last, comma-separated;
// names spa (a range, or one port), sub, api, and rotation (a range, or
// off). taken are the host's ports the choice must keep clear of (sshd's).
func ParsePorts(s string, taken ...uint16) (PortChoice, error) {
	var c PortChoice
	seen := map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		name, v, ok := strings.Cut(item, "=")
		if !ok || seen[name] {
			return c, fmt.Errorf("-ports %q: name=port once each, comma-separated (spa=40000-40099,sub=40100,api=40101,rotation=41000-41999|off)", item)
		}
		seen[name] = true
		switch name {
		case "spa", "rotation":
			if name == "rotation" && v == "off" {
				c.NoRotate = true
				continue
			}
			sp, err := parseSpan(v)
			if err != nil {
				return c, fmt.Errorf("-ports %s: %w", name, err)
			}
			if name == "spa" {
				c.SPA = sp
			} else {
				c.Rotation = sp
			}
		case "sub", "api":
			sp, err := parseSpan(v)
			if err == nil && sp.Range != 1 {
				err = fmt.Errorf("%q: one port", v)
			}
			if err != nil {
				return c, fmt.Errorf("-ports %s: %w", name, err)
			}
			if name == "sub" {
				c.Sub = sp.Base
			} else {
				c.API = sp.Base
			}
		default:
			return c, fmt.Errorf("-ports: %q is not one of spa, sub, api, rotation (443 and 53 are fixed)", name)
		}
	}
	spans := c.spans()
	names := []string{"spa", "sub", "api", "rotation"}
	for i, a := range names {
		for _, b := range names[i+1:] {
			if spans[a].overlaps(spans[b]) {
				return c, fmt.Errorf("-ports: %s %s and %s %s overlap", a, spans[a], b, spans[b])
			}
		}
		for _, p := range taken {
			if spans[a].overlaps(Span{p, 1}) {
				return c, fmt.Errorf("-ports: %s %s holds port %d, which SSH listens on", a, spans[a], p)
			}
		}
	}
	return c, nil
}

// SSHDPorts reads the ports in sshd -T's output: those of its listen
// addresses, which say them all, or else its port lines.
func SSHDPorts(out string) ([]uint16, error) {
	var ports, listen []uint16
	for _, line := range strings.Split(out, "\n") {
		key, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		into := &ports
		switch key {
		case "port":
		case "listenaddress":
			into = &listen
			// "[::]:22", "0.0.0.0:22 rdomain red"
			if f := strings.Fields(v); len(f) > 0 {
				v = f[0]
			}
			if i := strings.LastIndex(v, ":"); i >= 0 {
				v = v[i+1:]
			}
		default:
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("sshd -T: %s %q", key, v)
		}
		if !slices.Contains(*into, uint16(n)) {
			*into = append(*into, uint16(n))
		}
	}
	if len(listen) > 0 {
		return listen, nil
	}
	return ports, nil
}

// ParseSSHPorts reads rayd init's -ssh-ports: the ports sshd listens on,
// N[,N...], or none (no sshd, or an operator who checked).
func ParseSSHPorts(s string) ([]uint16, error) {
	if s == "none" {
		return nil, nil
	}
	var out []uint16
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("-ssh-ports %q: N[,N...] or none", s)
		}
		if !slices.Contains(out, uint16(n)) {
			out = append(out, uint16(n))
		}
	}
	return out, nil
}

// SSHPortsArg is ports as -ssh-ports takes them.
func SSHPortsArg(ports []uint16) string {
	if len(ports) == 0 {
		return "none"
	}
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(int(p))
	}
	return strings.Join(s, ",")
}

func parseSpan(v string) (Span, error) {
	from, to, isRange := strings.Cut(v, "-")
	if !isRange {
		to = from
	}
	a, err1 := strconv.Atoi(from)
	b, err2 := strconv.Atoi(to)
	switch {
	case err1 != nil || err2 != nil || a > b || b > 65535:
		return Span{}, fmt.Errorf("%q: a port or first-last, up to 65535", v)
	case a < MinChosenPort:
		return Span{}, fmt.Errorf("%q: below %d, a privileged port (443 and 53 are the node's fixed ones)", v, MinChosenPort)
	}
	return Span{uint16(a), uint16(b - a + 1)}, nil
}

// Ports are the chosen ports a node keeps (settingPorts): none when it was
// installed without -ports.
func Ports(ctx context.Context, st *store.Store) (PortChoice, error) {
	b, err := st.GetSetting(ctx, settingPorts)
	if errors.Is(err, store.ErrNotFound) {
		return PortChoice{}, nil
	}
	if err != nil {
		return PortChoice{}, err
	}
	return ParsePorts(string(b))
}

// CheckPorts refuses a choice for a node that exists already unless it is
// what the node has: ports are chosen at its first install only (an
// install again names them again, or not at all). Nothing is written: it
// runs on a store opened read-only (store.OpenReadOnly), beside a rayd
// that runs.
func CheckPorts(ctx context.Context, st *store.Store, c PortChoice) error {
	if c.Zero() {
		return nil
	}
	params, err := node.LoadParams(ctx, st)
	if errors.Is(err, store.ErrNotFound) {
		return nil // a new node
	}
	if err != nil {
		return err
	}
	has, err := Ports(ctx, st)
	if err != nil {
		return err
	}
	has.SPA = Span{params.PortBase, params.PortRange}
	if svc, err := st.ServiceByName(ctx, SubscriptionService); err == nil {
		if ps, _ := svc.Ports(); len(ps) > 0 {
			has.Sub = ps[0].Num
		}
	}
	all, err := st.ListServices(ctx)
	if err != nil {
		return err
	}
	for _, s := range all {
		if ps, _ := s.Ports(); s.Kind == "api" && len(ps) > 0 {
			has.API = ps[0].Num
		}
	}
	differs := c.SPA.Range > 0 && c.SPA != has.SPA || c.Sub != 0 && c.Sub != has.Sub || c.API != 0 && c.API != has.API ||
		c.Rotation.Range > 0 && c.Rotation != has.Rotation || c.NoRotate && !has.NoRotate
	if differs {
		return fmt.Errorf("%w -ports %s: ports are chosen at a node's first install only, and clients know this node's (%s): "+
			"install again without -ports, or with these", store.ErrInvalid, c, has)
	}
	return nil
}

// keepChoice stores c as the node's chosen ports when the node is new
// (fresh: its SPA parameters were made just now) and c names any. An
// install again of a node made without -ports that names its random
// ports (CheckPorts lets that through) stores nothing: they stay random,
// as rayctl ports says, and nothing on the node changes.
func keepChoice(ctx context.Context, st *store.Store, c PortChoice, fresh bool) error {
	if !fresh || c.Zero() {
		return nil
	}
	if _, err := st.GetSetting(ctx, settingPorts); !errors.Is(err, store.ErrNotFound) {
		return err // there already (nil), or not readable
	}
	return st.SetSetting(ctx, settingPorts, []byte(c.String()))
}

// initPorts makes the SPA parameters of a new node with c's range, or a
// random one clear of c's other ports.
func initPorts(c PortChoice) (spa.Params, error) {
	for range 100 {
		p, err := spa.RandomParams(nil)
		if err != nil {
			return p, err
		}
		if c.SPA.Range > 0 {
			p.PortBase, p.PortRange = c.SPA.Base, c.SPA.Range
			return p, p.Validate()
		}
		sp := Span{p.PortBase, p.PortRange}
		if !slices.ContainsFunc([]Span{{c.Sub, 1}, {c.API, 1}, c.Rotation}, sp.overlaps) {
			return p, nil
		}
	}
	return spa.Params{}, errors.New("no SPA range clear of the chosen ports")
}

// reserved are the chosen ports that random picks keep clear of: the API's
// before its service exists, and the rotation pool.
func reserved(ctx context.Context, st *store.Store) []Span {
	c, err := Ports(ctx, st)
	if err != nil {
		return nil
	}
	var out []Span
	if c.API != 0 {
		out = append(out, Span{c.API, 1})
	}
	if c.Rotation.Range > 0 {
		out = append(out, c.Rotation)
	}
	return out
}

// inReserved reports whether port p is one of reserved's.
func inReserved(rs []Span, p int) bool {
	return slices.ContainsFunc(rs, func(s Span) bool { return p >= int(s.Base) && p <= s.last() })
}

// rotationSlots are the ranges a chosen rotation pool is carved into: a
// quarter of it each (one port at least), so that it holds four services
// at least, the kinds that rotate.
func rotationSlots(pool Span) []Span {
	w := max(pool.Range/4, 1)
	var out []Span
	for b := int(pool.Base); b+int(w)-1 <= pool.last(); b += int(w) {
		out = append(out, Span{uint16(b), w})
	}
	return out
}
