package deploy

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Reserved ports: the ports a host listens on, kept out of those the
// kernel picks for outgoing connections and unbound sockets. SPA's slot
// ports and the services' own (the subscription, the remote API, ACME) are
// drawn from 20000-60999, which overlaps the ephemeral range (32768-60999
// by default): an outgoing connection that took one (rayd's, or Xray's and
// niko-server's for the users) held it, and a listen on it failed
// (EADDRINUSE) until that connection closed. The key is per network
// namespace and holds for IPv6, TCP and UDP alike.
const (
	ReservedPortsKey = "net.ipv4.ip_local_reserved_ports"
	// PortsSysctl holds the value apply sets: the host's ports and what
	// else was reserved then.
	PortsSysctl = "/etc/sysctl.d/90-raycontrol-ports.conf"
	// minReserved: the kernel picks no port below it for an outgoing
	// connection; the services' well-known ports are not reserved.
	minReserved = 1024
	// maxReserved bounds the ports reserved for one host: SPA's slots
	// (4096 at most) and the services' ports. More is not what raycontrol
	// listens on (a rayd that says so would take the ephemeral range from
	// every outgoing connection of the host, root's too): nothing is
	// reserved then, and apply says so.
	maxReserved = 4096 + 1024
	// ownMark starts the line of PortsSysctl that says which of its ports
	// are raycontrol's: the rest was reserved by others.
	ownMark = "# reserved by raycontrol: "
)

// span is the ports lo to hi, both included.
type span struct{ lo, hi int }

// spans are ports as the kernel prints them: sorted, none overlapping or
// touching another.
type spans []span

// merged sorts s and joins what overlaps or touches.
func merged(s spans) spans {
	s = slices.Clone(s)
	slices.SortFunc(s, func(a, b span) int { return a.lo - b.lo })
	var out spans
	for _, r := range s {
		if n := len(out); n > 0 && r.lo <= out[n-1].hi+1 {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return out
}

// listenSpans are the ports of ranges a host listens on that are
// reserved: from minReserved, whatever the protocol.
func listenSpans(ranges []PortRange) spans {
	var s spans
	for _, r := range ranges {
		if int(r.To) < minReserved || r.From > r.To {
			continue
		}
		s = append(s, span{max(int(r.From), minReserved), int(r.To)})
	}
	return merged(s)
}

// parseSpans reads a value of ReservedPortsKey: "a-b,c", the kernel's
// form; empty is none.
func parseSpans(v string) (spans, error) {
	v = strings.Join(strings.Fields(v), "")
	if v == "" {
		return nil, nil
	}
	var s spans
	for _, part := range strings.Split(v, ",") {
		a, b, isRange := strings.Cut(part, "-")
		lo, err1 := strconv.Atoi(a)
		hi, err2 := lo, error(nil)
		if isRange {
			hi, err2 = strconv.Atoi(b)
		}
		if err1 != nil || err2 != nil || lo < 0 || hi > 65535 || lo > hi {
			return nil, fmt.Errorf("%s %q: not ports", ReservedPortsKey, v)
		}
		s = append(s, span{lo, hi})
	}
	return merged(s), nil
}

// String is the kernel's form: "a-b,c".
func (s spans) String() string {
	parts := make([]string, len(s))
	for i, r := range s {
		parts[i] = strconv.Itoa(r.lo)
		if r.hi != r.lo {
			parts[i] += "-" + strconv.Itoa(r.hi)
		}
	}
	return strings.Join(parts, ",")
}

// count is how many ports s holds.
func (s spans) count() int {
	n := 0
	for _, r := range s {
		n += r.hi - r.lo + 1
	}
	return n
}

// minus is s without the ports of t.
func (s spans) minus(t spans) spans {
	var out spans
	for _, r := range s {
		parts := spans{r}
		for _, c := range t {
			var next spans
			for _, p := range parts {
				if c.hi < p.lo || c.lo > p.hi {
					next = append(next, p)
					continue
				}
				if p.lo < c.lo {
					next = append(next, span{p.lo, c.lo - 1})
				}
				if c.hi < p.hi {
					next = append(next, span{c.hi + 1, p.hi})
				}
			}
			parts = next
		}
		out = append(out, parts...)
	}
	return merged(out)
}

// ReservedValue is the value of ReservedPortsKey that reserves ports, the
// ranges a host listens on, and keeps what else live reserves: live
// without own (the ports raycontrol reserved before, as PortsSysctl
// says), with ports. An administrator's own reservations stay; ports
// raycontrol no longer listens on go. own is the new value's part that
// is raycontrol's.
func ReservedValue(live, before string, ports []PortRange) (value, own string, err error) {
	l, err := parseSpans(live)
	if err != nil {
		return "", "", err
	}
	b, err := parseSpans(before)
	if err != nil {
		b = nil // not ours to take away then
	}
	o := listenSpans(ports)
	return merged(append(l.minus(b), o...)).String(), o.String(), nil
}

// MissingReserved is what of ports a live value of ReservedPortsKey does
// not reserve ("" when all is), in the kernel's form.
func MissingReserved(live string, ports []PortRange) (string, error) {
	l, err := parseSpans(live)
	if err != nil {
		return "", err
	}
	return listenSpans(ports).minus(l).String(), nil
}

// portsFile is PortsSysctl with value, own its part that is raycontrol's.
func portsFile(value, own string) File {
	return File{Path: PortsSysctl, Mode: 0o644, Content: fmt.Appendf(nil,
		"# Generated by raycontrol: the ports this host listens on (SPA's slots, the services'),\n"+
			"# kept out of those the kernel picks for outgoing connections, with what else was\n"+
			"# reserved when rayctl apply last ran. Files that sort later win at boot; rayctl\n"+
			"# check warns then.\n%s%s\n%s = %s\n", ownMark, own, ReservedPortsKey, value)}
}

// ownReserved is the ports PortsSysctl says are raycontrol's, "" without
// the file.
func (h *Host) ownReserved() string {
	b, err := os.ReadFile(h.path(PortsSysctl))
	if err != nil {
		return ""
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		if v, ok := strings.CutPrefix(string(line), ownMark); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ReservePorts reserves the ports the host listens on (ports: the plan's
// host ports, or a relay's SPA slots and probe endpoint), from
// minReserved, in PortsSysctl and now. What else is reserved stays; what
// raycontrol reserved before and no longer listens on goes. The value
// before raycontrol is journaled, empty too, for uninstall. Apply does it
// before units start: a service or rayspa then finds its ports free. It
// warns, and goes on, where the value cannot be read or set (a container
// that does not let it change).
func (h *Host) ReservePorts(ports []PortRange) {
	want := listenSpans(ports)
	if len(want) == 0 {
		return
	}
	if n := want.count(); n > maxReserved {
		fmt.Fprintf(h.Out, "warning: the host's ports cover %d ports, more than raycontrol reserves (%d): none reserved (%s)\n", n, maxReserved, ReservedPortsKey)
		return
	}
	out, err := h.Run("sysctl", "-n", ReservedPortsKey)
	if err != nil {
		fmt.Fprintf(h.Out, "warning: %s cannot be read (%v): the ports this host listens on are not reserved, and an outgoing connection may hold one\n", ReservedPortsKey, err)
		return
	}
	live := strings.TrimSpace(string(out))
	value, own, err := ReservedValue(live, h.ownReserved(), ports)
	if err != nil {
		fmt.Fprintf(h.Out, "warning: %v; nothing reserved\n", err)
		return
	}
	// Empty too: uninstall puts an empty value back (recordSysctl keeps
	// none).
	if err := h.Journal.Record(Change{Kind: ChangeSysctl, Name: ReservedPortsKey, Value: live}); err != nil {
		fmt.Fprintf(h.Out, "warning: %s: %v; nothing reserved\n", ReservedPortsKey, err)
		return
	}
	f := portsFile(value, own)
	changed, err := h.WriteFile(f)
	if err != nil {
		fmt.Fprintf(h.Out, "warning: %s cannot be written: %v\n", f.Path, err)
		return
	}
	if changed {
		fmt.Fprintln(h.Out, "wrote", f.Path)
		h.relabel(f.Path)
	}
	if !changed && live == value {
		return
	}
	h.ApplySysctl([]File{f})
}

// RelayPorts are the ports a relay host listens on: its probe endpoint
// (TCP and UDP), if it has one, and its SPA slots (the exit's snapshot
// gives their base and range) for rayspa's TCP carrier.
func RelayPorts(spaBase, spaRange uint32, probe uint16) []PortRange {
	var out []PortRange
	if probe != 0 {
		out = append(out, PortRange{Proto: "tcp", From: probe, To: probe}, PortRange{Proto: "udp", From: probe, To: probe})
	}
	if last := uint64(spaBase) + uint64(spaRange) - 1; spaBase != 0 && spaRange != 0 && last <= 65535 {
		for _, proto := range []string{"tcp", "udp"} {
			out = append(out, PortRange{Proto: proto, From: uint16(spaBase), To: uint16(last)})
		}
	}
	return out
}
