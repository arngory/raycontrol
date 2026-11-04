package hostcheck

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// listener is a socket bound to a local port, and its process.
type listener struct {
	proto string // tcp, udp
	addr  netip.AddrPort
	inode string
	comm  string // process name, "" if unknown
	exe   string // the process's binary, " (deleted)" cut off
	pid   int
}

// listeners reads the bound sockets of /proc/net: TCP in LISTEN, every
// UDP socket; then which process holds each (root sees them all).
func (h *Host) listeners() []listener {
	var out []listener
	for _, f := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		out = append(out, parseProcNet(h.read("/proc/net/"+f.file), f.proto)...)
	}
	if len(out) == 0 {
		return nil
	}
	owner := map[string]listener{}
	procs, _ := os.ReadDir(h.path("/proc"))
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fds, _ := os.ReadDir(h.path(filepath.Join("/proc", p.Name(), "fd")))
		for _, fd := range fds {
			link, err := os.Readlink(h.path(filepath.Join("/proc", p.Name(), "fd", fd.Name())))
			if inode, ok := strings.CutPrefix(link, "socket:["); err == nil && ok {
				inode = strings.TrimSuffix(inode, "]")
				if _, seen := owner[inode]; !seen {
					exe, _ := os.Readlink(h.path(filepath.Join("/proc", p.Name(), "exe")))
					owner[inode] = listener{pid: pid, comm: strings.TrimSpace(h.read(filepath.Join("/proc", p.Name(), "comm"))),
						exe: strings.TrimSuffix(exe, " (deleted)")}
				}
			}
		}
	}
	for i, l := range out {
		if o, ok := owner[l.inode]; ok {
			out[i].pid, out[i].comm, out[i].exe = o.pid, o.comm, o.exe
		}
	}
	return out
}

// parseProcNet reads one /proc/net/{tcp,udp}[6] table.
func parseProcNet(table, proto string) []listener {
	var out []listener
	for i, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 {
			continue
		}
		// TCP: LISTEN only (0A). UDP: every socket, bound is enough.
		if proto == "tcp" && f[3] != "0A" {
			continue
		}
		addr, ok := parseHexAddr(f[1])
		if !ok {
			continue
		}
		out = append(out, listener{proto: proto, addr: addr, inode: f[9]})
	}
	return out
}

// parseHexAddr reads "0100007F:01BB": the address in the kernel's byte
// order (32-bit words, host order, little-endian here), the port big-endian.
func parseHexAddr(s string) (netip.AddrPort, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, false
	}
	for w := 0; w < len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), true
}

// others are the listeners on proto/port that are not ok.
func others(ls []listener, proto string, port uint16, ok func(listener) bool) []listener {
	var out []listener
	for _, l := range ls {
		if l.proto == proto && l.addr.Port() == port && !ok(l) {
			out = append(out, l)
		}
	}
	return out
}

func describe(ls []listener) string {
	if len(ls) == 0 {
		return "free"
	}
	var parts []string
	seen := map[string]bool{}
	for _, l := range ls {
		who := "an unknown process"
		if l.comm != "" {
			who = fmt.Sprintf("%s (pid %d)", l.comm, l.pid)
		}
		s := l.proto + " " + l.addr.String() + " is taken by " + who
		if !seen[s] {
			seen[s] = true
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "; ")
}

func numCPU() int { return runtime.NumCPU() }
