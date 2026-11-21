package render

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// LinkTrusted is the lowest link speed, Mbit/s, taken as Brutal's
// ceiling: below it the kernel's word is doubtful (an emulated rtl8139
// tells 100 whatever the channel), and the status asks for up_mbps.
const LinkTrusted = 1000

// hostLink is the first speed HostLink read that was known: kept until
// rayd restarts, as a change of it restarts Hysteria2 and cuts its
// sessions (a bond losing a port, a bridge's speed following its ports).
var hostLink struct {
	sync.Mutex
	mbps  int
	iface string
}

// HostLink is the speed, Mbit/s, of the interface the default route goes
// out of (IPv4's, else IPv6's), as the kernel knows it, and the
// interface's name. 0 when it does not know (most virtual NICs report no
// speed) or there is no default route; the name may be there all the same.
// Once known it stays as first read (hostLink).
func HostLink() (mbps int, iface string) {
	hostLink.Lock()
	defer hostLink.Unlock()
	if hostLink.mbps > 0 {
		return hostLink.mbps, hostLink.iface
	}
	iface = defaultIface("/proc/net/route", "/proc/net/ipv6_route")
	if iface == "" {
		return 0, ""
	}
	mbps = linkSpeed("/sys/class/net", iface)
	if mbps > 0 {
		hostLink.mbps, hostLink.iface = mbps, iface
	}
	return mbps, iface
}

// defaultIface is the interface of the default route of the lowest metric
// in route (/proc/net/route), else in route6 (/proc/net/ipv6_route); ""
// without one.
func defaultIface(route, route6 string) string {
	if f, err := os.Open(route); err == nil { //nolint:gosec // G304: /proc/net/route, the tests' copy
		iface := defaultIface4(f)
		_ = f.Close()
		if iface != "" {
			return iface
		}
	}
	if f, err := os.Open(route6); err == nil { //nolint:gosec // G304: /proc/net/ipv6_route, the tests' copy
		defer func() { _ = f.Close() }()
		return defaultIface6(f)
	}
	return ""
}

// Route flags (linux/route.h).
const (
	rtfUp     = 0x1
	rtfReject = 0x200
)

// defaultIface4 reads /proc/net/route: Iface, Destination, Gateway, Flags,
// RefCnt, Use, Metric, Mask, ... in hex, a header first.
func defaultIface4(r io.Reader) string {
	best, metric := "", uint64(0)
	s := bufio.NewScanner(r)
	for first := true; s.Scan(); first = false {
		f := strings.Fields(s.Text())
		if first || len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err1 := strconv.ParseUint(f[3], 16, 32)
		m, err2 := strconv.ParseUint(f[6], 10, 32)
		if err1 != nil || err2 != nil || flags&rtfUp == 0 || flags&rtfReject != 0 || !ifaceName(f[0]) {
			continue
		}
		if best == "" || m < metric {
			best, metric = f[0], m
		}
	}
	return best
}

// defaultIface6 reads /proc/net/ipv6_route: destination, its prefix
// length, source, its length, next hop, metric, refcount, use, flags (hex)
// and the interface. The kernel keeps an unreachable default on lo:
// rejected, it is none.
func defaultIface6(r io.Reader) string {
	best, metric := "", uint64(0)
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" {
			continue
		}
		m, err1 := strconv.ParseUint(f[5], 16, 32)
		flags, err2 := strconv.ParseUint(f[8], 16, 32)
		if err1 != nil || err2 != nil || flags&rtfUp == 0 || flags&rtfReject != 0 || f[9] == "lo" || !ifaceName(f[9]) {
			continue
		}
		if best == "" || m < metric {
			best, metric = f[9], m
		}
	}
	return best
}

// ifaceName is a name the kernel could give an interface: no path in it,
// and not the "*" of a route with none (blackhole).
func ifaceName(s string) bool {
	return s != "" && s != "." && s != ".." && s != "*" && len(s) < 16 && !strings.ContainsAny(s, "/\x00")
}

// linkSpeed is /sys/class/net/<iface>/speed, Mbit/s; 0 when unknown (-1,
// or an error such as EINVAL of a link that is down or virtual).
func linkSpeed(sys, iface string) int {
	b, err := os.ReadFile(filepath.Join(sys, iface, "speed")) //nolint:gosec // G304: sysfs; iface has no path in it (ifaceName)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// BrutalCeiling is the ceiling of a Hysteria2 service's Brutal (R4-16,
// protocol review 2026-11, M1), Mbit/s, and where it comes from: up_mbps
// set ("up_mbps", 0 when set to none), else the speed of the node's link
// from LinkTrusted on ("link"), else none (0, ""). The server sends each
// client at the rate the client asks for, so without a ceiling one client
// may ask for more than the port. An up_mbps that is no whole number
// (written by hand: service add -settings) counts as not set.
func BrutalCeiling(settings string, linkMbps int) (mbps int, from string) {
	var s struct {
		Up json.RawMessage `json:"up_mbps"`
	}
	_ = json.Unmarshal([]byte(settings), &s)
	if n, err := strconv.Atoi(string(s.Up)); err == nil && n >= 0 {
		return n, "up_mbps"
	}
	if linkMbps >= LinkTrusted {
		return linkMbps, "link"
	}
	return 0, ""
}
