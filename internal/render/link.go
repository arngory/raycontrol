package render

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// HostLink is the speed, Mbit/s, of the interface the default route goes
// out of (IPv4's, else IPv6's), as the kernel knows it, and the
// interface's name. 0 when it does not know (most virtual NICs report no
// speed) or there is no default route; the name may be there all the same.
func HostLink() (mbps int, iface string) {
	iface = defaultIface("/proc/net/route", "/proc/net/ipv6_route")
	if iface == "" {
		return 0, ""
	}
	return linkSpeed("/sys/class/net", iface), iface
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

// ifaceName is a name the kernel could give an interface: no path in it.
func ifaceName(s string) bool {
	return s != "" && s != "." && s != ".." && len(s) < 16 && !strings.ContainsAny(s, "/\x00")
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
// ("link"), else none (0, ""). The server sends each client at the rate
// the client asks for, so without a ceiling one client may fill the
// channel and starve the others.
func BrutalCeiling(settings string, linkMbps int) (mbps int, from string) {
	var s struct {
		Up *int `json:"up_mbps"`
	}
	_ = json.Unmarshal([]byte(settings), &s)
	switch {
	case s.Up != nil:
		return max(*s.Up, 0), "up_mbps"
	case linkMbps > 0:
		return linkMbps, "link"
	}
	return 0, ""
}
