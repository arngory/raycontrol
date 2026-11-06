package dnscheck

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Resolver is a recursive resolver the zones are checked through.
type Resolver struct {
	Name string // google, nsdi, …; udp:IP or tcp:IP as given
	Net  string // udp | tcp
	Addr netip.AddrPort
	// WarnOnly: its failures are warnings, never a failed zone. The
	// Russian resolvers may answer the node abroad otherwise than their
	// clients; the system one is the hoster's, not the clients'.
	WarnOnly bool
}

// Public reports whether a resolver may be asked for by a remote caller:
// one of the named ones, or a public address on port 53 (PublicAddr). A
// remote administrator gets no way to make the node dial its loopback,
// private or other non-public addresses, or other ports (reviews 7, 8).
func (r Resolver) Public() bool {
	if !strings.Contains(r.Name, ":") {
		return true // a named one (or the system's, read by the node)
	}
	return r.Addr.Port() == 53 && PublicAddr(r.Addr.Addr())
}

// nonPublic are ranges of global unicast no public DNS server is in (RFC
// 6890 and the special-purpose registries): shared address space (CGNAT,
// where providers keep internal resolvers), IETF protocol assignments,
// documentation, benchmarking, reserved; NAT64, 6to4 and Teredo, which
// embed IPv4 addresses (private ones too); discard-only; site-local.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// PublicAddr reports whether a public DNS server may have address a:
// global unicast, neither private, loopback nor link-local, and in none of
// the nonPublic ranges.
func PublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	return !slices.ContainsFunc(nonPublic, func(p netip.Prefix) bool { return p.Contains(a) })
}

// String is the resolver as the check shows it: "google 8.8.8.8".
func (r Resolver) String() string {
	if strings.HasPrefix(r.Name, "udp:") || strings.HasPrefix(r.Name, "tcp:") {
		return r.Name
	}
	return r.Name + " " + r.Addr.Addr().String()
}

// knownResolvers by name (docs/13-dns-resolvers.md).
var knownResolvers = []struct {
	name     string
	addrs    []string
	warnOnly bool
}{
	{"google", []string{"8.8.8.8"}, false},
	{"cloudflare", []string{"1.1.1.1"}, false},
	{"quad9", []string{"9.9.9.9"}, false},
	{"nsdi", []string{"195.208.5.1", "195.208.4.1"}, true},
	{"msk-ix", []string{"62.76.76.62"}, true},
	{"yandex", []string{"77.88.8.8"}, true},
}

// DefaultResolvers are those the node asks by itself. The Russian ones it
// asks only on demand (rayctl dns check -resolver nsdi,yandex): queries
// from the node to them at every round would be one more signal.
var DefaultResolvers = []string{"google", "cloudflare", "quad9"}

// ResolverNames are the names ParseResolvers knows, besides udp:IP and
// tcp:IP.
func ResolverNames() []string {
	names := make([]string, 0, len(knownResolvers)+1)
	for _, k := range knownResolvers {
		names = append(names, k.name)
	}
	return append(names, "system")
}

// maxResolvers bounds one check: each resolver costs the node up to four
// queries a zone.
const maxResolvers = 12

// ParseResolvers reads resolvers: names (ResolverNames; system is the
// host's own, from resolv.conf), udp:IP[:port], tcp:IP[:port] or a bare IP
// (UDP); an item may hold several, comma-separated.
func ParseResolvers(items []string) ([]Resolver, error) {
	var out []Resolver
	add := func(r Resolver) {
		for _, o := range out {
			if o.Net == r.Net && o.Addr == r.Addr {
				return
			}
		}
		out = append(out, r)
	}
	for _, item := range items {
		for _, s := range strings.Split(item, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			name := strings.ToLower(s)
			if name == "system" {
				servers, err := SystemResolvers("")
				if err != nil {
					return nil, err
				}
				for _, a := range servers {
					add(Resolver{Name: "system", Net: "udp", Addr: a, WarnOnly: true})
				}
				continue
			}
			known := false
			for _, k := range knownResolvers {
				if k.name == name {
					known = true
					for _, a := range k.addrs {
						add(Resolver{Name: k.name, Net: "udp", Addr: netip.AddrPortFrom(netip.MustParseAddr(a), 53), WarnOnly: k.warnOnly})
					}
				}
			}
			if known {
				continue
			}
			network, rest := "udp", s
			if p, r, ok := strings.Cut(s, ":"); ok && (p == "udp" || p == "tcp") {
				network, rest = p, r
			}
			addr, err := parseServer(rest)
			if err != nil {
				return nil, fmt.Errorf("resolver %q: a name (%s), udp:IP or tcp:IP", s, strings.Join(ResolverNames(), ", "))
			}
			shown := addr.String()
			if addr.Port() == 53 {
				shown = addr.Addr().String()
			}
			add(Resolver{Name: network + ":" + shown, Net: network, Addr: addr})
		}
	}
	if len(out) > maxResolvers {
		return nil, fmt.Errorf("%d resolvers: at most %d at once", len(out), maxResolvers)
	}
	return out, nil
}

// parseServer reads IP, IP:port or [IPv6]:port; the port is 53 unless
// given.
func parseServer(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a, 53), nil
}

// Resolv.conf of the host, and of systemd-resolved: the servers behind
// its stub.
const (
	resolvConf    = "/etc/resolv.conf"
	resolvedConf  = "/run/systemd/resolve/resolv.conf"
	resolvedStub  = "127.0.0.53"
	resolvedStub2 = "127.0.0.54"
)

// SystemResolvers are the host's resolvers: the nameservers of
// /etc/resolv.conf, under root ("" on the host). When that names only
// systemd-resolved's stub, the servers behind it: the stub would hide
// which server answers.
func SystemResolvers(root string) ([]netip.AddrPort, error) {
	read := func(p string) []netip.AddrPort {
		b, err := os.ReadFile(filepath.Join(root, p)) //nolint:gosec // G304: the host's resolv.conf
		if err != nil {
			return nil
		}
		var out []netip.AddrPort
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 2 || f[0] != "nameserver" {
				continue
			}
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, netip.AddrPortFrom(a, 53))
			}
		}
		return out
	}
	servers := read(resolvConf)
	if len(servers) == 0 {
		return nil, fmt.Errorf("%s names no nameserver", resolvConf)
	}
	stub := true
	for _, s := range servers {
		if a := s.Addr().String(); a != resolvedStub && a != resolvedStub2 {
			stub = false
		}
	}
	if stub {
		if up := read(resolvedConf); len(up) > 0 {
			return up, nil
		}
	}
	return servers, nil
}
