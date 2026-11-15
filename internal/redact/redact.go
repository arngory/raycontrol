// Package redact takes out of text what must not leave the node in a
// report (docs/09-observability.md): addresses, the node's names, keys,
// UUIDs, links and bundles. Addresses become stable tokens within one
// report, so lines about the same client still match, but not across
// reports: every Redactor has its own salt.
package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Redactor redacts text for one report.
type Redactor struct {
	salt  []byte
	names []string // the node's own names: domain, host
}

// New returns a redactor with a fresh salt; names are the node's domain and
// host, replaced wherever they appear (subdomains included).
func New(names ...string) *Redactor {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	r := &Redactor{salt: salt}
	for _, n := range names {
		if n = strings.TrimSpace(strings.ToLower(n)); n != "" {
			r.names = append(r.names, n)
		}
	}
	return r
}

// Add takes more of the node's names (its DNS tunnel zones, found later
// than the domain and host).
func (r *Redactor) Add(names ...string) {
	for _, n := range names {
		if n = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(n, "."))); n != "" && !slices.Contains(r.names, n) {
			r.names = append(r.names, n)
		}
	}
}

var (
	links    = regexp.MustCompile(`(?i)\b(vless|vmess|trojan|hysteria2|hy2|ss|tuic|naive\+https)://\S+`)
	bundles  = regexp.MustCompile(`rcdev1:[A-Za-z0-9_-]+`)
	uuids    = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	pemBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----`)
	// Long base64/base64url or hex runs: keys, seeds, signatures, tokens.
	secrets = regexp.MustCompile(`\b[A-Za-z0-9+/_=-]{32,}\b`)
	// Shorter hex runs: device and node IDs, which link reports to a node.
	hexIDs = regexp.MustCompile(`(?i)\b[0-9a-f]{12,31}\b`)
	ipv4   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// The last group may be missing: an address or a prefix that ends in
	// "::" (2001:db8::/32, an admin prefix) ends on no word boundary. Or
	// it is an IPv4 address (64:ff9b::198.51.100.9), taken whole: cut at
	// its first dot, the rest would be three octets that the IPv4 pattern
	// does not take. One that starts with "::" (::ffff:c633:6407, ::2)
	// starts on no word boundary either, unless a word is before it: its
	// "::" after anything but a word. Only what parses as an address is
	// replaced (addr).
	ipv6 = regexp.MustCompile(`(?i)(?:\b(?:[0-9a-f]{0,4}:){2,8}|\B::(?:[0-9a-f]{1,4}:){0,6})(?:\d{1,3}(?:\.\d{1,3}){3}\b|[0-9a-f]{1,4}\b)?`)
)

// String redacts s.
func (r *Redactor) String(s string) string {
	s = pemBlock.ReplaceAllString(s, "<pem>")
	s = links.ReplaceAllString(s, "<link>")
	s = bundles.ReplaceAllString(s, "<bundle>")
	s = uuids.ReplaceAllString(s, "<uuid>")
	for _, n := range r.names {
		s = replaceName(s, n)
	}
	// The addresses until none is left: text that is no address as a whole
	// may hold one that a token leaves bare ("1:2:3:4:5:6::" when the IPv4
	// address after it goes, the whole having a group too many). Each round
	// that changes the text takes an address out of it.
	for {
		next := ipv4.ReplaceAllStringFunc(ipv6.ReplaceAllStringFunc(s, r.addr), r.addr)
		if next == s {
			break
		}
		s = next
	}
	s = hexIDs.ReplaceAllString(s, "<id>")
	s = secrets.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Trim(m, "-_=") == "" {
			return m
		}
		return "<secret>"
	})
	return s
}

// replaceName replaces a name and any subdomain of it with <domain> (with a
// label count, which says enough to debug and nothing about the labels).
func replaceName(s, name string) string {
	lower := strings.ToLower(s)
	var b strings.Builder
	for {
		i := strings.Index(lower, name)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		// Extend left over subdomain labels.
		start := i
		for start > 0 && isLabelByte(lower[start-1]) {
			start--
		}
		labels := strings.Count(lower[start:i], ".")
		b.WriteString(s[:start])
		if labels > 0 {
			b.WriteString("<sub>." + strings.Repeat("<sub>.", labels-1))
		}
		b.WriteString("<domain>")
		s, lower = s[i+len(name):], lower[i+len(name):]
	}
}

func isLabelByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.'
}

// addr turns an address into a token: its kind and a salted short hash.
// Loopback and unspecified addresses stay, they say nothing.
//
// The IPv6 pattern takes more than the address around a colon, and the
// whole then does not parse. After it: a colon ("from 2001:db8::5:
// refused", the last group being optional), or a colon and a port or a
// hex word, without brackets, after an address of eight groups or of
// seven and "::" ("2001:db8:1:2:3:4:5:6:443", eight groups and the
// last): the address is the match up to its last colon, and the rest
// stays. Before it: the colon that glues it to a word ("ipv6:2001:db8::1",
// where the match starts on a word boundary, or "ipv6:::2", where it
// starts with three), which stays too.
func (r *Redactor) addr(m string) string {
	lead := ""
	if strings.HasPrefix(m, ":") && (!strings.HasPrefix(m, "::") || strings.HasPrefix(m, ":::")) {
		lead, m = ":", m[1:]
	}
	if a, ok := parseAddr(m); ok {
		return lead + r.token(a, m)
	}
	if i := strings.LastIndexByte(m, ':'); i > 0 && strings.Contains(m[:i], ":") {
		if a, ok := parseAddr(m[:i]); ok {
			return lead + r.token(a, m[:i]) + m[i:]
		}
	}
	return lead + m
}

// parseAddr parses an address as a reader takes it: an IPv4 one with a
// leading zero in an octet too (203.0.113.05), which netip refuses, alone
// or at the end of an IPv6 one (64:ff9b::198.51.100.09).
func parseAddr(m string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(m); err == nil {
		return a, true
	}
	head, v4 := "", m
	if i := strings.LastIndexByte(m, ':'); i >= 0 {
		head, v4 = m[:i+1], m[i+1:]
	}
	if strings.Count(v4, ".") != 3 {
		return netip.Addr{}, false
	}
	octets := strings.Split(v4, ".")
	for i, o := range octets {
		if o == "" {
			return netip.Addr{}, false
		}
		octets[i] = strings.TrimLeft(o, "0")
		if octets[i] == "" {
			octets[i] = "0"
		}
	}
	a, err := netip.ParseAddr(head + strings.Join(octets, "."))
	return a, err == nil
}

// token is address a, found as m, as a report has it.
func (r *Redactor) token(a netip.Addr, m string) string {
	if a.IsLoopback() || a.IsUnspecified() {
		return m
	}
	kind := "ip4"
	if a.Is6() && !a.Is4In6() {
		kind = "ip6"
	}
	if a.IsPrivate() || a.IsLinkLocalUnicast() {
		kind += "-private"
	}
	h := hmac.New(sha256.New, r.salt)
	h.Write(a.Unmap().AsSlice()) // a mapped address is the IPv4 one
	return "<" + kind + ":" + hex.EncodeToString(h.Sum(nil)[:3]) + ">"
}
