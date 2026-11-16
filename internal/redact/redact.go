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
	"iter"
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
	// An IPv4 address, as a reader takes it: octets of up to 255, leading
	// zeros too (203.0.113.05). No word boundary around it: one glued to
	// a word or a number (host203.0.113.5, 203.0.113.5abc,
	// 203.0.113.5203.0.113.6) goes too; so does a version that is four
	// such numbers (v1.2.3.4), which an address after a "v" would be.
	ipv4 = regexp.MustCompile(v4)
	quad = regexp.MustCompile(`^` + v4) // one at the start
	// The last group may be missing: an address or a prefix that ends in
	// "::" (2001:db8::/32, an admin prefix) ends on no word boundary. Or
	// it is an IPv4 address (64:ff9b::198.51.100.9), taken whole: cut at
	// its first dot, the rest would be three octets that the IPv4 pattern
	// does not take. One that starts with "::" (::ffff:c633:6407, ::2)
	// starts on no word boundary either, unless a word is before it: its
	// "::" after anything but a word. Only what parses as an address is
	// replaced (span), and what is glued to the text around it is read
	// from that text (at).
	ipv6 = regexp.MustCompile(`(?i)(?:\b(?:[0-9a-f]{0,4}:){2,8}|\B::(?:[0-9a-f]{1,4}:){0,6})(?:(` + v4 + `)|([0-9a-f]{1,4}))?`)
)

// v4 is an IPv4 address: four octets of up to 255, leading zeros too.
const v4 = `(?:0*(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}0*(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`

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
	glued := false
	for {
		next, g6 := r.ipv6s(s)
		next, g4 := r.ipv4s(next)
		glued = glued || g6 || g4
		if next == s {
			break
		}
		s = next
	}
	// An address glued to a link or a UUID after it hid the word boundary
	// they start on ("203.0.113.5ss://…"); its token leaves one.
	if glued {
		s = links.ReplaceAllString(s, "<link>")
		s = uuids.ReplaceAllString(s, "<uuid>")
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
// The text is lowered byte by byte, A to Z only: strings.ToLower changes
// the length of text that is not UTF-8 ("\xd1node.example.org", a
// replacement character for the byte), and the places in the lowered text
// were no longer those in s.
func replaceName(s, name string) string {
	lower := asciiLower(s)
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

// asciiLower is s with A to Z lowered, every other byte as it is.
func asciiLower(s string) string {
	i := strings.IndexFunc(s, func(c rune) bool { return c >= 'A' && c <= 'Z' })
	if i < 0 {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if c := b[i]; c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func isLabelByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.'
}

// ipv4s replaces the IPv4 addresses in s; glued: one with a word after it.
func (r *Redactor) ipv4s(s string) (out string, glued bool) {
	var b strings.Builder
	last := 0
	for a, z := range runs(s, isDecimal, '.', 3) {
		for _, m := range ipv4.FindAllStringIndex(s[a:z], -1) {
			i, j := a+m[0], a+m[1]
			if addr, ok := parseAddr(s[i:j]); ok {
				b.WriteString(s[last:i])
				b.WriteString(r.token(addr, s[i:j]))
				last = j
				glued = glued || j < len(s) && isWord(s[j])
			}
		}
	}
	if last == 0 {
		return s, false
	}
	b.WriteString(s[last:])
	return b.String(), glued
}

// ipv6s replaces the IPv6 addresses in s (at); glued: one with a word
// after it. The pattern runs on a stretch with the byte before and after
// it, which its word boundaries look at.
func (r *Redactor) ipv6s(s string) (out string, glued bool) {
	var b strings.Builder
	last := 0
	for a, z := range runs(s, isAddrByte, ':', 2) {
		lo := max(a-1, 0)
		for _, m := range ipv6.FindAllStringSubmatchIndex(s[lo:min(z+1, len(s))], -1) {
			for k := range m {
				if m[k] >= 0 {
					m[k] += lo
				}
			}
			if i, j, addr, ok := at(s, m, last); ok {
				b.WriteString(s[last:i])
				b.WriteString(r.token(addr, s[i:j]))
				last = j
				glued = glued || j < len(s) && isWord(s[j])
			}
		}
	}
	if last == 0 {
		return s, false
	}
	b.WriteString(s[last:])
	return b.String(), glued
}

// runs are the stretches of s made of the bytes in, with at least n of
// sep: the only places the address patterns, made of those bytes, find
// one. Most text has none, and a pattern run on all of it costs more than
// the rest of String.
func runs(s string, in func(byte) bool, sep byte, n int) iter.Seq2[int, int] {
	return func(yield func(int, int) bool) {
		for i := 0; i < len(s); {
			if !in(s[i]) {
				i++
				continue
			}
			j, seps := i, 0
			for ; j < len(s) && in(s[j]); j++ {
				if s[j] == sep {
					seps++
				}
			}
			if seps >= n && !yield(i, j) {
				return
			}
			i = j
		}
	}
}

func isDecimal(c byte) bool { return c >= '0' && c <= '9' || c == '.' }

// isAddrByte is what an IPv6 address is written with, an IPv4 one at its
// end too.
func isAddrByte(c byte) bool { return isHex(c) || c == ':' || c == '.' }

// at is the address of match m of the IPv6 pattern in s, and where it
// starts and ends in s, at last or after.
//
// The pattern takes no word boundary for the end of the last group, and an
// address glued to a word or to another address is read from the text
// around the match:
//   - After a word (host2001:db8::1, eth0fe80::1): the match starts at the
//     colon after the first group, which is the last four hex digits of the
//     word; they go with it. Only with two groups at least: "Cafe::new"
//     stays.
//   - Before an IPv4 address (2001:db8::1203.0.113.5): the last group ends
//     where one can start, the one that leaves the most to it, which the
//     IPv4 pattern then takes.
//   - Before a word (2001:db8::1x): the last group up to it. "io::Error" is
//     no address: glued on both sides, one group is not enough, and the
//     match goes without its last group, as it went before.
func at(s string, m []int, last int) (start, end int, a netip.Addr, ok bool) {
	i, j := m[0], m[1]
	tail := -1 // where the last group or the IPv4 address at the end starts
	if m[2] >= 0 {
		tail = m[2]
	} else if m[4] >= 0 {
		tail = m[4]
	}
	if s[i] == ':' && i-4 >= last && isHex(s[i-4]) && isHex(s[i-3]) && isHex(s[i-2]) && isHex(s[i-1]) {
		if b, z, _, ok := span(s, i-4, j); ok && b == i-4 && groups(s[b:z]) >= 2 {
			i = b
		}
	}
	if m[4] >= 0 && j < len(s) && s[j] == '.' {
		for k := tail; k < j; k++ {
			if quad.MatchString(s[k:]) {
				if b, z, a, ok := span(s, i, k); ok && z == k {
					return b, z, a, true
				}
			}
		}
	}
	start, end, a, ok = span(s, i, j)
	if ok && end == j && tail >= 0 && j < len(s) && isWord(s[j]) && start > 0 && isWord(s[start-1]) && groups(s[start:end]) < 2 {
		return span(s, i, tail)
	}
	return start, end, a, ok
}

// span is the address in s[i:j] as the IPv6 pattern takes it, and where
// it starts and ends in s.
//
// The pattern takes more than the address around a colon, and the whole
// then does not parse. After it: a colon ("from 2001:db8::5: refused", the
// last group being optional), or a colon and a port or a hex word, without
// brackets, after an address of eight groups or of seven and "::"
// ("2001:db8:1:2:3:4:5:6:443", eight groups and the last): the address is
// the match up to its last colon, and the rest stays. Before it: the colon
// that glues it to a word ("ipv6:2001:db8::1", where the match starts on a
// word boundary, or "ipv6:::2", where it starts with three), which stays
// too.
func span(s string, i, j int) (start, end int, a netip.Addr, ok bool) {
	m := s[i:j]
	if strings.HasPrefix(m, ":") && (!strings.HasPrefix(m, "::") || strings.HasPrefix(m, ":::")) {
		i, m = i+1, m[1:]
	}
	if a, ok := parseAddr(m); ok {
		return i, j, a, true
	}
	if c := strings.LastIndexByte(m, ':'); c > 0 && strings.Contains(m[:c], ":") {
		if a, ok := parseAddr(m[:c]); ok {
			return i, i + c, a, true
		}
	}
	return 0, 0, netip.Addr{}, false
}

// groups is how many groups an IPv6 address is written with, an IPv4
// address at its end two.
func groups(a string) int {
	n := 0
	for i := 0; i < len(a); i++ {
		switch {
		case a[i] == '.':
			return n + 1 // the IPv4 address's first octet counted one
		case a[i] != ':' && (i == 0 || a[i-1] == ':'):
			n++
		}
	}
	return n
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// isWord is what glues an address to the text around it: a letter, a
// digit or an underscore.
func isWord(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
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

// token is address a, found as m, as a report has it: its kind and a
// salted short hash. Loopback and unspecified addresses stay, they say
// nothing.
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
