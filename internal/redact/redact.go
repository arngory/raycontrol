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
	ipv6   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b`)
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
	s = ipv6.ReplaceAllStringFunc(s, r.addr)
	s = ipv4.ReplaceAllStringFunc(s, r.addr)
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
func (r *Redactor) addr(m string) string {
	a, err := netip.ParseAddr(m)
	if err != nil {
		return m
	}
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
	h.Write(a.AsSlice())
	return "<" + kind + ":" + hex.EncodeToString(h.Sum(nil)[:3]) + ">"
}
