package release

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// HideMirrors is text of an update's that leaves its host (a relay's
// status, which rayd relay tells the exit) with the mirrors in it named by
// their place in mirrors, as "<mirror 2 of 3>": their URLs, with the user
// and password in them and as net/http writes them, and their hosts. A
// mirror is the host's own setting (RAYCONTROL_MIRRORS), a private one
// maybe; the host's journal names it, and the place says which. The
// default mirrors, public, keep their names.
func HideMirrors(text string, mirrors []string) string {
	for i, m := range mirrors {
		if slices.Contains(DefaultMirrors, m) {
			continue
		}
		name := fmt.Sprintf("<mirror %d of %d>", i+1, len(mirrors))
		u, err := url.Parse(m)
		if err != nil || u.Host == "" {
			text = replaceFold(text, m, name, false)
			continue
		}
		// The URL as written, as net/http's errors write it (the password
		// as ***), as url writes it (as xxxxx); then the host, with its
		// user, with its port, alone.
		prefixes := []string{m}
		if u.User != nil {
			if _, ok := u.User.Password(); ok {
				prefixes = append(prefixes,
					strings.Replace(m, u.User.String()+"@", u.User.Username()+":***@", 1), u.Redacted())
			}
		}
		slash := ""
		if strings.HasSuffix(m, "/") {
			slash = "/"
		}
		for _, p := range prefixes {
			text = replaceFold(text, p, name+slash, false)
		}
		hosts := []string{u.Host, u.Hostname()}
		if u.User != nil {
			for _, ui := range []string{u.User.String(), u.User.Username() + ":***", u.User.Username()} {
				hosts = append([]string{ui + "@" + u.Host, ui + "@" + u.Hostname()}, hosts...)
			}
		}
		for _, h := range hosts {
			text = replaceFold(text, h, name, true)
		}
	}
	return text
}

// replaceFold replaces old in s with repl, A to Z matching a to z; whole,
// only where old is not part of a longer name (host).
func replaceFold(s, old, repl string, whole bool) string {
	if old == "" {
		return s
	}
	lower, lold := asciiLower(s), asciiLower(old)
	var b strings.Builder
	last := 0
	for i := 0; i+len(lold) <= len(lower); {
		k := strings.Index(lower[i:], lold)
		if k < 0 {
			break
		}
		j := i + k
		if whole && !alone(s, j, j+len(old)) {
			i = j + 1
			continue
		}
		b.WriteString(s[last:j])
		b.WriteString(repl)
		last = j + len(old)
		i = last
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// alone reports whether the name at s[i:j] is a name of its own, not part
// of a longer one: no letter, digit or hyphen next to it, nor a dot and
// one after it (mirror.example.org); a dot before it makes it a name's
// domain, which goes too, and one after it with nothing more ends a
// sentence.
func alone(s string, i, j int) bool {
	if i > 0 && nameByte(s[i-1]) {
		return false
	}
	longer := j < len(s) && (nameByte(s[j]) || s[j] == '.' && j+1 < len(s) && nameByte(s[j+1]))
	return !longer
}

// nameByte is what a host's name is made of besides dots.
func nameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

// asciiLower is s with A to Z lowered, every other byte as it is: the
// places in it are those in s.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
