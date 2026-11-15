package nodeupdate

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// fuzzNow is the fuzz targets' clock: 03:30 UTC, in the default window.
var fuzzNow = time.Date(2026, 11, 15, 3, 30, 0, 0, time.UTC)

// installedVersions are what root's side runs: its own version, never
// rayd's word.
var installedVersions = []string{"v0.28.0", "v0.27.3", "v1.2.9", "v0.0.1", "dev", ""}

var bigVersion = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)$`)

// numbers is a release's three numbers, whatever their size; nil for what
// is no release. An oracle apart from release.Newer.
func numbers(v string) []*big.Int {
	m := bigVersion.FindStringSubmatch(v)
	if m == nil {
		return nil
	}
	out := make([]*big.Int, 3)
	for i := range out {
		out[i], _ = new(big.Int).SetString(m[i+1], 10)
	}
	return out
}

// newerBig reports whether release a is newer than b by its numbers; any
// release is newer than what is none.
func newerBig(a, b string) bool {
	na, nb := numbers(a), numbers(b)
	switch {
	case na == nil:
		return false
	case nb == nil:
		return true
	}
	for i := range na {
		if c := na[i].Cmp(nb[i]); c != 0 {
			return c > 0
		}
	}
	return false
}

// shown reports whether s is text a terminal or a journal shows as it is:
// UTF-8, and nothing they act on or hide (controls, format characters
// such as the bidi overrides, line and paragraph separators, spaces other
// than the ASCII one, the replacement character of a broken byte).
func shown(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError || unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs, unicode.Co, unicode.Zl, unicode.Zp) ||
			(unicode.IsSpace(r) && r != ' ') {
			return false
		}
	}
	return true
}

// FuzzRequest is root's side of an update by request
// (spec/node-update-v1.md §3, spec/relay-update-remote-v1.md §4.2): the
// file rayd (rayd relay) writes, as root reads it, checked against root's
// own version, its held releases and its policy file. What passes is what
// the rules say may run: well formed, fresh, of this host's kind, a
// signed release's name (vX.Y.Z) or latest, strictly newer by its
// numbers, an auto update a patch release in the window, an exit's not
// held, the policy on for it. Its status, written whatever it held, reads
// back printable and within its bounds.
func FuzzRequest(f *testing.F) {
	at := fuzzNow.Add(-time.Minute).Format(time.RFC3339Nano)
	for _, s := range []struct {
		req       string
		installed uint8
		held      string
		relay     bool
		policy    string
	}{
		{`{"id":"6f1c0e2a9b3d4c5e","kind":"remote","version":"latest","by":"alice/phone (remote)","at":"` + at + `"}`, 0, "", false,
			`{"remote":"on","auto":"off","window":"03:00-05:00"}`},
		{`{"id":"6f1c0e2a9b3d4c5e","kind":"remote","version":"latest","release":"v0.28.1","by":"alice/phone (remote)","at":"` + at + `"}`, 0, "", false,
			`{"remote":"on","auto":"off","window":"03:00-05:00"}`},
		{`{"id":"0a","kind":"auto","version":"v0.28.1","by":"auto","at":"` + at + `"}`, 0, "v0.28.2", false,
			`{"remote":"off","auto":"patch","window":"03:00-05:00"}`},
		{`{"id":"0a","kind":"auto","version":"v0.29.0","by":"auto","at":"` + at + `"}`, 0, "", false,
			`{"remote":"on","auto":"patch","window":"23:30-01:00"}`},
		{`{"id":"0b","kind":"exit","version":"v0.28.1","by":"exit","at":"` + at + `"}`, 0, "v0.28.1", true,
			`{"remote":"on","auto":"off","window":"03:00-05:00"}`},
		{`{"id":"0b","kind":"exit","version":"v0.29.0","by":"exit","at":"` + at + `"}`, 1, "v0.28.1,v0.28.2", true,
			`{"remote":"on","auto":"off","window":"03:00-05:00"}`},
		{`{"id":"0b","kind":"exit","version":"v0.28.01","by":"exit","at":"` + at + `"}`, 0, "v0.28.1", true,
			`{"remote":"on","auto":"off","window":"03:00-05:00"}`},
		{`{"id":"0c","kind":"remote","version":"v0.99999999999999999999.0","by":"x","at":"` + at + `"}`, 0, "", false,
			`{"remote":"on","auto":"off","window":"03:00-05:00"}`},
		{`{"id":"0c","Kind":"remote","KIND":"auto","version":"v0.28.1","by":"x\u202e","at":"` + at + `"}`, 0, "", false,
			`{"remote":"on","auto":"patch","window":"03:00-05:00"}`},
		{`{"id":"../x","kind":"remote","version":"v9.9.9\n","by":"\u001b[2J","at":"2026-11-15T09:00:00Z"}`, 4, "", false, `{"remote":"on"}`},
		{`{"id":"0d","kind":"remote","version":"latest","by":"` + strings.Repeat("é", 200) + `","at":"0001-01-01T00:00:00Z"}`, 5, "", false, `null`},
		{`[]`, 0, "", false, `{"remote":"on","auto":"patch","window":"3-5"}`},
		{strings.Repeat(" ", maxFile+1), 0, "", true, ``},
	} {
		f.Add([]byte(s.req), s.installed, s.held, s.relay, []byte(s.policy))
	}
	dir := f.TempDir()
	reqPath, polPath, statPath := filepath.Join(dir, "update-request"), filepath.Join(dir, "policy.json"), filepath.Join(dir, "status.json")
	f.Fuzz(func(t *testing.T, raw []byte, inst uint8, heldList string, relay bool, policy []byte) {
		if err := os.WriteFile(reqPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(polPath, policy, 0o600); err != nil {
			t.Fatal(err)
		}
		installed := installedVersions[int(inst)%len(installedVersions)]
		var held []string
		if heldList != "" {
			held = strings.Split(heldList, ",")
		}
		kinds := NodeKinds
		if relay {
			kinds = RelayKinds
		}

		r, ok, err := ReadRequest(reqPath)
		if !ok {
			t.Fatal("a file there, and no request seen")
		}
		if err == nil && len(raw) > maxFile {
			t.Fatalf("a request of %d bytes taken", len(raw))
		}
		p := ReadPolicy(polPath)
		if p.Check() != nil {
			t.Fatalf("policy %+v read, and it does not pass its own check", p)
		}
		if err == nil {
			err = r.Check(kinds, installed, held, fuzzNow)
		}
		if err == nil {
			err = p.Allows(r, fuzzNow)
		}

		// The status root writes of it, taken or not (requests.run).
		st := Status{ID: r.ID, State: Failed, From: installed, To: r.Version, Target: r.Version, Release: r.Tried(), By: r.By, Kind: r.Kind,
			Requested: r.At, Started: fuzzNow, Held: held}
		if err != nil {
			st.Error, st.Untouched, st.Reason = err.Error(), true, ReasonOf(err)
		}
		if werr := WriteStatus(statPath, st); werr != nil {
			t.Fatal(werr)
		}
		got := ReadStatus(statPath)
		checkStatus(t, got)
		if got.State != Failed || len(st.Held) <= maxHeld && !slices.Equal(got.Held, slices.DeleteFunc(slices.Clone(st.Held), func(v string) bool {
			return numbers(v) == nil || len(v) > maxField
		})) {
			t.Fatalf("status %+v read back as %+v", st, got)
		}
		if err != nil {
			return
		}

		// Taken: the rules hold, by oracles of their own.
		switch {
		case r.ID == "" || len(r.ID) > 32 || strings.Trim(r.ID, "0123456789abcdef") != "":
			t.Fatalf("id %q taken", r.ID)
		case !slices.Contains(kinds, r.Kind):
			t.Fatalf("kind %q taken (relay %v)", r.Kind, relay)
		case r.Version != "latest" && numbers(r.Version) == nil, relay && numbers(r.Version) == nil:
			t.Fatalf("version %q taken (relay %v)", r.Version, relay)
		case r.Version != "latest" && !newerBig(r.Version, installed):
			t.Fatalf("%q taken over %q: not newer", r.Version, installed)
		case r.Release != "" && numbers(r.Release) == nil:
			t.Fatalf("release %q taken", r.Release)
		case r.By == "" || len(r.By) > maxField || !shown(r.By):
			t.Fatalf("by %q taken", r.By)
		case fuzzNow.Sub(r.At) > Stale || r.At.Sub(fuzzNow) > time.Minute:
			t.Fatalf("a request of %v taken at %v", r.At, fuzzNow)
		case r.Kind == Exit && slices.Contains(held, r.Version):
			// By its text, as Check holds it: v0.28.01 is not a held
			// v0.28.1 here, and it runs as far as the download, where
			// GitHub has no such tag and a mirror's files sign v0.28.1.
			t.Fatalf("held %q taken", r.Version)
		case (r.Kind == Remote || r.Kind == Exit) && p.Remote != "on":
			t.Fatalf("a %s request taken with remote %q", r.Kind, p.Remote)
		}
		if r.Kind == Auto {
			a, b := numbers(r.Version), numbers(installed)
			if a == nil || b == nil || a[0].Cmp(b[0]) != 0 || a[1].Cmp(b[1]) != 0 || p.Auto != "patch" ||
				!InWindow(fuzzNow, p.Window) && !InWindow(fuzzNow.Add(-5*time.Minute), p.Window) {
				t.Fatalf("auto %q taken over %q with %+v", r.Version, installed, p)
			}
		}
		// What runs is what rayctl update is given: a version, no flag.
		if strings.HasPrefix(r.Version, "-") || strings.ContainsAny(r.Version, " \t\n/") {
			t.Fatalf("version %q handed to rayctl update", r.Version)
		}
	})
}

// checkStatus fails t unless s is what rayd may show and pass on: every
// text printable and cut to its bound, a reason of a code's form, held
// releases only, and no more than maxHeld.
func checkStatus(t *testing.T, s Status) {
	t.Helper()
	for _, v := range []string{s.ID, s.State, s.From, s.To, s.Target, s.Release, s.By, s.Kind} {
		if !shown(v) || len(v) > maxField+len("…") {
			t.Fatalf("status field %q", v)
		}
	}
	if !shown(s.Error) || len(s.Error) > maxError+len("…") {
		t.Fatalf("status error %q", s.Error)
	}
	if !ValidReason(s.Reason) {
		t.Fatalf("status reason %q", s.Reason)
	}
	if len(s.Held) > maxHeld {
		t.Fatalf("%d held", len(s.Held))
	}
	for _, v := range s.Held {
		if numbers(v) == nil || len(v) > maxField {
			t.Fatalf("held %q", v)
		}
	}
}

// FuzzStatus is the status and the result as root writes them, whatever
// their fields hold (a request's, an update's last words): rayd reads
// them back, printable and bounded, the result's state one of its three.
// And the files as they come, whatever they hold: no panic, a policy
// only one that passes its own check.
func FuzzStatus(f *testing.F) {
	f.Add("6f1c0e2a9b3d4c5e", Failed, "v0.27.0", "v0.28.0", "exit", "alice/phone (remote)", "this SSH session comes from 198.51.100.7",
		ReasonSSH, "v0.27.1,v0.27.2", []byte(`{"id":"6f1c0e2a9b3d4c5e","state":"done","from":"v0.26.0","to":"v0.27.0","held":["v0.26.1"]}`))
	f.Add("\x00\"\\", "running\u2028", "\xff\xfe", strings.Repeat("é", maxField), "\u202e", "<&>", strings.Repeat("e\x1b[2J", maxError),
		"Download", "v0.19.1,not one,v0.19.2,v0.19.3,v0.19.4,v0.19.5,v0.19.6,v0.19.7,v0.19.8,v0.19.9", []byte(`{"state":"rolled_back","reason":"x"}`))
	f.Add("", "", "", "", "", "", "", "", "", []byte(`{"remote":"on","auto":"patch","window":"23:30-01:00"}`))
	f.Add("a", Done, "b", "c", "d", "e", strings.Repeat("\U0001F600", maxError), "mirror_gone", ",,,", []byte(`{"state":"done","error":"`+strings.Repeat("x", maxStatus)+`"}`))
	dir := f.TempDir()
	statPath, resPath, rawPath := filepath.Join(dir, "status.json"), filepath.Join(dir, "result.json"), filepath.Join(dir, "raw")
	f.Fuzz(func(t *testing.T, id, state, from, to, kind, by, text, reason, heldList string, raw []byte) {
		s := Status{ID: id, State: state, From: from, To: to, Target: to, Release: to, By: by, Kind: kind, Error: text, Reason: reason,
			Held: strings.Split(heldList, ",")}
		if err := WriteStatus(statPath, s); err != nil {
			t.Fatal(err)
		}
		got := ReadStatus(statPath)
		checkStatus(t, got)
		if state != "" && got.State == Idle && state != Idle {
			t.Fatalf("status %+v not read back", s)
		}
		if raw, _ := os.ReadFile(statPath); len(raw) > maxStatus || !utf8.Valid(raw) || strings.ContainsFunc(strings.TrimSuffix(string(raw), "\n"), unicode.IsControl) {
			t.Fatalf("status file of %d bytes: %.200q", len(raw), raw)
		}

		if err := WriteResult(resPath, Result{State: state, Version: from, Release: to, Error: text, Reason: reason}); err != nil {
			t.Fatal(err)
		}
		res, ok := ReadResult(resPath)
		switch {
		case ok != (state == Done || state == RolledBack || state == Failed):
			t.Fatalf("result of state %q: %v", state, ok)
		case ok && (!shown(res.Version) || len(res.Version) > maxField+len("…") || !shown(res.Release) || len(res.Release) > maxField+len("…") ||
			!shown(res.Error) || len(res.Error) > maxError+len("…") || !ValidReason(res.Reason)):
			t.Fatalf("result %+v", res)
		}

		// The files as they are, whatever wrote them.
		if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if p := ReadPolicy(rawPath); p.Check() != nil {
			t.Fatalf("policy %+v read", p)
		}
		if res, ok := ReadResult(rawPath); ok && res.State != Done && res.State != RolledBack && res.State != Failed {
			t.Fatalf("result %+v read", res)
		}
		if st := ReadStatus(rawPath); st.State == "" {
			t.Fatalf("status %+v read", st)
		}
		_, _ = PeekRequest(rawPath)
	})
}

// graphic reports whether s is UTF-8 of letters, marks, numbers,
// punctuation, symbols and the ASCII space only, and no U+FFFD: what
// Printable is to leave as it is.
func graphic(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError || r != ' ' && !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S) {
			return false
		}
	}
	return true
}

// FuzzPrintable: what Printable and clip make of any text is UTF-8 with
// nothing a terminal acts on, one rune for each of the text's, and clip's
// within its bound (and the "…" that says so), cut on a rune.
func FuzzPrintable(f *testing.F) {
	for _, s := range []string{"", "alice/phone (remote)", "a\x1b[2Jb\x00", "\xff\xfe\xfd", "é\u2028\u202e\ufeff\U0001F600", "\ufffd", strings.Repeat("é", 100)} {
		f.Add(s, uint8(5))
	}
	f.Fuzz(func(t *testing.T, s string, n uint8) {
		p := Printable(s)
		if !shown(p) {
			t.Fatalf("Printable(%q) = %q", s, p)
		}
		if utf8.RuneCountInString(p) != utf8.RuneCountInString(s) {
			t.Fatalf("Printable(%q) = %q: runes lost or added", s, p)
		}
		if graphic(s) && p != s {
			t.Fatalf("Printable(%q) = %q: a printable text changed", s, p)
		}
		c := clip(p, int(n))
		switch {
		case !utf8.ValidString(c):
			t.Fatalf("clip(%q, %d) = %q", p, n, c)
		case len(p) <= int(n) && c != p:
			t.Fatalf("clip(%q, %d) = %q: cut within its bound", p, n, c)
		case len(p) > int(n) && (len(c) > int(n)+len("…") || !strings.HasSuffix(c, "…") || !strings.HasPrefix(p, strings.TrimSuffix(c, "…"))):
			t.Fatalf("clip(%q, %d) = %q", p, n, c)
		}
		// What WriteStatus writes of it decodes back to the same.
		b, err := marshal(c)
		var back string
		if err != nil || json.Unmarshal(b, &back) != nil || back != c {
			t.Fatalf("%q marshalled as %s", c, b)
		}
	})
}
