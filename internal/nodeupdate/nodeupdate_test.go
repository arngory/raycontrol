package nodeupdate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // the zones of TestWindowAcrossClockChanges, wherever it runs
	"unicode/utf8"
)

func TestRequestCheck(t *testing.T) {
	now := time.Now()
	ok := Request{ID: NewID(), Kind: Remote, Version: "v0.19.1", By: "alice/phone (remote)", At: now.Add(-time.Second)}
	if err := ok.Check(NodeKinds, "v0.19.0", nil, now); err != nil {
		t.Fatal(err)
	}
	// A refusal carries its reason code where the codes name one; a request
	// that is not well formed has none.
	for _, c := range []struct {
		r            func(Request) Request
		want, reason string
	}{
		{func(r Request) Request { r.ID = ""; return r }, "no id", ""},
		{func(r Request) Request { r.ID = "../../x"; return r }, "no id", ""},
		{func(r Request) Request { r.Kind = "root"; return r }, "kind", ""},
		{func(r Request) Request { r.Kind = Exit; return r }, "kind", ""}, // a relay's
		{func(r Request) Request { r.Version = "v0.19"; return r }, "latest or vX.Y.Z", ReasonVersion},
		{func(r Request) Request { r.Version = "v0.18.1"; return r }, "never goes back", ReasonVersion},
		{func(r Request) Request { r.Version = "v0.19.0"; return r }, "never goes back", ReasonVersion},
		{func(r Request) Request { r.Kind = Auto; r.Version = "v0.20.0"; return r }, "patch releases", ReasonVersion},
		{func(r Request) Request { r.Kind = Auto; r.Version = "latest"; return r }, "patch releases", ReasonVersion},
		{func(r Request) Request { r.By = ""; return r }, "no one", ""},
		{func(r Request) Request { r.By = "alice\nraycontrol v9.9.9 is running"; return r }, "no one", ""},
		{func(r Request) Request { r.By = "\x1b[2Jalice"; return r }, "no one", ""},
		{func(r Request) Request { r.By = strings.Repeat("a", maxField+1); return r }, "no one", ""},
		{func(r Request) Request { r.At = now.Add(-Stale - time.Minute); return r }, "too old", ReasonStale},
		{func(r Request) Request { r.At = now.Add(time.Hour); return r }, "too old", ReasonStale},
	} {
		err := c.r(ok).Check(NodeKinds, "v0.19.0", nil, now)
		if err == nil || !strings.Contains(err.Error(), c.want) || ReasonOf(err) != c.reason {
			t.Errorf("%+v: %v (reason %q), want %q (%q)", c.r(ok), err, ReasonOf(err), c.want, c.reason)
		}
	}
	if err := (Request{ID: NewID(), Kind: Remote, Version: "latest", By: "alice/phone (remote)", At: now}).Check(NodeKinds, "v0.19.0", nil, now); err != nil {
		t.Errorf("latest: %v", err)
	}
	if err := (Request{ID: NewID(), Kind: Auto, Version: "v0.19.4", By: "auto", At: now}).Check(NodeKinds, "v0.19.0", nil, now); err != nil {
		t.Errorf("a patch: %v", err)
	}
	// Held is the relay's rule here: an admin may still name a release that
	// did not hold on the node; the auto update leaves it, on rayd's side.
	if err := ok.Check(NodeKinds, "v0.19.0", []string{"v0.19.1"}, now); err != nil {
		t.Errorf("a held release asked for by an admin: %v", err)
	}
}

// A relay's request (spec/relay-update-remote-v1.md §4.2): the release its
// exit names, any newer than the relay's, none that did not hold on it.
// rayd relay is the side that cannot be trusted: none of it is skipped by
// writing another kind.
func TestExitRequestCheck(t *testing.T) {
	now := time.Now()
	held := []string{"v0.27.1"}
	ok := Request{ID: NewID(), Kind: Exit, Version: "v0.28.0", By: "exit", At: now.Add(-time.Second)}
	if err := ok.Check(RelayKinds, "v0.27.0", held, now); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		r            func(Request) Request
		want, reason string
	}{
		{func(r Request) Request { r.Version = "latest"; return r }, "the release the exit runs", ReasonVersion},
		{func(r Request) Request { r.Version = "v0.28"; return r }, "the release the exit runs", ReasonVersion},
		{func(r Request) Request { r.Version = "v0.27.0"; return r }, "never goes back", ReasonVersion},
		{func(r Request) Request { r.Version = "v0.26.9"; return r }, "never goes back", ReasonVersion},
		{func(r Request) Request { r.Version = "v0.27.1"; return r }, "did not hold here", ReasonVersion},
		{func(r Request) Request { r.At = now.Add(-Stale - time.Minute); return r }, "too old", ReasonStale},
		{func(r Request) Request { r.Kind = Remote; return r }, "kind", ""},
		{func(r Request) Request { r.Kind = Remote; r.Version = "v0.27.1"; return r }, "kind", ""}, // held, as remote
		{func(r Request) Request { r.Kind = Auto; r.Version = "v0.27.2"; return r }, "kind", ""},
		{func(r Request) Request { r.ID = "x"; return r }, "no id", ""},
		{func(r Request) Request { r.By = ""; return r }, "no one", ""},
	} {
		err := c.r(ok).Check(RelayKinds, "v0.27.0", held, now)
		if err == nil || !strings.Contains(err.Error(), c.want) || ReasonOf(err) != c.reason {
			t.Errorf("%+v: %v (reason %q), want %q (%q)", c.r(ok), err, ReasonOf(err), c.want, c.reason)
		}
	}
	// Any newer release, a minor or a major one too: the relay follows its
	// exit (§11, 4). And a node takes no exit request.
	for _, v := range []string{"v0.27.2", "v0.30.0", "v1.0.0"} {
		r := ok
		r.Version = v
		if err := r.Check(RelayKinds, "v0.27.0", held, now); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	if err := ok.Check(NodeKinds, "v0.27.0", nil, now); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Errorf("an exit request on a node: %v", err)
	}
	// What a run that never ended left (Holding) is held too.
	last := Status{State: Running, Release: "v0.28.0", Held: held}
	if err := ok.Check(RelayKinds, "v0.27.0", last.Holding(), now); ReasonOf(err) != ReasonVersion {
		t.Errorf("the release of a run that never ended: %v", err)
	}
}

// Root's policy, not rayd's word: off unless root's file says on, an
// auto update in the window only.
func TestPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "policy.json")
	if p := ReadPolicy(path); p != DefaultPolicy() {
		t.Fatalf("no file: %+v", p)
	}
	at := time.Date(2026, 11, 8, 3, 10, 0, 0, time.UTC)
	remote, auto, exit := Request{Kind: Remote}, Request{Kind: Auto}, Request{Kind: Exit}
	for _, r := range []Request{remote, auto, exit} {
		if err := DefaultPolicy().Allows(r, at); err == nil || ReasonOf(err) != ReasonPolicy {
			t.Fatalf("the default, %s: %v", r.Kind, err)
		}
	}
	if err := DefaultPolicy().Allows(exit, at); !strings.Contains(err.Error(), "off on this relay (rayctl update remote on)") {
		t.Errorf("an exit request: %v", err)
	}
	for _, bad := range []Policy{{"yes", "off", DefaultWindow}, {"on", "minor", DefaultWindow}, {"on", "off", "3-5"}, {"on", "off", "03:00-03:10"}} {
		if err := WritePolicy(path, bad); err == nil {
			t.Errorf("%+v written", bad)
		}
	}
	p := Policy{Remote: "on", Auto: "patch", Window: "23:30-01:00"}
	if err := WritePolicy(path, p); err != nil {
		t.Fatal(err)
	}
	if got := ReadPolicy(path); got != p {
		t.Fatalf("read %+v", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode())
	}
	if err := p.Allows(remote, at); err != nil {
		t.Error(err)
	}
	// On a relay remote is root's word that its exit may name the release.
	if err := p.Allows(exit, at); err != nil {
		t.Error(err)
	}
	if err := (Policy{Remote: "off", Auto: "patch", Window: "03:00-05:00"}).Allows(exit, at); err == nil {
		t.Error("exit with remote off")
	}
	if err := p.Allows(auto, at); err == nil || ReasonOf(err) != ReasonPolicy {
		t.Errorf("auto outside the window: %v", err)
	}
	// A kind with no rule of its own does not run, whatever is on.
	if err := p.Allows(Request{Kind: "local"}, at); err == nil {
		t.Error("a kind with no rule")
	}
	night := time.Date(2026, 11, 8, 0, 30, 0, 0, time.UTC)
	if err := p.Allows(auto, night); err != nil {
		t.Error(err)
	}
	if err := p.Allows(auto, time.Date(2026, 11, 8, 1, 3, 0, 0, time.UTC)); err != nil {
		t.Errorf("written at the end of the window: %v", err)
	}
	os.WriteFile(path, []byte(`{"remote":"on","auto":"patch","window":"nope"}`), 0o644)
	if got := ReadPolicy(path); got != DefaultPolicy() {
		t.Errorf("a broken file: %+v", got)
	}
}

// The request lives in rayd's directory: root reads it without following
// a link and refuses what is no regular file; whatever is there goes.
func TestRequestFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-request")
	now := time.Now().UTC().Truncate(time.Second)
	r := Request{ID: NewID(), Kind: Remote, Version: "latest", By: "alice/phone", At: now}
	if err := WriteRequest(path, r, now); err != nil {
		t.Fatal(err)
	}
	if got, ok := PeekRequest(path); !ok || got != r {
		t.Fatalf("peek %+v %v", got, ok)
	}
	// One waits: another does not replace it; a stale one is replaced.
	other := Request{ID: NewID(), Kind: Auto, Version: "v0.19.1", By: "auto", At: now}
	if err := WriteRequest(path, other, now); !errors.Is(err, ErrWaiting) {
		t.Fatalf("over a waiting one: %v", err)
	}
	if err := WriteRequest(path, other, now.Add(Stale)); err != nil {
		t.Fatalf("over a stale one: %v", err)
	}
	if got, _ := PeekRequest(path); got != other {
		t.Fatalf("after %+v", got)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".update-request.*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
	got, ok, err := ReadRequest(path)
	if err != nil || !ok || got != other {
		t.Fatalf("read %+v %v %v", got, ok, err)
	}
	if err := RemoveRequest(path); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadRequest(path); ok || err != nil {
		t.Errorf("none: %v %v", ok, err)
	}
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte(`{"id":"0a","kind":"remote","version":"latest"}`), 0o600)
	os.Symlink(secret, path)
	if _, ok, err := ReadRequest(path); !ok || err == nil {
		t.Errorf("a link followed: %v %v", ok, err)
	}
	RemoveRequest(path)
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Error("the link stays")
	}
	if _, err := os.Stat(secret); err != nil {
		t.Error("the link's target went")
	}
	os.WriteFile(path, []byte(strings.Repeat("x", maxFile+1)), 0o600)
	if _, _, err := ReadRequest(path); err == nil {
		t.Error("a huge request taken")
	}
	os.Remove(path)
	// A directory planted there goes too: one request that cannot be
	// removed would keep the path unit firing.
	os.MkdirAll(filepath.Join(path, "a"), 0o700)
	os.Symlink(secret, filepath.Join(path, "a", "l"))
	if _, ok, err := ReadRequest(path); !ok || err == nil {
		t.Errorf("a directory: %v %v", ok, err)
	}
	if err := RemoveRequest(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Error("the directory stays")
	}
	if _, err := os.Stat(secret); err != nil {
		t.Error("a link's target in it went")
	}
}

func TestResultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	if _, ok := ReadResult(path); ok {
		t.Fatal("no file")
	}
	r := Result{State: RolledBack, Version: "v0.19.0", Error: strings.Repeat("e", 2*maxError)}
	if err := WriteResult(path, r); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadResult(path)
	if !ok || got.State != RolledBack || got.Version != "v0.19.0" || len(got.Error) > maxError+len("…") {
		t.Fatalf("read %+v %v", got, ok)
	}
	os.WriteFile(path, []byte(`{"state":"great"}`), 0o600)
	if _, ok := ReadResult(path); ok {
		t.Error("an unknown state taken")
	}
	// The reason: a code, kept as long as it has the form of one, also one
	// this version does not know (a newer rayctl's, for an older runner).
	for reason, want := range map[string]string{
		ReasonDownload:            ReasonDownload,
		"mirror_gone":             "mirror_gone",
		"Download":                "",
		"down load":               "",
		"ssh\n":                   "",
		"_x":                      "",
		"v2":                      "",
		strings.Repeat("a", 33):   "",
		"signature\x1b[2J":        "",
		strings.Repeat("é", 2000): "",
	} {
		if err := WriteResult(path, Result{State: Failed, Untouched: true, Reason: reason}); err != nil {
			t.Fatal(err)
		}
		if got, ok := ReadResult(path); !ok || got.Reason != want || !got.Untouched {
			t.Errorf("reason %q: read %+v %v", reason, got, ok)
		}
	}
	// What the rayctl of an older release writes, with no reason, reads as
	// none.
	os.WriteFile(path, []byte(`{"state":"failed","version":"v0.27.0","release":"v0.28.0","error":"no SHA256SUMS","untouched":true}`+"\n"), 0o600)
	if got, ok := ReadResult(path); !ok || got.State != Failed || got.Reason != "" || !got.Untouched || got.Release != "v0.28.0" {
		t.Errorf("an older result: %+v %v", got, ok)
	}
}

// The codes are what ValidReason takes, and none twice.
func TestReasons(t *testing.T) {
	codes := []string{ReasonPolicy, ReasonStale, ReasonVersion, ReasonBusy, ReasonUnfinished, ReasonBundle, ReasonSSH, ReasonDownload,
		ReasonSignature, ReasonPlace, ReasonInstall, ReasonCheck, ReasonInterrupted, ReasonOpen, ReasonNotTaken}
	seen := map[string]bool{}
	for _, c := range codes {
		if !ValidReason(c) || c == "" || seen[c] {
			t.Errorf("code %q", c)
		}
		seen[c] = true
	}
	if !ValidReason("") {
		t.Error("none is no reason")
	}
	if ReasonOf(nil) != "" || ReasonOf(errors.New("x")) != "" {
		t.Error("a reason from nowhere")
	}
	// Wrapped or joined, as the runner reports it.
	err := errors.Join(fmt.Errorf("the request: %w", refused(ReasonStale, errors.New("too old"))), errors.New("disk full"))
	if ReasonOf(err) != ReasonStale || !strings.Contains(err.Error(), "too old") {
		t.Errorf("joined: %v %q", err, ReasonOf(err))
	}
}

// The status replaces a link instead of writing through it.
func TestStatusFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	if s := ReadStatus(path); s.State != Idle {
		t.Fatalf("no file: %+v", s)
	}
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("keep"), 0o600)
	os.Symlink(target, path)
	s := Status{ID: "0a", State: Done, From: "v0.19.0", To: "v0.19.1"}
	if err := WriteStatus(path, s); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("written through a link")
	}
	if got := ReadStatus(path); got.State != Done || got.To != "v0.19.1" {
		t.Fatalf("read %+v", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode())
	}
	// A relay's: of kind exit, with where it failed and whether an update
	// of it did not end.
	relay := Status{ID: "0b", State: Failed, From: "v0.27.0", To: "v0.27.0", Target: "v0.28.0", Release: "v0.28.0", By: "exit", Kind: Exit,
		Error: "an earlier update did not end", Untouched: true, Reason: ReasonUnfinished, Unfinished: true}
	if err := WriteStatus(path, relay); err != nil {
		t.Fatal(err)
	}
	if got := ReadStatus(path); got.Kind != Exit || got.Reason != ReasonUnfinished || !got.Unfinished || !got.Untouched {
		t.Fatalf("a relay's: %+v", got)
	}
	// An update by hand on the node the relays do not follow
	// (rayctl update -no-relays).
	local := Status{ID: "0c", State: Done, From: "v0.27.0", To: "v0.28.0", Target: "v0.28.0", Release: "v0.28.0", By: "rayctl on the node", Kind: Local,
		NoRelays: true}
	if err := WriteStatus(path, local); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); !bytes.Contains(raw, []byte(`"no_relays":true`)) {
		t.Errorf("no_relays not written: %s", raw)
	}
	if got := ReadStatus(path); got.Kind != Local || !got.NoRelays {
		t.Fatalf("an update by hand: %+v", got)
	}
	local.NoRelays = false
	WriteStatus(path, local)
	if raw, _ := os.ReadFile(path); bytes.Contains(raw, []byte(`no_relays`)) {
		t.Errorf("no_relays written when the relays follow: %s", raw)
	}
	// What the rayctl of an older release writes, with neither, reads as
	// none (raycontrol v0.27.0).
	os.Remove(path)
	os.WriteFile(path, []byte(`{"id":"6f1c0e2a9b3d4c5e","state":"done","from":"v0.26.0","to":"v0.27.0","target":"latest","release":"v0.27.0",`+
		`"by":"alice/phone (remote)","kind":"remote","held":["v0.26.1"],"requested":"2026-11-14T03:00:00Z","started":"2026-11-14T03:00:05Z",`+
		`"ended":"2026-11-14T03:02:41Z"}`+"\n"), 0o644)
	if got := ReadStatus(path); got.State != Done || got.To != "v0.27.0" || got.Reason != "" || got.Unfinished || got.NoRelays || !slices.Equal(got.Held, []string{"v0.26.1"}) ||
		got.Ended.Unix() != time.Date(2026, 11, 14, 3, 2, 41, 0, time.UTC).Unix() {
		t.Fatalf("an older status: %+v", got)
	}
	// However long the fields, and whatever JSON escapes in them, rayd
	// reads the status back.
	s.State, s.Error, s.Reason = Failed, strings.Repeat("é\x1b<&\"\\", maxFile), strings.Repeat("<", maxFile)
	s.ID, s.From, s.To, s.Target, s.Release, s.By, s.Kind = strings.Repeat("<\\", maxFile), strings.Repeat("\"", maxFile), strings.Repeat("\x00", maxFile),
		strings.Repeat(">", maxFile), strings.Repeat("&", maxFile), strings.Repeat("<", maxFile), strings.Repeat("\u2028", maxFile)
	s.Held = []string{"v0.19.1", "v0.19.2", "v0.19.3", "v0.19.4", "v0.19.5", "v0.19.6", "v0.19.7", "v0.19.8", "v0.19.9", "not one", strings.Repeat("x", maxFile)}
	if err := WriteStatus(path, s); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); bytes.Contains(raw, []byte(`\u00`)) || bytes.Contains(raw, []byte(`\u2028`)) || len(raw) > maxFile {
		t.Errorf("escapes in the status, %d bytes", len(raw))
	}
	got := ReadStatus(path)
	if got.State != Failed || !utf8.ValidString(got.Error) || strings.ContainsRune(got.Error, 0x1b) || strings.ContainsRune(got.To, 0) || got.Reason != "" {
		t.Errorf("long fields: %+v", got)
	}
	if len(got.Held) != maxHeld || got.Held[maxHeld-1] != "v0.19.9" {
		t.Errorf("held %v", got.Held)
	}
	if h := Hold(Hold(Hold(nil, "v0.19.1"), "v0.19.1"), "latest"); len(h) != 1 {
		t.Errorf("hold %v", h)
	}
}

func TestBusy(t *testing.T) {
	now := time.Now()
	if Busy(Status{State: Done}, Request{}, false, now) {
		t.Error("done is busy")
	}
	if !Busy(Status{State: Running, Started: now.Add(-time.Minute)}, Request{}, false, now) {
		t.Error("running is not busy")
	}
	dead := Status{State: Running, Started: now.Add(-Stale)}
	if Busy(dead, Request{}, false, now) {
		t.Error("a dead run is busy")
	}
	if s := Settled(dead, now); s.State != Failed || !strings.Contains(s.Error, "interrupted") {
		t.Errorf("a dead run: %+v", s)
	}
	if s := Settled(Status{State: Running, Started: now}, now); s.State != Running {
		t.Errorf("a run: %+v", s)
	}
	if !Busy(Status{State: Idle}, Request{At: now}, true, now) {
		t.Error("a waiting request is not busy")
	}
}

func TestPatchAndWindow(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v0.19.1", "v0.19.0", true},
		{"v0.19.10", "v0.19.9", true},
		{"v0.20.0", "v0.19.9", false},
		{"v1.19.1", "v0.19.0", false},
		{"v0.19.0", "v0.19.1", false},
		{"v0.19.1", "dev", false},
	} {
		if got := Patch(c.a, c.b); got != c.want {
			t.Errorf("Patch(%s, %s) = %v", c.a, c.b, got)
		}
	}
	// What the auto update leaves: a newer minor or major version.
	for _, c := range []struct{ a, b, want string }{
		{"v0.27.0", "v0.26.3", "minor"},
		{"v0.30.1", "v0.26.0", "minor"},
		{"v1.0.0", "v0.26.0", "major"},
		{"v0.26.4", "v0.26.3", ""},
		{"v0.26.0", "v0.27.0", ""},
		{"v0.27.0", "v0.27.0", ""},
		{"v0.27.0", "dev", ""},
		{"", "v0.26.0", ""},
	} {
		if got := Step(c.a, c.b); got != c.want {
			t.Errorf("Step(%s, %s) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
	at := func(h, m int) time.Time { return time.Date(2026, 11, 8, h, m, 0, 0, time.UTC) }
	for _, c := range []struct {
		w    string
		t    time.Time
		want bool
	}{
		{"03:00-05:00", at(3, 0), true},
		{"03:00-05:00", at(4, 59), true},
		{"03:00-05:00", at(5, 0), false},
		{"03:00-05:00", at(2, 59), false},
		{"23:30-01:00", at(23, 45), true},
		{"23:30-01:00", at(0, 30), true},
		{"23:30-01:00", at(1, 0), false},
		{"3:00-5:00", at(3, 30), false},
		{"03:00-03:00", at(3, 0), false},
		{"03:00-03:20", at(3, 10), false}, // shorter than MinWindow
		{"23:50-00:20", at(0, 10), true},
	} {
		if got := InWindow(c.t, c.w); got != c.want {
			t.Errorf("InWindow(%s, %s) = %v", c.t.Format("15:04"), c.w, got)
		}
	}
	for _, c := range []struct {
		w    string
		t    time.Time
		want time.Duration
	}{
		{"03:00-05:00", at(3, 0), 2 * time.Hour},
		{"03:00-05:00", at(4, 30), 30 * time.Minute},
		{"03:00-05:00", at(5, 0), 0},
		{"23:30-01:00", at(23, 30), 90 * time.Minute},
		{"23:30-01:00", at(0, 45), 15 * time.Minute},
		{"23:30-01:00", at(22, 0), 0},
	} {
		if got := Left(c.t, c.w); got != c.want {
			t.Errorf("Left(%s, %s) = %v, want %v", c.t.Format("15:04"), c.w, got, c.want)
		}
	}
}

// What a request goes for, and what the next status holds.
func TestTriedAndHolding(t *testing.T) {
	for _, c := range []struct {
		r    Request
		want string
	}{
		{Request{Version: "v0.19.2"}, "v0.19.2"},
		{Request{Version: "latest", Release: "v0.19.3"}, "v0.19.3"},
		{Request{Version: "latest"}, ""},
		{Request{Version: "latest", Release: "../x"}, ""},
	} {
		if got := c.r.Tried(); got != c.want {
			t.Errorf("%+v: %q", c.r, got)
		}
	}
	if h := (Status{State: Running, Release: "v0.19.3", Held: []string{"v0.19.1"}}).Holding(); !slices.Equal(h, []string{"v0.19.1", "v0.19.3"}) {
		t.Errorf("a run that never ended: %v", h)
	}
	if h := (Status{State: Done, Release: "v0.19.3", Held: []string{"v0.19.1"}}).Holding(); !slices.Equal(h, []string{"v0.19.1"}) {
		t.Errorf("done: %v", h)
	}
	if err := (Request{ID: NewID(), Kind: Remote, Version: "latest", Release: "v1", By: "x", At: time.Now()}).Check(NodeKinds, "v0.19.0", nil, time.Now()); err == nil {
		t.Error("a release hint that is no release")
	}
}

// On the nights the clock moves the window is what the node's clock reads,
// and Left is real time: every moment before t+Left(t) is in the window,
// t+Left(t) is not, and no window runs longer than it is long plus the
// shift (an hour). rayd picks its moment that way and root checks it the
// same way: they agree.
func TestWindowAcrossClockChanges(t *testing.T) {
	windows := []string{"02:00-03:00", "02:00-02:30", "02:30-03:30", "01:30-02:30", "01:00-02:00", "23:30-02:30", "22:00-00:00", "23:00-00:30", "03:00-05:00"}
	for zone, days := range map[string][]string{
		"Europe/Berlin":       {"2026-03-29", "2026-10-25"},
		"America/New_York":    {"2026-03-08", "2026-11-01"},
		"America/Santiago":    {"2026-04-05", "2026-09-06"},
		"Australia/Lord_Howe": {"2026-04-05", "2026-10-04"},
	} {
		loc, err := time.LoadLocation(zone)
		if err != nil {
			t.Fatal(err)
		}
		for _, day := range days {
			d, _ := time.ParseInLocation("2006-01-02", day, loc)
			for _, w := range windows {
				from, to, _ := ParseWindow(w)
				long := time.Duration((to-from+24*60)%(24*60)) * time.Minute
				for at := d.Add(-24 * time.Hour); at.Before(d.Add(48 * time.Hour)); at = at.Add(time.Minute) {
					left := Left(at, w)
					if !InWindow(at, w) {
						if left != 0 {
							t.Fatalf("%s %s %s at %s: outside, %v left", zone, day, w, at, left)
						}
						continue
					}
					if left <= 0 || left > long+time.Hour {
						t.Fatalf("%s %s %s at %s: %v left", zone, day, w, at, left)
					}
					for x := time.Duration(0); x < left; x += time.Minute {
						if !InWindow(at.Add(x), w) {
							t.Fatalf("%s %s %s: at %s with %v left, %s is outside", zone, day, w, at, left, at.Add(x))
						}
					}
					if InWindow(at.Add(left), w) {
						t.Fatalf("%s %s %s: at %s, still in the window after %v", zone, day, w, at, left)
					}
				}
			}
		}
	}
	// The night the clock goes forward in Berlin (02:00 → 03:00): at 01:45
	// the window 01:30-02:30 has a quarter of an hour left, a moment picked
	// then is in it for root too.
	berlin, _ := time.LoadLocation("Europe/Berlin")
	at := time.Date(2026, 3, 29, 1, 45, 0, 0, berlin)
	if got := Left(at, "01:30-02:30"); got != 15*time.Minute {
		t.Errorf("spring forward: %v left at 01:45", got)
	}
	if err := (Policy{Remote: "off", Auto: "patch", Window: "01:30-02:30"}).Allows(Request{Kind: Auto}, at.Add(14*time.Minute)); err != nil {
		t.Errorf("spring forward, a moment rayd may pick: %v", err)
	}
	// In New York the hour before the jump is there: 01:00-02:00 runs.
	ny, _ := time.LoadLocation("America/New_York")
	if got := Left(time.Date(2026, 3, 8, 1, 0, 0, 0, ny), "01:00-02:00"); got != time.Hour {
		t.Errorf("New York, spring forward: %v left at 01:00", got)
	}
}
