package nodeupdate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestRequestCheck(t *testing.T) {
	now := time.Now()
	ok := Request{ID: NewID(), Kind: Remote, Version: "v0.19.1", By: "alice/phone (remote)", At: now.Add(-time.Second)}
	if err := ok.Check("v0.19.0", now); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		r    func(Request) Request
		want string
	}{
		{func(r Request) Request { r.ID = ""; return r }, "no id"},
		{func(r Request) Request { r.ID = "../../x"; return r }, "no id"},
		{func(r Request) Request { r.Kind = "root"; return r }, "kind"},
		{func(r Request) Request { r.Version = "v0.19"; return r }, "latest or vX.Y.Z"},
		{func(r Request) Request { r.Version = "v0.18.1"; return r }, "never goes back"},
		{func(r Request) Request { r.Version = "v0.19.0"; return r }, "never goes back"},
		{func(r Request) Request { r.Kind = Auto; r.Version = "v0.20.0"; return r }, "patch releases"},
		{func(r Request) Request { r.Kind = Auto; r.Version = "latest"; return r }, "patch releases"},
		{func(r Request) Request { r.By = ""; return r }, "no one"},
		{func(r Request) Request { r.By = "alice\nraycontrol v9.9.9 is running"; return r }, "no one"},
		{func(r Request) Request { r.By = "\x1b[2Jalice"; return r }, "no one"},
		{func(r Request) Request { r.By = strings.Repeat("a", maxField+1); return r }, "no one"},
		{func(r Request) Request { r.At = now.Add(-Stale - time.Minute); return r }, "too old"},
		{func(r Request) Request { r.At = now.Add(time.Hour); return r }, "too old"},
	} {
		if err := c.r(ok).Check("v0.19.0", now); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.r(ok), err, c.want)
		}
	}
	if err := (Request{ID: NewID(), Kind: Remote, Version: "latest", By: "alice/phone (remote)", At: now}).Check("v0.19.0", now); err != nil {
		t.Errorf("latest: %v", err)
	}
	if err := (Request{ID: NewID(), Kind: Auto, Version: "v0.19.4", By: "auto", At: now}).Check("v0.19.0", now); err != nil {
		t.Errorf("a patch: %v", err)
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
	remote, auto := Request{Kind: Remote}, Request{Kind: Auto}
	if DefaultPolicy().Allows(remote, at) == nil || DefaultPolicy().Allows(auto, at) == nil {
		t.Fatal("the default allows")
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
	if err := p.Allows(auto, at); err == nil {
		t.Error("auto outside the window")
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
	// However long the fields, and whatever JSON escapes in them, rayd
	// reads the status back.
	s.State, s.Error = Failed, strings.Repeat("é\x1b<&\"\\", maxFile)
	s.ID, s.From, s.To, s.Target, s.Release, s.By, s.Kind = strings.Repeat("<\\", maxFile), strings.Repeat("\"", maxFile), strings.Repeat("\x00", maxFile),
		strings.Repeat(">", maxFile), strings.Repeat("&", maxFile), strings.Repeat("<", maxFile), strings.Repeat("\u2028", maxFile)
	s.Held = []string{"v0.19.1", "v0.19.2", "v0.19.3", "v0.19.4", "v0.19.5", "v0.19.6", "v0.19.7", "v0.19.8", "v0.19.9", "not one", strings.Repeat("x", maxFile)}
	if err := WriteStatus(path, s); err != nil {
		t.Fatal(err)
	}
	got := ReadStatus(path)
	if got.State != Failed || !utf8.ValidString(got.Error) || strings.ContainsRune(got.Error, 0x1b) || strings.ContainsRune(got.To, 0) {
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
	// The night the clock goes forward (Berlin, 2026-03-29, 02:00 → 03:00):
	// the window 01:30-02:30 ends an hour of real time after it opened.
	if berlin, err := time.LoadLocation("Europe/Berlin"); err == nil {
		t0 := time.Date(2026, 3, 29, 1, 45, 0, 0, berlin)
		if got := Left(t0, "01:30-02:30"); got > 45*time.Minute || got <= 0 {
			t.Errorf("spring forward: %v left at 01:45", got)
		}
		if at := t0.Add(30 * time.Minute); !InWindow(at, "01:30-02:30") { // 03:15 on the clock
			t.Errorf("spring forward: not in the window at %s, a moment picked at 01:45", at.Format("15:04"))
		}
		if InWindow(t0.Add(time.Hour), "01:30-02:30") {
			t.Errorf("spring forward: in the window at %s", t0.Add(time.Hour).Format("15:04"))
		}
	}
}
