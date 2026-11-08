package nodeupdate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRequestCheck(t *testing.T) {
	ok := Request{ID: NewID(), Kind: Remote, Version: "v0.19.1", By: "alice/phone (remote)"}
	if err := ok.Check("v0.19.0"); err != nil {
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
	} {
		if err := c.r(ok).Check("v0.19.0"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.r(ok), err, c.want)
		}
	}
	if err := (Request{ID: NewID(), Kind: Remote, Version: "latest"}).Check("v0.19.0"); err != nil {
		t.Errorf("latest: %v", err)
	}
	if err := (Request{ID: NewID(), Kind: Auto, Version: "v0.19.4"}).Check("v0.19.0"); err != nil {
		t.Errorf("a patch: %v", err)
	}
}

// The request lives in rayd's directory: root reads it without following
// a link, takes it away, and refuses what is no regular file.
func TestRequestFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-request")
	r := Request{ID: NewID(), Kind: Remote, Version: "latest", By: "alice/phone", At: time.Now().UTC().Truncate(time.Second)}
	if err := WriteRequest(path, r); err != nil {
		t.Fatal(err)
	}
	if got, ok := PeekRequest(path); !ok || got != r {
		t.Fatalf("peek %+v %v", got, ok)
	}
	got, ok, err := TakeRequest(path)
	if err != nil || !ok || got != r {
		t.Fatalf("take %+v %v %v", got, ok, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the request stays after it was taken")
	}
	if _, ok, err := TakeRequest(path); ok || err != nil {
		t.Errorf("none: %v %v", ok, err)
	}
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte(`{"id":"0a","kind":"remote","version":"latest"}`), 0o600)
	os.Symlink(secret, path)
	if _, ok, err := TakeRequest(path); !ok || err == nil {
		t.Errorf("a link followed: %v %v", ok, err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Error("the link stays")
	}
	os.WriteFile(path, []byte(strings.Repeat("x", maxFile+1)), 0o600)
	if _, _, err := TakeRequest(path); err == nil {
		t.Error("a huge request taken")
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
}

func TestBusy(t *testing.T) {
	now := time.Now()
	if Busy(Status{State: Done}, Request{}, false, now) {
		t.Error("done is busy")
	}
	if !Busy(Status{State: Running, Started: now.Add(-time.Minute)}, Request{}, false, now) {
		t.Error("running is not busy")
	}
	if Busy(Status{State: Running, Started: now.Add(-3 * time.Hour)}, Request{}, false, now) {
		t.Error("a dead run is busy")
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
	} {
		if got := InWindow(c.t, c.w); got != c.want {
			t.Errorf("InWindow(%s, %s) = %v", c.t.Format("15:04"), c.w, got)
		}
	}
}
