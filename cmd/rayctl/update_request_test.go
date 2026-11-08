package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/release"
)

// rayctl update -request (spec/node-update-v1.md §3): the request checked
// again on root's side against root's policy, its status written before it
// goes, the update by the installed rayctl, the outcome it wrote in the
// status file.
func TestUpdateRequest(t *testing.T) {
	saved := version
	t.Cleanup(func() { version = saved })
	version = "v0.19.0"
	dir := t.TempDir()
	statDir := filepath.Join(dir, "status")
	q := requests{request: filepath.Join(dir, "update-request"), status: filepath.Join(statDir, "status.json"),
		policy: filepath.Join(statDir, "policy.json"), result: filepath.Join(statDir, "result.json"),
		ready: func() error { return nil }, nodeVersion: func() string { return "v0.19.0" }}
	os.MkdirAll(statDir, 0o755)
	policy := func(remote, auto, window string) {
		t.Helper()
		if err := nodeupdate.WritePolicy(q.policy, nodeupdate.Policy{Remote: remote, Auto: auto, Window: window}); err != nil {
			t.Fatal(err)
		}
	}
	fake := func(script string) string {
		p := filepath.Join(t.TempDir(), "rayctl")
		os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755)
		return p
	}
	run := func(r nodeupdate.Request, rayctl string) (nodeupdate.Status, error) {
		t.Helper()
		if r.ID != "" {
			if err := nodeupdate.WriteRequest(q.request, r, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		q.rayctl = rayctl
		err := q.run()
		if _, serr := os.Lstat(q.request); !os.IsNotExist(serr) {
			t.Fatal("the request stays: the path unit would fire again")
		}
		if _, serr := os.Stat(q.result); !os.IsNotExist(serr) {
			t.Fatal("the result stays")
		}
		return nodeupdate.ReadStatus(q.status), err
	}
	req := func(kind, v string) nodeupdate.Request {
		return nodeupdate.Request{ID: nodeupdate.NewID(), Kind: kind, Version: v, By: "alice/phone (remote)", At: time.Now().UTC()}
	}
	never := fake(`echo ran >&2; exit 9`)

	// No request: nothing.
	if err := q.run(); err != nil {
		t.Fatal(err)
	}
	// Refused, with nothing run: root's policy off (whatever rayd says),
	// going back, an auto update past a patch or outside the window, a
	// stale request, a node that cannot be updated.
	policy("off", "off", nodeupdate.DefaultWindow)
	stale := req(nodeupdate.Remote, "latest")
	stale.At = stale.At.Add(-2 * time.Hour)
	inWindow := time.Now().Add(-time.Minute).Format("15:04") + "-" + time.Now().Add(time.Hour).Format("15:04")
	for _, c := range []struct {
		policy [3]string
		r      nodeupdate.Request
		ready  error
		want   string
	}{
		{[3]string{"off", "patch", inWindow}, req(nodeupdate.Remote, "latest"), nil, "remote updates are off"},
		{[3]string{"on", "off", inWindow}, req(nodeupdate.Auto, "v0.19.1"), nil, "auto updates are off"},
		{[3]string{"on", "patch", nodeupdate.DefaultWindow}, req(nodeupdate.Remote, "v0.18.1"), nil, "never goes back"},
		{[3]string{"on", "patch", inWindow}, req(nodeupdate.Auto, "v0.20.0"), nil, "patch releases"},
		{[3]string{"on", "patch", time.Now().Add(2*time.Hour).Format("15:04") + "-" + time.Now().Add(3*time.Hour).Format("15:04")},
			req(nodeupdate.Auto, "v0.19.1"), nil, "outside the window"},
		{[3]string{"on", "off", nodeupdate.DefaultWindow}, stale, nil, "too old"},
		{[3]string{"on", "off", nodeupdate.DefaultWindow}, req(nodeupdate.Remote, "latest"), errors.New("a relay host"), "a relay host"},
	} {
		policy(c.policy[0], c.policy[1], c.policy[2])
		q.ready = func() error { return c.ready }
		st, err := run(c.r, never)
		if err == nil || !strings.Contains(err.Error(), c.want) || st.State != nodeupdate.Failed || st.ID != c.r.ID ||
			!strings.Contains(st.Error, c.want) || !st.Untouched {
			t.Errorf("%+v: %v, status %+v", c.r, err, st)
		}
	}
	q.ready = func() error { return nil }
	// Something that is no request still goes: a directory planted there.
	os.MkdirAll(filepath.Join(q.request, "x"), 0o700)
	if st, err := run(nodeupdate.Request{}, never); err == nil || st.State != nodeupdate.Failed {
		t.Errorf("a directory: %v %+v", err, st)
	}

	// Done: the installed rayctl updated and said so; it saw the status
	// running, and no request.
	policy("on", "off", nodeupdate.DefaultWindow)
	args := filepath.Join(dir, "args")
	ok := fake(`echo "$@" > ` + args + `; grep -q '"running"' ` + q.status + ` && [ ! -e ` + q.request + ` ] || exit 3
echo '{"state":"done","version":"v0.19.1"}' > "$RAYCONTROL_UPDATE_RESULT"`)
	st, err := run(req(nodeupdate.Remote, "latest"), ok)
	if b, _ := os.ReadFile(args); err != nil || st.State != nodeupdate.Done || st.From != "v0.19.0" || st.To != "v0.19.1" || st.Target != "latest" ||
		strings.TrimSpace(string(b)) != "update -yes -version latest" || st.Ended.IsZero() || st.Untouched {
		t.Fatalf("done: %+v %v %q", st, err, b)
	}
	// Rolled back: the cause from the result, whatever was printed last;
	// the release it went for (an admin's latest) held from now on.
	back := fake(`echo '{"state":"rolled_back","version":"v0.19.0","release":"v0.19.3","error":"niko-front.service exited"}' > "$RAYCONTROL_UPDATE_RESULT"
echo "rayctl: the update by the rayctl of v0.19.3: exit status 1" >&2; exit 1`)
	st, err = run(req(nodeupdate.Remote, "latest"), back)
	if err == nil || st.State != nodeupdate.RolledBack || st.Error != "niko-front.service exited" || st.To != "v0.19.0" || st.Target != "latest" ||
		st.Release != "v0.19.3" || len(st.Held) != 1 || st.Held[0] != "v0.19.3" {
		t.Fatalf("rolled back: %+v %v", st, err)
	}
	// Failed before it changed anything: untouched, the auto update may
	// try again.
	dl := fake(`echo '{"state":"failed","version":"v0.19.0","error":"downloading SHA256SUMS: timeout","untouched":true}' > "$RAYCONTROL_UPDATE_RESULT"; exit 1`)
	if st, _ = run(req(nodeupdate.Remote, "v0.19.1"), dl); st.State != nodeupdate.Failed || !st.Untouched || st.Error != "downloading SHA256SUMS: timeout" ||
		st.Release != "v0.19.1" || len(st.Held) != 1 {
		t.Fatalf("download (not held; v0.19.3 still is): %+v", st)
	}
	// A refusal later does not forget what is held.
	policy("off", "off", nodeupdate.DefaultWindow)
	if st, _ = run(req(nodeupdate.Remote, "latest"), never); st.State != nodeupdate.Failed || len(st.Held) != 1 || st.Held[0] != "v0.19.3" {
		t.Fatalf("a refusal: %+v", st)
	}
	policy("on", "off", nodeupdate.DefaultWindow)
	// No result (a rayctl that died): its last words.
	died := fake(`echo "update failed: niko-front.service exited"; echo "rayctl: update failed, the previous version runs again: niko-front.service exited" >&2; exit 1`)
	if st, _ = run(req(nodeupdate.Remote, "v0.19.1"), died); st.State != nodeupdate.RolledBack || st.Error != "niko-front.service exited" || st.To != "v0.19.0" {
		t.Fatalf("no result, rolled back: %+v", st)
	}
	broken := fake(`echo "rayctl: SHA256SUMS: minisign: signed with another key" >&2; exit 1`)
	if st, _ = run(req(nodeupdate.Remote, "v0.19.1"), broken); st.State != nodeupdate.Failed || st.Error != "SHA256SUMS: minisign: signed with another key" || st.Untouched ||
		!slices.Equal(st.Held, []string{"v0.19.3", "v0.19.1"}) {
		t.Fatalf("no result, failed (held: it may have changed the node): %+v", st)
	}
	if fi, err := os.Stat(q.status); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("status file %v %v", fi, err)
	}

	// An admin's latest that dies with no result: held is the release it
	// said it verified, else what rayd saw as latest.
	os.Remove(q.status)
	l := req(nodeupdate.Remote, "latest")
	l.Release = "v0.19.4"
	diedQuiet := fake(`echo "rayctl: killed" >&2; exit 1`)
	if st, _ = run(l, diedQuiet); st.State != nodeupdate.Failed || st.Release != "v0.19.4" || !slices.Equal(st.Held, []string{"v0.19.4"}) {
		t.Fatalf("latest, no result, the hint: %+v", st)
	}
	l = req(nodeupdate.Remote, "latest")
	l.Release = "v0.19.4"
	diedLoud := fake(`echo "release v0.19.5 verified: its own rayctl updates the node"; echo "rayctl: killed" >&2; exit 1`)
	if st, _ = run(l, diedLoud); st.Release != "v0.19.5" || !slices.Equal(st.Held, []string{"v0.19.4", "v0.19.5"}) {
		t.Fatalf("latest, no result, the release verified: %+v", st)
	}
	// A run that never ended (a power cut: no result, no stop hook): the
	// next run holds its release.
	nodeupdate.WriteStatus(q.status, nodeupdate.Status{ID: "0a", State: nodeupdate.Running, Target: "latest", Release: "v0.19.6", Started: time.Now().Add(-2 * time.Hour)})
	if st, _ = run(req(nodeupdate.Remote, "v0.19.1"), ok); st.State != nodeupdate.Done || !slices.Contains(st.Held, "v0.19.6") {
		t.Fatalf("after a run that never ended: %+v", st)
	}
}

// A runner killed on the way (the unit's timeout, a shutdown): its status
// does not stay running.
func TestMarkInterrupted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	t.Setenv("SERVICE_RESULT", "timeout")
	if err := markInterrupted(path); err != nil || nodeupdate.ReadStatus(path).State != nodeupdate.Idle {
		t.Fatalf("no status: %v", err)
	}
	nodeupdate.WriteStatus(path, nodeupdate.Status{ID: "0a", State: nodeupdate.Done})
	markInterrupted(path)
	if st := nodeupdate.ReadStatus(path); st.State != nodeupdate.Done {
		t.Fatalf("done: %+v", st)
	}
	nodeupdate.WriteStatus(path, nodeupdate.Status{ID: "0a", State: nodeupdate.Running, Target: "v0.19.1", Release: "v0.19.1"})
	markInterrupted(path)
	if st := nodeupdate.ReadStatus(path); st.State != nodeupdate.Failed || !strings.Contains(st.Error, "interrupted (timeout)") || st.Ended.IsZero() || st.Untouched ||
		len(st.Held) != 1 {
		t.Fatalf("running: %+v", st)
	}
}

// A rollback by hand: the release rolled back from is held, what was held
// stays.
func TestNoteRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	nodeupdate.WriteStatus(path, nodeupdate.Status{ID: "0a", State: nodeupdate.Done, Held: []string{"v0.19.2"}})
	noteRollback(path, "v0.19.3", "v0.19.1")
	st := nodeupdate.ReadStatus(path)
	if st.State != nodeupdate.RolledBack || st.Release != "v0.19.3" || st.To != "v0.19.1" || len(st.Held) != 2 || st.Held[1] != "v0.19.3" {
		t.Fatalf("%+v", st)
	}
	none := filepath.Join(t.TempDir(), "none", "status.json")
	noteRollback(none, "v0.19.3", "v0.19.1")
	if _, err := os.Stat(filepath.Dir(none)); !os.IsNotExist(err) {
		t.Error("a status where updates by request never ran")
	}
}

// The apply an update runs does not get the update's own variables.
func TestApplyEnv(t *testing.T) {
	t.Setenv(nodeupdate.ResultEnv, "/x")
	t.Setenv(handoffEnv, "1")
	t.Setenv(updateFromEnv, "v0.19.0")
	t.Setenv(updateStageEnv, "/old")
	for _, stage := range []string{"", "/var/lib/raycontrol-install/update-1"} {
		var got []string
		for _, kv := range applyEnv(stage) {
			if strings.HasPrefix(kv, "RAYCONTROL_UPDATE") {
				got = append(got, kv)
			}
		}
		want := 0
		if stage != "" {
			want = 1
		}
		if len(got) != want || (want == 1 && got[0] != updateStageEnv+"="+stage) {
			t.Errorf("stage %q: %v", stage, got)
		}
	}
}

// What an update tells the runner (nodeupdate.ResultEnv, frozen).
func TestWriteResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	for _, c := range []struct {
		err     error
		touched bool
		want    nodeupdate.Result
	}{
		{nil, false, nodeupdate.Result{State: nodeupdate.Done, Version: "v0.19.0", Release: "v0.19.1"}}, // the newest is installed
		{nil, true, nodeupdate.Result{State: nodeupdate.Done, Version: "v0.19.1", Release: "v0.19.1"}},
		{rolledBack{errors.New("niko-front.service exited")}, true, nodeupdate.Result{State: nodeupdate.RolledBack, Version: "v0.19.0", Release: "v0.19.1", Error: "niko-front.service exited"}},
		{errors.New("downloading"), false, nodeupdate.Result{State: nodeupdate.Failed, Version: "v0.19.0", Release: "v0.19.1", Error: "downloading", Untouched: true}},
		{errors.New("x; rollback failed too: y"), true, nodeupdate.Result{State: nodeupdate.Failed, Release: "v0.19.1", Error: "x; rollback failed too: y"}},
	} {
		writeResult(path, c.err, c.touched, "v0.19.0", "v0.19.1")
		if got, ok := nodeupdate.ReadResult(path); !ok || got != c.want {
			t.Errorf("%v %v: %+v, want %+v", c.err, c.touched, got, c.want)
		}
	}
	if !strings.Contains(rolledBack{errors.New("x")}.Error(), "the previous version runs again") {
		t.Error("the rollback's words changed: runners before the result file read them")
	}
}

// A release's rayctl that does not run here (a noexec mount, another
// architecture): this rayctl updates from the same stage.
func TestHandoffFallback(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range []string{"rayctl", "rayd", "VERSIONS"} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: 4, Typeflag: tar.TypeReg})
		tw.Write([]byte("\x00ELF"))
	}
	tw.Close()
	zw.Close()
	r := release.Release{Version: "v0.19.1", Archive: buf.Bytes(), Sums: []byte("sums"), Sig: []byte("sig")}
	stage := t.TempDir()
	handed, err := handoff(r, stage, "v0.19.0", true)
	if handed || err == nil {
		t.Fatalf("a rayctl that cannot run was handed the update: %v %v", handed, err)
	}
	if _, err := release.Extract(r.Archive, stage); err != nil {
		t.Fatalf("the fallback cannot extract: %v", err)
	}
}

// The policy is root's file: rayctl update remote|auto writes it as root,
// checked; rayd only reads it.
func TestUpdatePolicyCommands(t *testing.T) {
	dir := t.TempDir()
	path, unit := filepath.Join(dir, "p", "policy.json"), filepath.Join(dir, "unit")
	c := &cli{}
	root := func() error { return nil }
	set := func(args ...string) error { return c.updatePolicyAt(context.Background(), args, path, unit, root) }
	if err := set("remote", "on"); err != nil {
		t.Fatal(err)
	}
	if err := set("auto", "patch", "-window", "23:30-01:00"); err != nil {
		t.Fatal(err)
	}
	if p := nodeupdate.ReadPolicy(path); p != (nodeupdate.Policy{Remote: "on", Auto: "patch", Window: "23:30-01:00"}) {
		t.Fatalf("policy %+v", p)
	}
	for _, bad := range [][]string{{"remote", "yes"}, {"auto", "minor"}, {"auto", "patch", "-window", "3-5"}, {"auto", "patch", "-window", "03:00-03:10"}, {"status", "x"}, {"nope"}} {
		if err := set(bad...); err == nil {
			t.Errorf("%v taken", bad)
		}
	}
	if err := set("auto", "off"); err != nil {
		t.Fatal(err)
	}
	if p := nodeupdate.ReadPolicy(path); p != (nodeupdate.Policy{Remote: "on", Auto: "off", Window: "23:30-01:00"}) {
		t.Fatalf("policy after off %+v", p)
	}
	// Not root (a member of the raycontrol group): nothing changes.
	root = func() error { return errors.New("run as root") }
	if err := set("remote", "off"); err == nil || nodeupdate.ReadPolicy(path).Remote != "on" {
		t.Fatalf("not root: %v", err)
	}
}
