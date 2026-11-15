package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/release"
)

// errReady stands for the update: a request that gets this far passed all
// of root's checks, and nothing runs.
var errReady = errors.New("ready: the update would run now")

// FuzzUpdateRequest is rayctl update -request as root runs it, on a node
// and on a relay, with whatever rayd (rayd relay) left at the request's
// path, a file or a directory, and whatever root's policy file holds. The
// request goes, always (else the path unit fires again); a status is
// written for it, printable and within its bounds, failed and untouched
// unless the update would run; and only a request that root's rules take
// gets that far: of the host's kind, a release newer than this one by its
// numbers (latest on a node), on a relay not below the release a relay
// updates from, remote on for it (auto in its window), and never one that
// the status holds, on a relay.
func FuzzUpdateRequest(f *testing.F) {
	at := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	for _, s := range []struct {
		req     string
		relay   bool
		dir     bool
		policy  string
		install uint8
	}{
		{`{"id":"6f1c0e2a9b3d4c5e","kind":"remote","version":"latest","by":"alice/phone (remote)","at":"` + at + `"}`, false, false,
			`{"remote":"on","auto":"off","window":"03:00-05:00"}`, 0},
		{`{"id":"6f1c0e2a9b3d4c5e","kind":"remote","version":"v0.28.1","by":"alice/phone (remote)","at":"` + at + `"}`, false, false,
			`{"remote":"off","auto":"off","window":"03:00-05:00"}`, 0},
		{`{"id":"0a","kind":"auto","version":"v0.28.1","by":"auto","at":"` + at + `"}`, false, false,
			`{"remote":"off","auto":"patch","window":"00:00-23:59"}`, 0},
		{`{"id":"0b","kind":"exit","version":"v0.28.1","by":"exit","at":"` + at + `"}`, true, false,
			`{"remote":"on","auto":"off","window":"03:00-05:00"}`, 0},
		{`{"id":"0b","kind":"exit","version":"v0.25.9","by":"exit","at":"` + at + `"}`, true, false,
			`{"remote":"on","auto":"off","window":"03:00-05:00"}`, 2},
		{`{"id":"0b","kind":"remote","version":"latest","by":"exit","at":"` + at + `"}`, true, false,
			`{"remote":"on","auto":"off","window":"03:00-05:00"}`, 0},
		{`{"id":"0c","kind":"exit","version":"v0.28.1","by":"\u202eexit","at":"` + at + `"}`, true, false, `{"remote":"on"}`, 0},
		{``, false, true, ``, 0},
		{`{"id":"` + strings.Repeat("0", 40) + `","kind":"\u0000","version":"` + strings.Repeat("é", 300) + `"}`, true, false, `nope`, 1},
	} {
		f.Add([]byte(s.req), s.relay, s.dir, []byte(s.policy), s.install)
	}
	installed := []string{"v0.28.0", "v0.27.3", "dev", "v0.25.0"}
	saved := version
	f.Cleanup(func() { version = saved })
	f.Fuzz(func(t *testing.T, raw []byte, relay, dir bool, policy []byte, inst uint8) {
		version = installed[int(inst)%len(installed)]
		d := t.TempDir()
		q := requests{request: filepath.Join(d, "update-request"), status: filepath.Join(d, "status", "status.json"),
			policy: filepath.Join(d, "status", "policy.json"), result: filepath.Join(d, "status", "result.json"),
			ready: func() error { return errReady }, nodeVersion: func() string { return version }, kinds: nodeupdate.NodeKinds}
		if relay {
			q.kinds, q.target = nodeupdate.RelayKinds, relayTarget
			q.relay = &relayRunner{mark: func() (relayMark, bool) { return relayMark{}, false }}
		}
		// What a run before left: a release held.
		if err := nodeupdate.WriteStatus(q.status, nodeupdate.Status{ID: "0a", State: nodeupdate.RolledBack, Held: []string{"v0.28.2"}}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(q.policy, policy, 0o600); err != nil {
			t.Fatal(err)
		}
		if dir {
			if err := os.MkdirAll(filepath.Join(q.request, "x"), 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(q.request, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		err := q.run()
		if _, serr := os.Lstat(q.request); !os.IsNotExist(serr) {
			t.Fatalf("the request stays: %v", serr)
		}
		st := nodeupdate.ReadStatus(q.status)
		for _, v := range []string{st.ID, st.State, st.From, st.To, st.Target, st.Release, st.By, st.Kind, st.Error} {
			if !utf8.ValidString(v) || nodeupdate.Printable(v) != v || len(v) > 512+len("…") {
				t.Fatalf("status field %q", v)
			}
		}
		if !slices.Contains(st.Held, "v0.28.2") || !nodeupdate.ValidReason(st.Reason) {
			t.Fatalf("status %+v", st)
		}
		if !errors.Is(err, errReady) {
			if err == nil || st.State != nodeupdate.Failed || !st.Untouched || st.Error == "" {
				t.Fatalf("refused (%v), status %+v", err, st)
			}
			return
		}

		// Taken: what root's rules say, from the request itself.
		var r nodeupdate.Request
		if json.Unmarshal(raw, &r) != nil {
			t.Fatalf("%q taken", raw)
		}
		p := nodeupdate.ReadPolicy(q.policy)
		switch {
		case dir:
			t.Fatal("a directory taken")
		case !slices.Contains(q.kinds, r.Kind):
			t.Fatalf("kind %q taken (relay %v)", r.Kind, relay)
		case relay && (!release.IsRelease(r.Version) || release.Newer(relayUpdateSince, r.Version) || slices.Contains(st.Held, r.Version)):
			t.Fatalf("%q taken on a relay of %s", r.Version, version)
		case r.Version != "latest" && !release.Newer(r.Version, version):
			t.Fatalf("%q taken over %s", r.Version, version)
		case (r.Kind == nodeupdate.Remote || r.Kind == nodeupdate.Exit) && p.Remote != "on", r.Kind == nodeupdate.Auto && p.Auto != "patch":
			t.Fatalf("a %s request taken with %+v", r.Kind, p)
		case st.State != nodeupdate.Failed || st.ID != r.ID || st.Kind != r.Kind:
			t.Fatalf("status %+v of %+v", st, r)
		}
	})
}
