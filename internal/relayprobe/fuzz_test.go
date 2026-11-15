package relayprobe

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// relayReport fails t unless r is a report the exit takes (its
// checkRelayUpdate, spec/relay-update-remote-v1.md §3.6): versions of a
// release or none, a state of the protocol's, an id of 1-32 hex or none,
// a reason of a code's form, printable text of 200 bytes at most.
func relayReport(t *testing.T, r *perimeterv1.RelayUpdate) {
	t.Helper()
	states := []string{nodeupdate.Idle, nodeupdate.Requested, nodeupdate.Running, nodeupdate.Done, nodeupdate.RolledBack, nodeupdate.Failed}
	switch {
	case r.Version != "" && !isVersion(r.Version), r.Target != "" && !isVersion(r.Target):
		t.Fatalf("report of version %q, target %q", r.Version, r.Target)
	case !strings.Contains(strings.Join(states, " ")+" ", r.State+" ") || r.State == "":
		t.Fatalf("report of state %q", r.State)
	case r.Id != "" && !validID(r.Id), !nodeupdate.ValidReason(r.Reason):
		t.Fatalf("report of id %q, reason %q", r.Id, r.Reason)
	case len(r.Error) > maxText || !utf8.ValidString(r.Error) || nodeupdate.Printable(r.Error) != r.Error:
		t.Fatalf("report of error %q", r.Error)
	}
}

// FuzzOffer: whatever the exit offers in its feed (another host's word),
// and whatever root's status and policy on the relay say, a request rayd
// relay writes for it is one root's own checks take (nodeupdate's
// Request.Check of a relay, the policy's Allows): the exit names a newer
// release that did not fail here, and no more; and the state rayd relay
// tells the exit is one the exit takes.
func FuzzOffer(f *testing.F) {
	for _, s := range []struct {
		id, version string
		rayd        uint8
		state, kind string
		target      string
		untouched   bool
		held        string
		remote      bool
		text        string
	}{
		{"6f1c0e2a9b3d4c5e", "v0.29.0", 0, "", "", "", false, "", true, ""},
		{"6f1c0e2a9b3d4c5e", "v0.29.0", 0, nodeupdate.Failed, nodeupdate.Exit, "v0.29.0", false, "v0.29.0", true, "rolled back: 198.51.100.7 refused"},
		{"6f1c0e2a9b3d4c5e", "v0.29.0", 0, nodeupdate.Failed, nodeupdate.Exit, "v0.29.0", true, "", true, "downloading SHA256SUMS: https://m.example.org/x: 502"},
		{"a1", "v0.29.0", 0, nodeupdate.Running, nodeupdate.Exit, "v0.29.0", false, "", true, ""},
		{"a1", "v0.28.0", 0, nodeupdate.Done, nodeupdate.Exit, "v0.28.0", false, "", true, ""},
		{"a1", "v0.29.01", 0, nodeupdate.Done, nodeupdate.Local, "v0.29.1", false, "v0.29.1", true, ""},
		{"A1", "v0.29.0", 1, "", "", "", false, "", true, ""},
		{"a1", "v0.29.0\n", 2, "", "", "", false, "", false, ""},
		{"../x", "-version", 3, nodeupdate.Failed, nodeupdate.Exit, "\x1b[2J", true, "", true, strings.Repeat("é\x00", 300)},
		{strings.Repeat("a", 33), "v" + strings.Repeat("9", 40) + ".0.0", 0, "", "", "", false, "", true, ""},
	} {
		f.Add(s.id, s.version, s.rayd, s.state, s.kind, s.target, s.untouched, s.held, s.remote, s.text)
	}
	versions := []string{"v0.28.0", "v0.27.3", "dev", "", "v0.29.1"}
	dir := f.TempDir()
	request, status, policy := filepath.Join(dir, "rayd-relay", "update-request"), filepath.Join(dir, "status.json"), filepath.Join(dir, "policy.json")
	if err := os.MkdirAll(filepath.Dir(request), 0o700); err != nil {
		f.Fatal(err)
	}
	now := time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, id, version string, rayd uint8, state, kind, target string, untouched bool, held string, remote bool, text string) {
		if err := os.Remove(request); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		st := nodeupdate.Status{ID: "b2", State: state, Kind: kind, From: "v0.28.0", To: target, Target: target, Release: target, Untouched: untouched,
			Error: text, Reason: nodeupdate.ReasonDownload, Requested: now.Add(-2 * time.Hour), Started: now.Add(-2 * time.Hour), Ended: now.Add(-time.Hour)}
		if held != "" {
			st.Held = strings.Split(held, ",")
		}
		if err := nodeupdate.WriteStatus(status, st); err != nil {
			t.Fatal(err)
		}
		on := map[bool]string{true: "on", false: "off"}[remote]
		if err := nodeupdate.WritePolicy(policy, nodeupdate.Policy{Remote: on, Auto: "off", Window: nodeupdate.DefaultWindow}); err != nil {
			t.Fatal(err)
		}
		u := NewUpdates(versions[int(rayd)%len(versions)], request, dir, nil)
		u.now = func() time.Time { return now }
		o := offer{id: id, version: version, some: true}
		standing := u.read(now)
		u.seed(standing, now)
		took := u.take(o, standing, now)
		req, waiting := nodeupdate.PeekRequest(request)
		switch {
		case took != waiting:
			t.Fatalf("took %v, a request there %v", took, waiting)
		case took:
			if req.ID != id || req.Version != version || req.Kind != nodeupdate.Exit {
				t.Fatalf("offer %q %q written as %+v", id, version, req)
			}
			root := nodeupdate.ReadStatus(status)
			if err := req.Check(nodeupdate.RelayKinds, u.version, root.Holding(), now); err != nil {
				t.Fatalf("offer %q %q over %s, status %+v: root refuses it: %v", id, version, u.version, root, err)
			}
			if err := nodeupdate.ReadPolicy(policy).Allows(req, now); err != nil {
				t.Fatalf("offer %q %q: the policy refuses it: %v", id, version, err)
			}
		}
		relayReport(t, u.read(now).r)
		if u.own != nil {
			relayReport(t, u.own)
		}
	})
}

// FuzzClean: root's text of a relay's update, whatever it holds, is told
// the exit as one printable line of 200 bytes at most, with no address of
// the relay's left in it (spec/relay-update-remote-v1.md §6).
func FuzzClean(f *testing.F) {
	for _, s := range []string{
		"this SSH session comes from 198.51.100.7, not from the relay's admin addresses [203.0.113.0/24 2001:db8:1::/48]",
		`downloading SHA256SUMS: Get "https://mirror.corp.example:8443/x": dial tcp: lookup mirror.corp.example on 127.0.0.53:53: no such host`,
		"the relay install: rayctl: relay_dnat to [2001:db8::7]:443\nfailed\x1b[2J: exit status 1",
		strings.Repeat("é", 255) + "…",
		"an update cut at 203.0.113.1…",
		"",
	} {
		f.Add(s, []byte{198, 51, 100, 7})
	}
	f.Fuzz(func(t *testing.T, text string, a4 []byte) {
		u := NewUpdates("v0.28.0", "", "", nil)
		var addr netip.Addr
		if len(a4) >= 4 {
			addr = netip.AddrFrom4([4]byte(a4))
			text = strings.ReplaceAll(text, "198.51.100.7", addr.String())
		}
		out := u.clean(text)
		switch {
		case len(out) > maxText || !utf8.ValidString(out) || nodeupdate.Printable(out) != out:
			t.Fatalf("%q told as %q", text, out)
		case strings.ContainsAny(out, "\n\r\t"):
			t.Fatalf("%q told on more than a line: %q", text, out)
		case text == "" && out != "":
			t.Fatalf("no text told as %q", out)
		}
		if addr.IsValid() && !addr.IsLoopback() && !addr.IsUnspecified() && strings.Contains(" "+out+" ", " "+addr.String()+" ") {
			t.Fatalf("%v left in %q", addr, out)
		}
	})
}
