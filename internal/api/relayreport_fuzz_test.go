package api

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/redact"
	"github.com/arngory/raycontrol/internal/release"
)

// FuzzRelayReport: a relay's report of its update (ReportUpdate, from the
// relay's host over its client certificate: another host than the exit,
// which may be broken or taken) is kept only within §3.6's bounds, and its
// error as the exit keeps and shows it is one printable line of 200 bytes
// at most with no address of the relay's text left in it: the relay
// redacted it, and the exit does again.
func FuzzRelayReport(f *testing.F) {
	for _, u := range []*perimeterv1.RelayUpdate{
		{Version: "v0.28.0", Remote: true, State: nodeupdate.Idle},
		{Version: "v0.28.0", Remote: true, State: nodeupdate.Failed, Id: "6f1c0e2a9b3d4c5e", Target: "v0.29.0", Reason: nodeupdate.ReasonSSH,
			Error: "this SSH session comes from 198.51.100.7, not from the relay's admin addresses [203.0.113.0/24]", At: 1767225600},
		{Version: "v0.28.0", State: nodeupdate.RolledBack, Id: "a1", Target: "v0.29.0", Reason: "mirror_gone", Error: "x\x1b[2J\n y", Unfinished: true},
		{Version: "dev", State: "great", Id: "../x", Target: "latest", Reason: "Download", Error: strings.Repeat("é", 101)},
	} {
		b, err := proto.Marshal(&perimeterv1.ReportUpdateRequest{Update: u})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, []byte{198, 51, 100, 7})
	}
	f.Add([]byte(nil), []byte(nil))
	srv := &Server{}
	srv.relayUpd.red = redact.New("node.example.org")
	f.Fuzz(func(t *testing.T, raw, a4 []byte) {
		m := &perimeterv1.ReportUpdateRequest{}
		if proto.Unmarshal(raw, m) != nil {
			return
		}
		var addr netip.Addr
		if u := m.GetUpdate(); u != nil && len(a4) >= 4 {
			addr = netip.AddrFrom4([4]byte(a4))
			u.Error = strings.ReplaceAll(u.Error, "198.51.100.7", addr.String())
		}
		rec, err := checkRelayUpdate(m, func(e string) string { return srv.cleanRelayError(context.Background(), e) })
		if err != nil {
			return
		}
		u := m.GetUpdate()
		version := func(v string) bool { return v == "" || len(v) <= maxUpdateVersion && release.IsRelease(v) }
		switch {
		case proto.Size(m) > maxUpdateReport:
			t.Fatalf("a report of %d bytes taken", proto.Size(m))
		case !version(rec.Version) || !version(rec.Target):
			t.Fatalf("version %q, target %q taken", rec.Version, rec.Target)
		case !strings.Contains(" idle requested running done rolled_back failed ", " "+rec.Reported+" ") || rec.Reported == "":
			t.Fatalf("state %q taken", rec.Reported)
		case rec.UpdateID != "" && !validUpdateID(rec.UpdateID), !nodeupdate.ValidReason(rec.Reason):
			t.Fatalf("id %q, reason %q taken", rec.UpdateID, rec.Reason)
		case len(rec.Error) > maxUpdateError || !utf8.ValidString(rec.Error) || nodeupdate.Printable(rec.Error) != rec.Error:
			t.Fatalf("error %q kept of %q", rec.Error, u.Error)
		}
		if addr.IsValid() && !addr.IsLoopback() && !addr.IsUnspecified() && strings.Contains(u.Error, addr.String()) &&
			strings.Contains(" "+rec.Error+" ", " "+addr.String()+" ") {
			t.Fatalf("%v kept in %q", addr, rec.Error)
		}
	})
}
