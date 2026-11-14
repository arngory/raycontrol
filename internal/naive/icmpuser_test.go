package naive

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"testing"

	"github.com/arngory/raycontrol/internal/site"
)

// A user's ICMP limits are the user's, not a password's: the credentials
// of one user (a rotation's two, a device's own) share the streams and the
// echoes, as they share TCP's and UoT's limits; another user has their own.
func TestICMPLimitsByUser(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsersNamed(t, users, map[string]string{"pw-a": "u5-aaaa", "pw-b": "u5-bbbb", "pw-c": "u6-cccc"})
	answer, _ := site.Responder(site.Answer404, "")
	h := &Server{Users: &Users{Path: users}, Answer: answer, ICMP: true, icmpOpen: newFakeNet().open, Log: slog.New(slog.DiscardHandler)}
	url := serveNaive(t, h)
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2"},
	}}
	t.Cleanup(tr.CloseIdleConnections)
	// open is an ICMP stream of the password's, its version said.
	open := func(password string) *paddedStream {
		t.Helper()
		pr, pw := io.Pipe()
		req, _ := http.NewRequest(http.MethodConnect, url, pr)
		req.Host = ICMPName + ":0"
		req.Header.Set("Padding", paddingHeader())
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:"+password)))
		resp, err := tr.RoundTrip(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT: %v %v", resp, err)
		}
		t.Cleanup(func() { pw.Close(); resp.Body.Close() })
		s := &paddedStream{r: resp.Body, w: pw}
		_, _ = s.Write([]byte{icmpVersion}) // a stream refused is reset before it is written to
		return s
	}
	// The user's streams, between two credentials.
	for i := range icmpPerUser {
		open([]string{"pw-a", "pw-b"}[i%2])
	}
	eventually(t, "streams not counted", func() bool { return h.icmp.count() == icmpPerUser })
	for _, password := range []string{"pw-a", "pw-b"} {
		if !reset(t, open(password)) {
			t.Errorf("a stream past the user's %d was served for %s: each credential has limits of its own", icmpPerUser, password)
		}
	}
	// Another user's are their own.
	open("pw-c")
	eventually(t, "another user's stream not counted", func() bool { return h.icmp.count() == icmpPerUser+1 })
	h.icmp.mu.Lock()
	got := slices.Sorted(maps.Keys(h.icmp.users))
	h.icmp.mu.Unlock()
	if !slices.Equal(got, []string{"u5", "u6"}) {
		t.Fatalf("ICMP limits are kept for %v, want the users u5 and u6", got)
	}
}
