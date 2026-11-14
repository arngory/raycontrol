package naive

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/arngory/raycontrol/internal/site"
)

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

// A peer without a password cannot make the process hold its upload
// windows. With -answer silent the site's answer holds each request for
// site.SilentHold and reads no body: before it gave the body up, a peer
// that sent a connection's window (8 MiB) on a few requests held that much
// of the process for a minute, on each of its connections. Now what it
// sends is dropped as it comes and the connection's window goes back. The
// requests are held for the whole of the test: the hold ends with the
// test's server.
func TestSilentAnswerKeepsNoBody(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12"})
	answer, _ := site.Responder(site.AnswerSilent, "")
	h := &Server{Users: &Users{Path: users}, Answer: answer, Log: slog.New(slog.DiscardHandler)}
	url := serveNaive(t, h)
	before := heapInUse()
	p := newH2Peer(t, url)
	eventually(t, "no SETTINGS", func() bool { _, ok := p.setting(http2.SettingInitialWindowSize); return ok })
	eventually(t, "no window", func() bool { return p.window(0) > 0 })
	sent := 0
	chunk := make([]byte, 16<<10)
	for i := range 4 {
		stream := uint32(1 + 2*i)
		// A naive CONNECT with a password the node does not know.
		p.headers(t, stream, false, [2]string{":method", "CONNECT"}, [2]string{":authority", "192.0.2.1:443"},
			[2]string{"padding", paddingHeader()}, [2]string{"proxy-authorization", "Basic bmlrbzp3cm9uZw=="})
		// The request is in the handler's hands before its body comes, as
		// it is for any peer but one that races for it.
		time.Sleep(50 * time.Millisecond)
		d := &h2Data{p: p, stream: stream, room: site.StreamWindow}
		for {
			n, err := d.Write(chunk)
			sent += n
			if err != nil {
				if !errors.Is(err, io.ErrShortWrite) {
					t.Fatal(err)
				}
				break
			}
		}
	}
	if sent != site.ConnWindow {
		t.Fatalf("sent %d, want the whole connection window %d", sent, site.ConnWindow)
	}
	// The requests are still held (no answer, no reset), their bodies are
	// not: the connection's window is back but for Go's last few
	// kilobytes, and the heap did not grow by them.
	eventually(t, "the connection's window did not come back", func() bool {
		return p.window(0)+65535-site.ConnWindow >= int64(sent)-64<<10
	})
	p.mu.Lock()
	ended, status := p.ended, len(p.status)
	p.mu.Unlock()
	if ended != "" || status != 0 {
		t.Errorf("the silent answer said something: %q, %d answers", ended, status)
	}
	if held := int64(heapInUse()) - int64(before); held > 2<<20 {
		t.Errorf("the process holds %d KiB for %d bytes a peer without a password sent", held>>10, sent)
	}
	// The stream's window is not given back: a stream's window is all a
	// peer can send on a request that is held.
	if got := p.window(1); got != 0 {
		t.Errorf("%d bytes of a held stream's window came back", got)
	}
}
