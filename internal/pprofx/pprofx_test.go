package pprofx

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func TestStart(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv(Env, "")
	if err := Start(log); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"0.0.0.0:6060", ":6060", "192.0.2.1:6060", "nonsense"} {
		t.Setenv(Env, bad)
		if err := Start(log); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	sock := filepath.Join(t.TempDir(), "pprof.sock")
	t.Setenv(Env, "unix:"+sock)
	if err := Start(log); err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{Dial: func(string, string) (net.Conn, error) { return net.Dial("unix", sock) }}}
	resp, err := c.Get("http://x/debug/pprof/goroutine?debug=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
