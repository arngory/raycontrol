package pprofx

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestStart(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv(Env, "")
	if err := Start(log); err != nil {
		t.Fatal(err)
	}
	// Not even loopback: the data plane's processes reach it (S-2).
	for _, bad := range []string{"0.0.0.0:6060", ":6060", "192.0.2.1:6060", "127.0.0.1:6060", "[::1]:6060", "nonsense", "unix:"} {
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
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("socket %v %v", fi.Mode(), err)
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
