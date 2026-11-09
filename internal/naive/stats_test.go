package naive_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/traffic"
)

// The stats socket speaks niko-server's traffic line, as rayd reads it;
// anything else gets nothing, and reading resets nothing.
func TestStatsSocket(t *testing.T) {
	dir := t.TempDir()
	users := filepath.Join(dir, "users.json")
	b, _ := json.Marshal(map[string]string{naive.HashPassword("pw"): "u3", naive.HashPassword("pw2"): "u3-n"})
	if err := os.WriteFile(users, b, 0o600); err != nil {
		t.Fatal(err)
	}
	u := &naive.Users{Path: users}
	if !u.Accepts("pw") {
		t.Fatal("not accepted")
	}
	sock := filepath.Join(dir, "stats.sock")
	if err := u.ServeStats(t.Context(), sock, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(sock); err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket %v %v", st, err)
	}
	r, err := traffic.ReadLine(t.Context(), sock)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Boot) != 16 || len(r.Users) != 2 || r.Users["u3"] != (store.TrafficCounter{}) {
		t.Fatalf("%+v", r)
	}
	// How long the process has run: rayd tells a new one by it.
	if !r.AgeKnown || r.Age > time.Hour {
		t.Fatalf("age %v %v", r.Age, r.AgeKnown)
	}
	again, err := traffic.ReadLine(t.Context(), sock)
	if err != nil || again.Boot != r.Boot {
		t.Fatalf("again: %+v %v", again, err)
	}
	// Another process: another boot.
	u2 := &naive.Users{Path: users}
	sock2 := filepath.Join(dir, "stats2.sock")
	if err := u2.ServeStats(t.Context(), sock2, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if r2, err := traffic.ReadLine(t.Context(), sock2); err != nil || r2.Boot == r.Boot {
		t.Fatalf("a second process: %+v %v", r2, err)
	}
	// Anything but the traffic line: closed without a word.
	for _, line := range []string{"1.2.3.4 u3\n", "TRAFFIC\n", "traffic", string(make([]byte, 300)) + "\n"} {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(c, line)
		if cw, ok := c.(*net.UnixConn); ok {
			_ = cw.CloseWrite()
		}
		got, _ := io.ReadAll(c)
		c.Close()
		if len(got) != 0 {
			t.Errorf("%q: %q", line, got)
		}
	}
}

// The refusals may be set while the socket answers (rayd sets them as the
// process starts): no race, and the next answer has them.
func TestStatsRefusedLate(t *testing.T) {
	dir := t.TempDir()
	users := filepath.Join(dir, "users.json")
	b, _ := json.Marshal(map[string]string{naive.HashPassword("pw"): "u3"})
	if err := os.WriteFile(users, b, 0o600); err != nil {
		t.Fatal(err)
	}
	u := &naive.Users{Path: users}
	sock := filepath.Join(dir, "stats.sock")
	if err := u.ServeStats(t.Context(), sock, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	read := make(chan error)
	go func() {
		defer close(read)
		for range 20 {
			if _, err := traffic.ReadLine(t.Context(), sock); err != nil {
				read <- err
				return
			}
		}
	}()
	u.SetRefused(func() map[string]map[string]int64 { return map[string]map[string]int64{"u3": {"tcp": 2}} })
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	r, err := traffic.ReadLine(t.Context(), sock)
	if err != nil || r.Limits["u3"]["tcp"] != 2 {
		t.Fatalf("%+v %v", r.Limits, err)
	}
}
