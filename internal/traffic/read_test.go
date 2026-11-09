package traffic

import (
	"bufio"
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

func TestParseLine(t *testing.T) {
	r, err := parseLine([]byte(`{"v":1,"boot":"0123456789abcdef","users":{"u5":{"up":1,"down":2},"u5-n":{"up":-3,"down":4}}}` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Boot != "0123456789abcdef" || !r.Start.IsZero() || r.Users["u5"] != (store.TrafficCounter{Up: 1, Down: 2}) ||
		r.Users["u5-n"] != (store.TrafficCounter{Up: 0, Down: 4}) {
		t.Fatalf("%+v", r)
	}
	// The connection limits' refusals (rayd naive from v0.24.0): beside
	// the bytes; a reading without them has none.
	r, err = parseLine([]byte(`{"v":1,"boot":"b","users":{"u5-ab":{"up":1,"down":2}},"limit":{"u5":{"tcp":3,"lookup":1}}}`))
	if err != nil || r.Limits["u5"]["tcp"] != 3 || r.Limits["u5"]["lookup"] != 1 || len(r.Users) != 1 {
		t.Fatalf("limits: %+v %v", r, err)
	}
	if r, _ := parseLine([]byte(`{"v":1,"boot":"b","users":{}}`)); r.Limits != nil || r.AgeKnown {
		t.Fatalf("no limits, no uptime: %+v", r)
	}
	// How long the process has run (rayd naive from v0.24.0), in seconds;
	// 0 is known, a negative one is not.
	for line, want := range map[string]time.Duration{`"uptime":0`: 0, `"uptime":95`: 95 * time.Second, `"uptime":-1`: -1} {
		r, err := parseLine([]byte(`{"v":1,"boot":"b","users":{},` + line + `}`))
		if err != nil || (want >= 0) != r.AgeKnown || want >= 0 && r.Age != want {
			t.Errorf("%s: %+v %v", line, r, err)
		}
	}
	if _, err := parseLine([]byte(`{"v":1,"boot":"b","users":{},"limit":{"u5":{"a":1,"b":1,"c":1,"d":1,"e":1,"f":1,"g":1,"h":1,"i":1,"j":1,"k":1,"l":1,"m":1,"n":1,"o":1,"p":1,"q":1}}}`)); err == nil {
		t.Error("too many kinds accepted")
	}
	// No users yet: an empty reading, not an error.
	if r, err := parseLine([]byte(`{"v":1,"boot":"b","users":{}}`)); err != nil || len(r.Users) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	for name, body := range map[string]string{
		"nothing (niko-server before v0.15.0)": "",
		"version 2":                            `{"v":2,"boot":"b","users":{}}`,
		"no boot":                              `{"v":1,"users":{}}`,
		"a long boot":                          `{"v":1,"boot":"` + strings.Repeat("b", 65) + `","users":{}}`,
		"a boot with a newline":                `{"v":1,"boot":"a\nb","users":{}}`,
		"an Xray boot":                         `{"v":1,"boot":"xray:1","users":{}}`,
		"not JSON":                             "rtt 12",
		"a value past int64":                   `{"v":1,"boot":"b","users":{"u1":{"up":99999999999999999999,"down":0}}}`,
		"a value of another type":              `{"v":1,"boot":"b","users":{"u1":{"up":"1","down":0}}}`,
		"too large":                            `{"v":1,"boot":"b","users":{"u1":{"up":1,"down":1}},"pad":"` + strings.Repeat("x", maxAnswer) + `"}`,
	} {
		if _, err := parseLine([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "bbbbbbbb") {
			t.Errorf("%s: the boot echoed: %v", name, err)
		}
	}
	if _, err := parseLine(nil); !errors.Is(err, ErrNoCounters) {
		t.Errorf("empty: %v", err)
	}
	// Too many names.
	var b strings.Builder
	b.WriteString(`{"v":1,"boot":"b","users":{`)
	for i := range maxNames + 1 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"x` + itoa(int64(i)) + `":{}`)
	}
	b.WriteString(`}}`)
	if _, err := parseLine([]byte(b.String())); err == nil {
		t.Error("too many names accepted")
	}
}

// serve answers each connection to a unix socket with answer, after
// reading its line.
func serve(t *testing.T, answer func(c net.Conn, line string)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stats.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				answer(c, line)
			}()
		}
	}()
	return path
}

func TestReadLine(t *testing.T) {
	ctx := context.Background()
	path := serve(t, func(c net.Conn, line string) {
		if line == "traffic\n" {
			_, _ = c.Write([]byte(`{"v":1,"boot":"b1","users":{"u1":{"up":5,"down":6}}}` + "\n"))
		}
	})
	r, err := ReadLine(ctx, path)
	if err != nil || r.Boot != "b1" || r.Users["u1"] != (store.TrafficCounter{Up: 5, Down: 6}) {
		t.Fatalf("%+v %v", r, err)
	}
	// An old niko-server: it reads the line as an address and closes.
	old := serve(t, func(net.Conn, string) {})
	if _, err := ReadLine(ctx, old); !errors.Is(err, ErrNoCounters) {
		t.Fatalf("old: %v", err)
	}
	// One that never answers holds the poll 2 s at most.
	stuck := serve(t, func(net.Conn, string) { time.Sleep(10 * time.Second) })
	start := time.Now()
	if _, err := ReadLine(ctx, stuck); err == nil || time.Since(start) > readWait+time.Second {
		t.Fatalf("stuck: %v after %v", err, time.Since(start))
	}
	// One that sends without end is cut at the bound.
	flood := serve(t, func(c net.Conn, _ string) {
		buf := []byte(strings.Repeat(" ", 64<<10))
		for {
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	})
	if _, err := ReadLine(ctx, flood); err == nil {
		t.Fatal("flood accepted")
	}
	if _, err := ReadLine(ctx, filepath.Join(t.TempDir(), "none.sock")); err == nil {
		t.Fatal("no socket")
	}
}

// A process that does not run is told apart from one that answers wrong:
// no socket, or a socket nobody listens on.
func TestNotRunning(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if _, err := ReadLine(ctx, filepath.Join(dir, "none.sock")); !notRunning(err) {
		t.Errorf("no socket: %v", err)
	}
	if _, err := ReadXray(ctx, filepath.Join(dir, "none.sock")); !notRunning(err) {
		t.Errorf("no Xray: %v", err)
	}
	stale := filepath.Join(dir, "stale.sock")
	ln, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	if _, err := ReadLine(ctx, stale); !notRunning(err) {
		t.Errorf("a stale socket: %v", err)
	}
	if _, err := ReadXray(ctx, stale); !notRunning(err) {
		t.Errorf("a stale Xray socket: %v", err)
	}
	old := serve(t, func(net.Conn, string) {})
	if _, err := ReadLine(ctx, old); err == nil || notRunning(err) {
		t.Errorf("an old niko-server: %v", err)
	}
}

const (
	bootA = "6c0b4e8e-8f7a-4f4e-9d2c-1a2b3c4d5e6f"
	bootB = "0d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6"
)

func TestSameBoot(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"0123456789abcdef", "0123456789abcdef", true},
		{"0123456789abcdef", "0123456789abcdee", false},
		{"xray:1767225600", "xray:1767225605", true},
		{"xray:1767225600", "xray:1767225606", false},
		{"xray:1767225605", "xray:1767225600", true},
		{"xray:1767225600", "1767225600", false},
		{"xray:-9223372036854775808", "xray:9223372036854775807", false},
		{"xray:x", "xray:y", false},
		// With the kernel's boot: the monotonic start decides, the wall
		// one (stepped) does not; another boot is another run.
		{"xray:1767225600:" + bootA + ":3600", "xray:1767232800:" + bootA + ":3604", true},
		{"xray:1767225600:" + bootA + ":3600", "xray:1767225600:" + bootA + ":3606", false},
		{"xray:1767225600:" + bootA + ":3600", "xray:1767225600:" + bootB + ":3600", false},
		// One without it: the wall clock, as before.
		{"xray:1767225600:" + bootA + ":3600", "xray:1767225603", true},
		{"xray:1767225600:" + bootA + ":3600", "xray:1767232800", false},
		{"xray:1767225600::3600", "xray:1767225600::3601", false}, // no boot: unreadable
		{"xray:1767225600:" + bootA, "xray:1767225600:" + bootA + ":1", false},
		{"xray:1767225600:" + bootA + ":-1", "xray:1767225600:" + bootA + ":0", false},
		{"xray:1767225600:" + bootA + ":1:2", "xray:1767225600:" + bootA + ":1", false},
	} {
		if got := SameBoot(c.a, c.b); got != c.same {
			t.Errorf("SameBoot(%s, %s) = %v", c.a, c.b, got)
		}
	}
}
