package memlimit

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// start sets 7/8 of the cgroup's limit and logs it once; with GOMEMLIMIT,
// or without a limit below the host, it sets nothing and logs nothing.
func TestStart(t *testing.T) {
	for _, c := range []struct {
		name    string
		l       Limits
		env     string
		want    int64
		wantLog string
	}{
		{"max", Limits{Max: 512 * mib, MemTotal: 4 << 30}, "", 420 * mib,
			"memory_max=\"512 MiB\" memory_high=none host_mib=4096 go_limit_mib=420"},
		{"high", Limits{Max: 1 << 30, High: 400 * mib, MemTotal: 4 << 30}, "", 350 * mib,
			"memory_max=\"1024 MiB\" memory_high=\"400 MiB\" host_mib=4096 go_limit_mib=350"},
		{"GOMEMLIMIT", Limits{Max: 512 * mib, MemTotal: 4 << 30}, "300MiB", 0, ""},
		{"none", Limits{MemTotal: 4 << 30}, "", 0, ""},
		{"at the host", Limits{Max: 4 << 30, MemTotal: 4 << 30}, "", 3360 * mib, // 4096 / 16 * 15 = 3840; 7/8 of it
			"memory_max=\"4096 MiB\""},
		{"above the host", Limits{Max: 8 << 30, MemTotal: 4 << 30}, "", 0, ""},
	} {
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, nil))
		var set int64
		got := start(log, c.l, func(k string) string {
			if k == "GOMEMLIMIT" {
				return c.env
			}
			return ""
		}, func(n int64) int64 { set = n; return 0 })
		if got != c.want || set != c.want {
			t.Errorf("%s: start %d, set %d, want %d", c.name, got, set, c.want)
		}
		out := buf.String()
		if c.wantLog == "" {
			if out != "" {
				t.Errorf("%s: logged %q", c.name, out)
			}
			continue
		}
		if strings.Count(out, "\n") != 1 || !strings.Contains(out, c.wantLog) {
			t.Errorf("%s: log %q, want one line with %q", c.name, out, c.wantLog)
		}
	}
}
