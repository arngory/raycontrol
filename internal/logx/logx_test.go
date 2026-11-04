package logx

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestPrefixes(t *testing.T) {
	var b bytes.Buffer
	t.Setenv("JOURNAL_STREAM", "8:1234")
	log := New(&b, slog.LevelDebug).With("svc", "x")
	log.Debug("d")
	log.Info("i")
	log.Warn("w")
	log.Error("e")
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines %q", lines)
	}
	for i, pre := range []string{"<7>", "<6>", "<4>", "<3>"} {
		if !strings.HasPrefix(lines[i], pre+"time=") || !strings.Contains(lines[i], "svc=x") {
			t.Errorf("line %d: %q", i, lines[i])
		}
	}
	b.Reset()
	t.Setenv("JOURNAL_STREAM", "")
	New(&b, slog.LevelInfo).Warn("plain")
	if strings.HasPrefix(b.String(), "<") {
		t.Errorf("prefix outside journald: %q", b.String())
	}
}
