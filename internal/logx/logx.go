// Package logx makes the daemons' loggers. Under systemd stderr goes to
// journald, which takes a leading "<N>" as the line's syslog priority
// (SyslogLevelPrefix=, on by default): without it every line is info, and
// journalctl -p warning shows none of the warnings.
package logx

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// New returns a text logger on w at the level. When journald reads w
// (JOURNAL_STREAM is set), each line starts with its syslog priority.
func New(w io.Writer, level slog.Leveler) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if os.Getenv("JOURNAL_STREAM") == "" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(newPrefixed(w, opts))
}

// prefixed sends each record to the text handler of its priority.
type prefixed struct {
	byLevel [4]slog.Handler // debug, info, warn, error
}

// Priorities of journald (syslog): err, warning, info, debug.
var prefixes = [4]string{"<7>", "<6>", "<4>", "<3>"}

func newPrefixed(w io.Writer, opts *slog.HandlerOptions) *prefixed {
	var p prefixed
	for i, pre := range prefixes {
		p.byLevel[i] = slog.NewTextHandler(&prefixWriter{w: w, prefix: []byte(pre)}, opts)
	}
	return &p
}

func index(l slog.Level) int {
	switch {
	case l >= slog.LevelError:
		return 3
	case l >= slog.LevelWarn:
		return 2
	case l >= slog.LevelInfo:
		return 1
	}
	return 0
}

func (p *prefixed) Enabled(ctx context.Context, l slog.Level) bool {
	return p.byLevel[index(l)].Enabled(ctx, l)
}

func (p *prefixed) Handle(ctx context.Context, r slog.Record) error {
	return p.byLevel[index(r.Level)].Handle(ctx, r)
}

func (p *prefixed) WithAttrs(attrs []slog.Attr) slog.Handler {
	var q prefixed
	for i, h := range p.byLevel {
		q.byLevel[i] = h.WithAttrs(attrs)
	}
	return &q
}

func (p *prefixed) WithGroup(name string) slog.Handler {
	var q prefixed
	for i, h := range p.byLevel {
		q.byLevel[i] = h.WithGroup(name)
	}
	return &q
}

// prefixWriter puts the prefix before each record: the text handler writes
// one whole line per Write.
type prefixWriter struct {
	w      io.Writer
	prefix []byte
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	if _, err := p.w.Write(append(append([]byte{}, p.prefix...), b...)); err != nil {
		return 0, err
	}
	return len(b), nil
}
