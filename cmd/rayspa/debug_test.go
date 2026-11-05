package main

import (
	"log/slog"
	"testing"
	"time"
)

// rayspa logs at debug level while a snapshot names an open debug window,
// and goes back by itself when it ends; -debug keeps it on.
func TestDebugLevel(t *testing.T) {
	var d debugLevel
	d.until(time.Now().Add(time.Hour).Unix())
	if d.level.Level() != slog.LevelDebug {
		t.Fatal("not debug in the window")
	}
	d.until(0)
	if d.level.Level() != slog.LevelInfo {
		t.Fatal("still debug after the window closed")
	}
	d.until(time.Now().Add(-time.Minute).Unix())
	if d.level.Level() != slog.LevelInfo {
		t.Fatal("debug for a window in the past")
	}
	d.until(time.Now().Add(1500 * time.Millisecond).Unix()) // ends within 1–2 s
	if d.level.Level() != slog.LevelDebug {
		t.Fatal("not debug in a short window")
	}
	deadline := time.Now().Add(5 * time.Second)
	for d.level.Level() != slog.LevelInfo && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if d.level.Level() != slog.LevelInfo {
		t.Fatal("the window did not end by itself")
	}

	always := &debugLevel{always: true}
	always.level.Set(slog.LevelDebug)
	always.until(0)
	if always.level.Level() != slog.LevelDebug {
		t.Fatal("-debug turned off by a snapshot")
	}
	var none *debugLevel
	none.until(1) // a feed without a level: nothing to do
}
