package main

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

// The test stand's switches: refused without -supervise, each named, and
// with it RAYCONTROL_UNSAFE_SITE_KEY_SETTLE_NOW shortens the pins' settle
// time only.
func TestUnsafeStand(t *testing.T) {
	t.Cleanup(func() { pinSettle = settleAfterStart })
	quiet := slog.New(slog.DiscardHandler)
	env := func(set ...string) func(string) string {
		return func(name string) string {
			for _, s := range set {
				if s == name {
					return "1"
				}
			}
			return ""
		}
	}
	for _, name := range []string{"RAYCONTROL_UNSAFE_SITE_KEY_FORCE_ANY_AGE", "RAYCONTROL_UNSAFE_SITE_KEY_SETTLE_NOW"} {
		err := unsafeStand(false, env(name), quiet)
		if err == nil || !strings.Contains(err.Error(), name+" is for a test stand (-supervise) only") {
			t.Errorf("%s without -supervise: %v", name, err)
		}
	}
	if pinSettle != settleAfterStart {
		t.Fatal("a refused switch changed the settle time")
	}
	if err := unsafeStand(true, env(), quiet); err != nil || pinSettle != settleAfterStart {
		t.Fatalf("no switch: %v, settle %v", err, pinSettle)
	}
	if err := unsafeStand(true, env("RAYCONTROL_UNSAFE_SITE_KEY_SETTLE_NOW"), quiet); err != nil || pinSettle != unsafeSettle {
		t.Fatalf("the stand: %v, settle %v", err, pinSettle)
	}
	if unsafeSettle > 10*time.Second || settleAfterStart != 10*time.Minute {
		t.Fatal("the settle times moved")
	}
}
