package store

import (
	"context"
	"testing"
)

// The connection limits are on without a setting (spec/conn-limit-v1.md
// §12: on by default); off is a setting, and on takes it away.
func TestConnLimitSetting(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if off, err := s.ConnLimitOff(ctx); err != nil || off {
		t.Fatalf("a new node: off %v, %v", off, err)
	}
	if off, err := s.SetConnLimitOff(ctx, true); err != nil || !off {
		t.Fatalf("turned off: %v, %v", off, err)
	}
	if v, err := s.GetSetting(ctx, settingConnLimit); err != nil || string(v) != "off" {
		t.Fatalf("setting %q, %v", v, err)
	}
	if off, err := s.SetConnLimitOff(ctx, false); err != nil || off {
		t.Fatalf("turned on: %v, %v", off, err)
	}
	if _, err := s.GetSetting(ctx, settingConnLimit); err == nil {
		t.Fatal("on keeps a setting: absent is on")
	}
	// Anything but "off" is on.
	if err := s.SetSetting(ctx, settingConnLimit, []byte("on")); err != nil {
		t.Fatal(err)
	}
	if off, _ := s.ConnLimitOff(ctx); off {
		t.Fatal(`"on" read as off`)
	}
}
