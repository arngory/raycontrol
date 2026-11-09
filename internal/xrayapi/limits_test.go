package xrayapi_test

import (
	"context"
	"maps"
	"path/filepath"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/traffic"
	"github.com/arngory/raycontrol/internal/xrayapi"
)

// The fork's refusals of the connection limits (spec/conn-limit-v1.md
// §3.3) come with the bytes in one query: user>>>BASE>>>limit>>>KIND, by
// base name and kind; other names and negative values are left out. rayd
// reads them as it reads the bytes, with the uptime as the process's age.
func TestStatsLimits(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "api.sock")
	startFake(t, sock)
	ctx := context.Background()
	r, err := xrayapi.DialStats(sock).Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]int64{"u1": {"tcp": 3, "rate": 2}, "u7": {"udp": 1}}
	if !maps.EqualFunc(r.Limits, want, maps.Equal) {
		t.Errorf("limits %v, want %v", r.Limits, want)
	}
	if r.Uptime != time.Minute || len(r.Users) != 1 || r.Users["u1"] != (xrayapi.Counter{Up: 5, Down: 6}) {
		t.Errorf("users %v uptime %v", r.Users, r.Uptime)
	}
	tr, err := traffic.ReadXray(ctx, sock)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.EqualFunc(tr.Limits, want, maps.Equal) || !tr.AgeKnown || tr.Age != time.Minute || tr.Users["u1"].Up != 5 {
		t.Errorf("traffic reading: limits %v age %v %v users %v", tr.Limits, tr.Age, tr.AgeKnown, tr.Users)
	}
}
