package store

import (
	"context"
	"testing"
	"time"
)

// SetDeviceClient writes a change at once and the same client at most every
// interval, and again after the clock has gone back; ClientCounts counts
// the devices seen in its window, and those never seen with one.
func TestDeviceClient(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Unix(1768435200, 0)
	s.SetClock(func() time.Time { return now })
	if _, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	phone, _, err := s.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateDevice(ctx, "alice", "laptop", "user"); err != nil {
		t.Fatal(err)
	}
	seen := func() (string, int64) {
		t.Helper()
		devs, err := s.ListDevices(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range devs {
			if d.ID == phone.ID && d.ClientAt != nil {
				return d.Client, d.ClientAt.Unix()
			}
		}
		return "", 0
	}
	set := func(c string) {
		t.Helper()
		if err := s.SetDeviceClient(ctx, phone.ID, c, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	set("niko/1.59.0")
	if c, at := seen(); c != "niko/1.59.0" || at != now.Unix() {
		t.Fatalf("first: %q %d", c, at)
	}
	first := now.Unix()
	now = now.Add(10 * time.Minute)
	set("niko/1.59.0")
	if _, at := seen(); at != first {
		t.Fatalf("the same within the hour rewritten: %d", at)
	}
	set("niko/1.60.0")
	if c, at := seen(); c != "niko/1.60.0" || at != now.Unix() {
		t.Fatalf("a change not written at once: %q %d", c, at)
	}
	now = now.Add(2 * time.Hour)
	set("niko/1.60.0")
	if _, at := seen(); at != now.Unix() {
		t.Fatalf("not rewritten after the hour: %d", at)
	}
	now = now.Add(-24 * time.Hour) // the clock goes back
	set("niko/1.60.0")
	if _, at := seen(); at != now.Unix() {
		t.Fatalf("a time ahead of the clock kept: %d", at)
	}
	counts, err := s.ClientCounts(ctx, now.Add(-time.Hour))
	if err != nil || len(counts) != 2 || counts[0].Devices != 1 || counts[1].Devices != 1 {
		t.Fatalf("counts: %+v %v", counts, err)
	}
	if counts, err := s.ClientCounts(ctx, now.Add(time.Hour)); err != nil || len(counts) != 1 || counts[0].Client != "" {
		t.Fatalf("out of the window, only the device never seen with one: %+v %v", counts, err)
	}
}
