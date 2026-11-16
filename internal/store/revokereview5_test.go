package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Regression tests from the fifth review of R4-43.

// The stored schedule as going back reads it (RotationAt) and as a
// revocation does (StoredRotation of a Store with none set): a negative
// period is none (rayd runs no schedule with it, v0.30 no loop); a negative
// lead or grace the default's, the rest kept; none stored, or one that does
// not read, no period for going back (it renews, harmlessly), the default
// schedule for a revocation (review 5, S1).
func TestRotationAtOutOfRange(t *testing.T) {
	ctx := context.Background()
	h := time.Hour
	for _, c := range []struct {
		name      string
		value     string // "" for none
		back, rev Rotation
	}{
		{"negative period", `{"period":-1,"lead":7200,"grace":46800}`,
			Rotation{Lead: 2 * h, Grace: 13 * h}, Rotation{Lead: 2 * h, Grace: 13 * h}},
		{"negative lead", `{"period":0,"lead":-5,"grace":46800}`,
			Rotation{Lead: DefaultRotation.Lead, Grace: 13 * h}, Rotation{Lead: DefaultRotation.Lead, Grace: 13 * h}},
		{"negative grace", `{"period":2592000,"lead":7200,"grace":-5}`,
			Rotation{Period: 720 * h, Lead: 2 * h, Grace: DefaultRotation.Grace}, Rotation{Period: 720 * h, Lead: 2 * h, Grace: DefaultRotation.Grace}},
		{"does not read", `{"period":`,
			Rotation{Lead: DefaultRotation.Lead, Grace: DefaultRotation.Grace}, DefaultRotation},
		{"none", "",
			Rotation{Lead: DefaultRotation.Lead, Grace: DefaultRotation.Grace}, DefaultRotation},
	} {
		path := filepath.Join(t.TempDir(), "rayd.db")
		s, err := Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		if c.value != "" {
			must(t, s.SetSetting(ctx, settingRotation, []byte(c.value)))
		}
		if got, err := s.StoredRotation(ctx); err != nil || got != c.rev {
			t.Errorf("%s: a revocation goes by %+v %v, want %+v", c.name, got, err, c.rev)
		}
		s.Close()
		if got, err := RotationAt(ctx, path); err != nil || got != c.back {
			t.Errorf("%s: going back reads %+v %v, want %+v", c.name, got, err, c.back)
		}
	}
}

// rayd's own negative period, as SetRotation stores it: going back
// renews (review 5, S1, the reviewer's probe).
func TestRenewOverlapRotationsNegativePeriod(t *testing.T) {
	ctx := context.Background()
	f := newRenewFix(t, Rotation{Period: -time.Second, Lead: DefaultRotation.Lead, Grace: 12 * time.Hour}, "alice")
	f.s.SetClock(func() time.Time { return time.Now().Add(time.Minute) })
	if _, err := f.s.RevokeDeviceOverlap(ctx, f.devs["alice"][0].ID); err != nil {
		t.Fatal(err)
	}
	f.s.Close()
	if r, err := RotationAt(ctx, f.path); err != nil || r.Period != 0 {
		t.Errorf("stored period -1s reads as %+v %v", r, err)
	}
}
