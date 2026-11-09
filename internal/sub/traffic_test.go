package sub_test

import (
	"context"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// The traffic field (traffic-limit-v1 §4): only for a user with a limit;
// over it the answer is 200 with no profiles and exhausted, and expires by
// the reset; disabled is 404 as before.
func TestTrafficInSubscription(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet()}
	build := func() (sub.Payload, string, error) {
		t.Helper()
		env, err := srv.BuildForDevice(ctx, "alice", f.key[:], netip.Addr{}, time.Now())
		if err != nil {
			return sub.Payload{}, "", err
		}
		p, err := sub.Verify(env, f.keys.PublicJSON())
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(env.Payload)
		return p, string(raw), nil
	}
	p, raw, err := build()
	if err != nil || p.Traffic != nil || strings.Contains(raw, `"traffic"`) || len(p.Profiles) != 1 {
		t.Fatalf("no limit: %+v %v", p.Traffic, err)
	}
	limit := int64(1000)
	u, err := f.st.SetUserTraffic(ctx, "alice", store.TrafficChange{Limit: &limit})
	if err != nil {
		t.Fatal(err)
	}
	next := store.NextReset(time.Now(), 1)
	p, raw, err = build()
	if err != nil || p.Traffic == nil || *p.Traffic != (sub.TrafficHint{V: 1, Used: 0, Limit: 1000, Since: u.TrafficStart.Unix(), Reset: next.Unix()}) ||
		strings.Contains(raw, "exhausted") || len(p.Profiles) != 1 || p.Expires-p.Issued != int64(sub.Lifetime/time.Second) {
		t.Fatalf("under: %+v %v", p.Traffic, err)
	}
	if err := f.st.WriteTraffic(ctx, store.TrafficWrite{Adds: []store.TrafficAdd{{UserID: u.ID, Start: u.TrafficStart, Up: 700, Down: 300}}}); err != nil {
		t.Fatal(err)
	}
	p, raw, err = build()
	if err != nil || p.Traffic == nil || !p.Traffic.Exhausted || p.Traffic.Used != 1000 || !strings.Contains(raw, `"profiles":[]`) ||
		p.DNSProbe != nil || p.DNSAuth != nil || p.Seq == 0 {
		t.Fatalf("over: %+v %v\n%s", p.Traffic, err, raw)
	}
	if exp := time.Unix(p.Expires, 0); exp.After(time.Unix(p.Issued, 0).Add(time.Hour)) || exp.After(next.Add(sub.ExhaustedJitter)) {
		t.Fatalf("expires %v, issued %v, reset %v", exp, time.Unix(p.Issued, 0), next)
	}
	// none: no reset, an hour.
	none := store.PeriodNone
	if _, err := f.st.SetUserTraffic(ctx, "alice", store.TrafficChange{Period: &none}); err != nil {
		t.Fatal(err)
	}
	if p, _, err = build(); err != nil || p.Traffic.Reset != 0 || !p.Traffic.Exhausted || p.Expires-p.Issued != 3600 {
		t.Fatalf("none: %+v %v", p.Traffic, err)
	}
	// Over the limit and disabled: no subscription at all.
	if err := f.st.SetUserEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err = build(); err == nil {
		t.Fatal("disabled: an answer")
	}
	// A raised limit: the profiles are back.
	if err := f.st.SetUserEnabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	limit = 2000
	if _, err := f.st.SetUserTraffic(ctx, "alice", store.TrafficChange{Limit: &limit}); err != nil {
		t.Fatal(err)
	}
	if p, _, err = build(); err != nil || p.Traffic.Exhausted || len(p.Profiles) != 1 {
		t.Fatalf("raised: %+v %v", p.Traffic, err)
	}
}

func TestExhaustedExpiry(t *testing.T) {
	now := time.Date(2026, 11, 30, 23, 30, 0, 0, time.UTC)
	reset := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		reset  time.Time
		jitter time.Duration
		want   time.Time
	}{
		{reset, 3 * time.Minute, reset.Add(3 * time.Minute)},
		{reset, 0, reset},
		{reset, time.Hour, reset.Add(sub.ExhaustedJitter)}, // at most 10 minutes
		{reset, -time.Hour, reset},
		{reset.Add(24 * time.Hour), 5 * time.Minute, now.Add(time.Hour)}, // at most an hour
		{time.Time{}, 5 * time.Minute, now.Add(time.Hour)},               // none
	} {
		if got := sub.ExhaustedExpiry(now, c.reset, c.jitter); !got.Equal(c.want) {
			t.Errorf("reset %v jitter %v: %v, want %v", c.reset, c.jitter, got, c.want)
		}
	}
}
