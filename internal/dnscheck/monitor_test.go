package dnscheck

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMonitor(t *testing.T) {
	w := newWorld(t)
	var rounds, done atomic.Int32
	release := make(chan struct{})
	m := &Monitor{Checker: w.checker, Resolvers: mustResolvers(t, DefaultResolvers...), Gap: 300 * time.Millisecond,
		Targets: func(context.Context) ([]Zone, error) {
			if rounds.Add(1) == 1 {
				<-release
			}
			return w.zones()[:1], nil
		},
		Done: func(Report) { done.Add(1) }}
	ctx := context.Background()
	if _, ok := m.Last(); ok {
		t.Fatal("a report before any check")
	}

	// Two operators at once: one check.
	var wg sync.WaitGroup
	reps := make([]Report, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Go(func() { reps[i], errs[i] = m.Run(ctx, RunOptions{Forced: true}) })
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || rounds.Load() != 1 || done.Load() != 1 || !reps[0].Start.Equal(reps[1].Start) {
		t.Fatalf("two at once: %v %v, %d rounds, %d done", errs[0], errs[1], rounds.Load(), done.Load())
	}
	if len(reps[0].Zones) != 1 || reps[0].Zones[0].Err() != nil {
		t.Fatalf("report %+v", reps[0])
	}
	// Within the gap: the last report, no check.
	rep, err := m.Run(ctx, RunOptions{Forced: true})
	if err != nil || !rep.Limited || !rep.Start.Equal(reps[0].Start) || rounds.Load() != 1 {
		t.Fatalf("too soon: %v %v, %d rounds", rep.Limited, err, rounds.Load())
	}
	// Other resolvers within the gap: nothing to give.
	nsdi := mustResolvers(t, "nsdi")
	var soon TooSoon
	if _, err := m.Run(ctx, RunOptions{Forced: true, Resolvers: nsdi}); !errors.As(err, &soon) || soon.Wait <= 0 {
		t.Fatalf("other resolvers too soon: %v", err)
	}
	// The periodic check does not wait for the gap.
	if _, err := m.Run(ctx, RunOptions{}); err != nil || rounds.Load() != 2 || done.Load() != 2 {
		t.Fatalf("periodic: %v, %d rounds, %d done", err, rounds.Load(), done.Load())
	}
	periodic, _ := m.Last()

	// After the gap, other resolvers: a check of their own, which is not
	// the node's report and does not go to the board.
	time.Sleep(300 * time.Millisecond)
	w.resolver("195.208.5.1", &resolverSim{edns: 1232})
	w.resolver("195.208.4.1", &resolverSim{edns: 1232})
	rep, err = m.Run(ctx, RunOptions{Forced: true, Resolvers: nsdi})
	if err != nil || rep.Limited || rounds.Load() != 3 || done.Load() != 2 || len(rep.Zones[0].Resolvers) != 2 {
		t.Fatalf("nsdi: %v %+v, %d rounds, %d done", err, rep, rounds.Load(), done.Load())
	}
	if last, _ := m.Last(); !last.Start.Equal(periodic.Start) {
		t.Fatal("other resolvers replaced the node's report")
	}
	// Within the gap again, the same resolvers: their last report.
	if rep, err := m.Run(ctx, RunOptions{Forced: true, Resolvers: mustResolvers(t, "nsdi")}); err != nil || !rep.Limited || len(rep.Zones[0].Resolvers) != 2 {
		t.Fatalf("nsdi too soon: %v %+v", err, rep)
	}
	// The same resolvers as the node's, named: the node's check.
	time.Sleep(300 * time.Millisecond)
	if _, err := m.Run(ctx, RunOptions{Forced: true, Resolvers: mustResolvers(t, "quad9,google,cloudflare")}); err != nil || done.Load() != 3 {
		t.Fatalf("the defaults by name: %v, %d done", err, done.Load())
	}
	periodic, _ = m.Last()

	// Parents only: no report kept, nothing to the board.
	rep, err = m.Run(ctx, RunOptions{ParentOnly: true})
	if err != nil || !rep.ParentOnly || done.Load() != 3 {
		t.Fatalf("parents: %v %+v", err, rep)
	}
	if last, _ := m.Last(); !last.Start.Equal(periodic.Start) {
		t.Fatal("a parents-only round became the report")
	}

	// A caller that leaves does not stop the check.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := m.Run(cctx, RunOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("left: %v", err)
	}
	for range 100 {
		if last, _ := m.Last(); !last.Start.Equal(periodic.Start) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if last, _ := m.Last(); last.Start.Equal(periodic.Start) {
		t.Fatal("the check stopped with its caller")
	}

	// The zones cannot be read: the error, no report.
	m.Targets = func(context.Context) ([]Zone, error) { return nil, errors.New("store closed") }
	if _, err := m.Run(ctx, RunOptions{}); err == nil || err.Error() != "store closed" {
		t.Fatalf("targets: %v", err)
	}
}
