package main

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/arngory/raycontrol/internal/dnsstats"
	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// dnsttEvery is how often rayd reads the dnstt backends' counters, from
// dnsttFirst after its start.
const (
	dnsttEvery = time.Minute
	dnsttFirst = 20 * time.Second
)

// watchDNSTT reads each enabled dnstt service's counters every minute
// (the backend's stats socket, niko-server v0.11.0) and keeps an hour of
// them: the loop "dnstt <service>" in rayctl status says how many sessions
// there are and what the last hour brought, refusals of sessions and of
// queries (dnsauth, seal) included, and the tagged queries of each zone:
// which zones of the tunnel clients reach (a hint, spec/dnszones-v1.md). A
// backend that gives none fails the loop: it is not running. The DNS
// front's counters the same way, in the loop "dns-front": its queries by
// zone are load (anyone can send a zone's name), its probes, refusals and
// answers dropped. The first round waits a little: at rayd's start the
// backends may be starting too.
func watchDNSTT(ctx context.Context, st *store.Store, paths render.Paths, hb *health.Board) {
	windows := map[string]*dnsstats.Window[dnsstats.Snapshot]{}
	front := &dnsstats.Window[dnsstats.Front]{}
	select {
	case <-ctx.Done():
		return
	case <-time.After(dnsttFirst):
	}
	for {
		roundDNSTT(ctx, st, paths, windows, time.Now(), hb)
		roundFront(ctx, st, paths, front, time.Now(), hb)
		select {
		case <-ctx.Done():
			return
		case <-time.After(dnsttEvery):
		}
	}
}

// roundDNSTT is one round of watchDNSTT at now.
func roundDNSTT(ctx context.Context, st *store.Store, paths render.Paths, windows map[string]*dnsstats.Window[dnsstats.Snapshot], now time.Time, hb *health.Board) {
	// Each sample at the time it was read: a socket that does not answer
	// holds the round up to 2 s (review 15: samples stamped at the round's
	// start skewed the spans).
	start := time.Now()
	services, err := st.ListServices(ctx)
	if err != nil {
		return
	}
	var names []string
	for _, svc := range services {
		if svc.Kind != "dnstt" || !svc.Enabled {
			continue
		}
		names = append(names, svc.Name)
		w := windows[svc.Name]
		if w == nil {
			w = &dnsstats.Window[dnsstats.Snapshot]{}
			windows[svc.Name] = w
		}
		s, err := dnsstats.Read(ctx, paths.StatsSocket(svc.Name))
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			hb.Report("dnstt "+svc.Name, "", fmt.Errorf("the backend gives no counters: %w", err))
			continue
		}
		w.Add(now.Add(time.Since(start)), s)
		d, span, ok := w.Delta()
		hb.Report("dnstt "+svc.Name, dnsstats.Summary(s, d, span, ok), nil)
	}
	// A deleted or disabled service is forgotten.
	hb.Retain("dnstt ", names)
	for name := range windows {
		if !slices.Contains(names, name) {
			delete(windows, name)
		}
	}
}

// roundFront is one round of the front's counters at now, while there is
// a DNS tunnel (the front serves DNS only then).
func roundFront(ctx context.Context, st *store.Store, paths render.Paths, w *dnsstats.Window[dnsstats.Front], now time.Time, hb *health.Board) {
	services, err := st.ListServices(ctx)
	if err != nil {
		return
	}
	if !slices.ContainsFunc(services, func(s store.Service) bool {
		return s.Enabled && provision.DNSTunnel(s.Kind)
	}) {
		hb.Retain("dns-front", nil)
		*w = dnsstats.Window[dnsstats.Front]{}
		return
	}
	f, err := dnsstats.ReadFront(ctx, paths.FrontStats())
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		hb.Report("dns-front", "", fmt.Errorf("the front gives no counters: %w", err))
		return
	}
	w.Add(now, f)
	d, span, ok := w.Delta()
	hb.Report("dns-front", dnsstats.FrontSummary(d, span, ok), nil)
}
