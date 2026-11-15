package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// naiveNamesLoop is rayctl status's line of naive's names (R4-42).
const naiveNamesLoop = "naive-names"

// frontRoute is a TCP route of the rendered front's config.
type frontRoute struct {
	SNI     []string `json:"sni"`
	Backend string   `json:"backend"`
}

// naiveServed checks that the front routes the published next name of
// every enabled naive service (docs/20-naive-sni-rotation.md §8.4). A name
// chosen an epoch ahead is routed from then, so one missing means that the
// render left the service out (it waits for its site's certificate, or
// fails), and its clients that move to it meet REALITY's site and go back
// to their link. It reports whether the node has a naive service at all,
// and the services whose name is not served.
func naiveServed(ctx context.Context, st *store.Store, frontConfig string) (bool, error) {
	all, err := st.ListServices(ctx)
	if err != nil {
		return false, err
	}
	var published []store.Service
	naive := false
	for _, s := range all {
		if s.Kind != "naive" || !s.Enabled {
			continue
		}
		naive = true
		if provision.ParseNaiveState(s).NextFrom != 0 {
			published = append(published, s)
		}
	}
	if len(published) == 0 {
		return naive, nil
	}
	var front struct {
		TCP struct {
			Routes []frontRoute `json:"routes"`
		} `json:"tcp"`
	}
	b, err := os.ReadFile(frontConfig) //nolint:gosec // G304: rayd's own rendered file
	if err == nil {
		err = json.Unmarshal(b, &front)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return naive, fmt.Errorf("the front's config: %w", err)
	}
	var errs []error
	for _, s := range published {
		ns := provision.ParseNaiveState(s)
		if !slices.ContainsFunc(front.TCP.Routes, func(r frontRoute) bool {
			return r.Backend == s.Name && slices.ContainsFunc(r.SNI, func(n string) bool { return strings.EqualFold(n, ns.SNINext) })
		}) {
			errs = append(errs, fmt.Errorf("%s: name %s published (switch %s), but the front does not serve it: clients that move to it "+
				"go back to their link (see the apply line)", s.Name, ns.SNINext, time.Unix(ns.NextFrom, 0).UTC().Format(time.RFC3339)))
		}
	}
	return naive, errors.Join(errs...)
}
