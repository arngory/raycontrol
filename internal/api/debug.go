package api

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
)

// SetDebug opens the debug window for a while, or closes it
// (docs/09-observability.md §3). The data plane is rendered again with its
// level (its processes restart), rayspa takes it from its next snapshot
// and rayd from DebugChanged; the window ends by itself.
func (s *Server) SetDebug(ctx context.Context, req *connect.Request[nodev1.SetDebugRequest]) (*connect.Response[nodev1.SetDebugResponse], error) {
	d := time.Duration(req.Msg.Seconds) * time.Second
	var until time.Time
	var err error
	switch {
	case req.Msg.Seconds < 0 || d > store.MaxDebug:
		err = fmt.Errorf("%w: a debug window of %v (a day at most)", store.ErrInvalid, d)
	case d > 0:
		until = time.Now().Add(d).Truncate(time.Second)
	}
	if err == nil {
		err = s.Store.SetDebugUntil(ctx, until)
	}
	if err := s.done(ctx, "debug", d.String(), err); err != nil {
		return nil, err
	}
	s.notify()
	return connect.NewResponse(&nodev1.SetDebugResponse{Until: unixOf(until)}), nil
}

// debugUntil is the end of an open debug window, zero if none is open.
func debugUntil(ctx context.Context, st *store.Store) time.Time {
	if t := st.DebugUntil(ctx); time.Now().Before(t) {
		return t
	}
	return time.Time{}
}
