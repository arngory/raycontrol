package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/store"
)

// credRotation is rayd's schedule of credential rotation from its flags.
// With a period (R4-1): a lead shorter than the period and a grace of 12 h
// at least, or an error, as ever. Without one (-cred-period 0) nothing is
// scheduled, but a revocation with overlap rotates with this lead and grace
// (R4-43); before v0.31.0 they meant nothing there, so what is out of
// range is set right with a warning rather than refused: a grace under
// 12 h is raised to 12 h, and a lead below zero or of the default period
// or more (what the revoked device knew would be accepted that long) is
// the default lead.
func credRotation(r store.Rotation, log *slog.Logger) (store.Rotation, error) {
	if r.Period > 0 {
		if r.Lead >= r.Period {
			return r, errors.New("-cred-lead must be shorter than -cred-period")
		}
		// Niko moves to a new credential up to 12 h after the switch
		// (RAYCONTROL.md §11): the previous one must outlive that.
		if r.Grace < minCredGrace {
			return r, fmt.Errorf("-cred-grace must be at least %v: clients move to the new credential up to 12 h after the switch", minCredGrace)
		}
		return r, nil
	}
	if r.Lead < 0 || r.Lead >= store.DefaultRotation.Period {
		log.Warn("-cred-lead out of range without -cred-period, for the rotations revocations with overlap start: the default",
			"lead", r.Lead, "to", store.DefaultRotation.Lead)
		r.Lead = store.DefaultRotation.Lead
	}
	if r.Grace < minCredGrace {
		log.Warn("-cred-grace raised for the rotations revocations with overlap start", "grace", r.Grace, "to", minCredGrace)
		r.Grace = minCredGrace
	}
	return r, nil
}

// startCredentialRotation gives the store rayd's schedule, which a
// revocation with overlap goes by (store.SetRotation), and starts the
// rotation loop: with a period it publishes, switches and drops; without
// one (since v0.31.0) it still switches and drops what revocations with
// overlap published, which would otherwise be accepted for good.
func startCredentialRotation(ctx context.Context, st *store.Store, r store.Rotation, notify func(), hb *health.Board, log *slog.Logger) error {
	if err := st.SetRotation(ctx, r); err != nil {
		return err
	}
	go rotateCredentials(ctx, st, r, notify, hb, log)
	return nil
}
