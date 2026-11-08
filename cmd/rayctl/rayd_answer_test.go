package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// raydAnswering is a rayd whose GetDeployInputs answers with f, through
// the client rayctl uses.
func raydAnswering(t *testing.T, f func() (*nodev1.GetDeployInputsResponse, error)) *cli {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(nodev1connect.NodeServiceGetDeployInputsProcedure, connect.NewUnaryHandler(nodev1connect.NodeServiceGetDeployInputsProcedure,
		func(context.Context, *connect.Request[nodev1.GetDeployInputsRequest]) (*connect.Response[nodev1.GetDeployInputsResponse], error) {
			r, err := f()
			if err != nil {
				return nil, err
			}
			return connect.NewResponse(r), nil
		}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &cli{c: api.NewNodeClient(srv.Client(), srv.URL, api.MaxAnswer)}
}

// rayd's error text reaches root's terminal without what it would act on,
// and not without end (the review's case).
func TestRaydErrorPrintable(t *testing.T) {
	c := raydAnswering(t, func() (*nodev1.GetDeployInputsResponse, error) {
		return nil, connect.NewError(connect.CodeInternal, errors.New("\x1b]0;owned\x07\x1b[2J\x1b[1;1Hall good\n"+strings.Repeat("x", 5000)))
	})
	_, _, err := c.deployPlan(context.Background())
	if err == nil || strings.ContainsFunc(err.Error(), func(r rune) bool { return r < 0x20 || r == 0x7f }) || len(err.Error()) > 600 {
		t.Errorf("printed as %q", err)
	}
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("code %v", connect.CodeOf(err))
	}
}

// An answer past the limit is refused, not read whole into root's memory
// (the review's case, at 17 MiB rather than 200).
func TestRaydAnswerLimit(t *testing.T) {
	big := strings.Repeat("A", 1<<20)
	c := raydAnswering(t, func() (*nodev1.GetDeployInputsResponse, error) {
		ws := make([]string, 17)
		for i := range ws {
			ws[i] = big
		}
		return &nodev1.GetDeployInputsResponse{Warnings: ws}, nil
	})
	if _, _, err := c.deployPlan(context.Background()); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("17 MiB answer: %v", err)
	}
}

// rayd's warnings: at most deploy.MaxWarnings of them, and how many more.
func TestRaydWarningsCapped(t *testing.T) {
	c := raydAnswering(t, func() (*nodev1.GetDeployInputsResponse, error) {
		r := api.DeployInputsProto(nodeInputs())
		for i := range 150 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("rayd's warning %d", i))
		}
		return r, nil
	})
	p, _, err := c.deployPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, w := range p.Warnings {
		if strings.HasPrefix(w, "rayd's warning ") {
			n++
		}
	}
	if n != deploy.MaxWarnings || !strings.Contains(strings.Join(p.Warnings, "\n"), "50 more of rayd's warnings not shown") {
		t.Errorf("%d of rayd's warnings: %q", n, p.Warnings[len(p.Warnings)-1])
	}
}
