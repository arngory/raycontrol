package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/hostcheck"
)

// listingNode answers ListServices with its services.
type listingNode struct {
	nodev1connect.NodeServiceClient
	services []*nodev1.Service
}

func (n *listingNode) ListServices(context.Context, *connect.Request[nodev1.ListServicesRequest]) (*connect.Response[nodev1.ListServicesResponse], error) {
	return connect.NewResponse(&nodev1.ListServicesResponse{Services: n.services}), nil
}

// Services named as before v0.10.1 (-in, -api) are not deployed from
// v0.21.0: rayctl check says so, by name; rayctl update refuses before
// anything changes, unless -force, which goes on and says so (review of
// apply-plan-v1, item 8).
func TestMisnamed(t *testing.T) {
	c := &cli{c: &listingNode{services: []*nodev1.Service{
		{Kind: "hy2-masq", Name: "edge-api"}, {Kind: "dnstt", Name: "dns-in"}, {Kind: "dnstt", Name: "dns"},
		{Kind: "ssh", Name: "ssh-in"}, // no process: its name is no unit's
	}}}
	names := c.misnamed(context.Background())
	if len(names) != 2 || !strings.Contains(names[0], `"edge-api"`) || !strings.Contains(names[1], `"dns-in"`) {
		t.Fatalf("misnamed: %v", names)
	}
	rs := misnamedResults(names)
	if len(rs) != 2 || rs[0].OK || rs[0].Level != hostcheck.Advised || !strings.Contains(rs[0].Fix, "another name") {
		t.Errorf("check: %+v", rs)
	}
	var out bytes.Buffer
	if err := misnamedUpdate(&out, names, false); err == nil || !strings.Contains(err.Error(), "edge-api") ||
		!strings.Contains(err.Error(), "Nothing was changed") || out.Len() != 0 {
		t.Errorf("update without -force: %v %q", err, out.String())
	}
	if err := misnamedUpdate(&out, names, true); err != nil || !strings.Contains(out.String(), "warning: ") || !strings.Contains(out.String(), "dns-in") {
		t.Errorf("update -force: %v %q", err, out.String())
	}
	if err := misnamedUpdate(&out, nil, false); err != nil {
		t.Errorf("no such services: %v", err)
	}
	// rayd does not answer (before the install): nothing to say.
	if names := (&cli{c: untouchedList{}}).misnamed(context.Background()); names != nil {
		t.Errorf("no rayd: %v", names)
	}
}

// untouchedList is a rayd that does not answer.
type untouchedList struct {
	nodev1connect.NodeServiceClient
}

func (untouchedList) ListServices(context.Context, *connect.Request[nodev1.ListServicesRequest]) (*connect.Response[nodev1.ListServicesResponse], error) {
	return nil, connect.NewError(connect.CodeUnavailable, nil)
}
