package main

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// serviceNode keeps the service calls it got.
type serviceNode struct {
	nodev1connect.NodeServiceClient
	enabled []*nodev1.SetServiceEnabledRequest
	deleted []*nodev1.DeleteServiceRequest
}

func (n *serviceNode) SetServiceEnabled(_ context.Context, r *connect.Request[nodev1.SetServiceEnabledRequest]) (*connect.Response[nodev1.SetServiceEnabledResponse], error) {
	n.enabled = append(n.enabled, r.Msg)
	return connect.NewResponse(&nodev1.SetServiceEnabledResponse{}), nil
}

func (n *serviceNode) DeleteService(_ context.Context, r *connect.Request[nodev1.DeleteServiceRequest]) (*connect.Response[nodev1.DeleteServiceResponse], error) {
	n.deleted = append(n.deleted, r.Msg)
	return connect.NewResponse(&nodev1.DeleteServiceResponse{}), nil
}

// rayctl service disable|del NAME [-force]: -force goes to rayd, which
// refuses the last enabled ssh service without it; enable takes none.
func TestServiceForce(t *testing.T) {
	n := &serviceNode{}
	c := &cli{c: n}
	ctx := context.Background()
	for _, args := range [][]string{{"ssh", "-force"}, {"ssh"}} {
		if err := c.service(ctx, "del", args); err != nil {
			t.Fatal(err)
		}
		if err := c.service(ctx, "disable", args); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.service(ctx, "enable", []string{"ssh"}); err != nil {
		t.Fatal(err)
	}
	if len(n.deleted) != 2 || !n.deleted[0].Force || n.deleted[1].Force || n.deleted[0].Name != "ssh" ||
		len(n.enabled) != 3 || !n.enabled[0].Force || n.enabled[0].Enabled || n.enabled[1].Force || !n.enabled[2].Enabled {
		t.Errorf("deleted %v, enabled %v", n.deleted, n.enabled)
	}
	for _, c2 := range []struct {
		sub  string
		args []string
	}{{"enable", []string{"ssh", "-force"}}, {"del", []string{"ssh", "x"}}, {"disable", nil}, {"del", []string{"ssh", "-now"}}} {
		if err := c.service(ctx, c2.sub, c2.args); !errors.Is(err, errUsage) {
			t.Errorf("service %s %v: %v", c2.sub, c2.args, err)
		}
	}
}
