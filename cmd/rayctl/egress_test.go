package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/perimeter"
)

// egressNode keeps the policy as a node does and the changes it was asked.
type egressNode struct {
	nodev1connect.NodeServiceClient
	egress *nodev1.Egress
	sets   []*nodev1.SetEgressRequest
}

func (n *egressNode) GetEgress(context.Context, *connect.Request[nodev1.GetEgressRequest]) (*connect.Response[nodev1.GetEgressResponse], error) {
	return connect.NewResponse(&nodev1.GetEgressResponse{Egress: n.egress, Uids: []uint32{0}}), nil
}

func (n *egressNode) SetEgress(_ context.Context, req *connect.Request[nodev1.SetEgressRequest]) (*connect.Response[nodev1.SetEgressResponse], error) {
	n.sets = append(n.sets, req.Msg)
	if req.Msg.Bittorrent != nil {
		n.egress.Bittorrent = *req.Msg.Bittorrent
	}
	if req.Msg.Smtp != nil {
		n.egress.Smtp = *req.Msg.Smtp
	}
	return connect.NewResponse(&nodev1.SetEgressResponse{Egress: n.egress}), nil
}

// rayctl egress block|allow: root only; a block goes through the kernel's
// dry run first, the whole policy as rayspa will write it, and a refusal
// changes nothing; allow needs no dry run.
func TestEgressCommand(t *testing.T) {
	ctx := context.Background()
	euid, check := egressEuid, egressCheck
	t.Cleanup(func() { egressEuid, egressCheck = euid, check })
	var scripts []string
	refuse := false
	egressCheck = func(s string) ([]byte, error) {
		scripts = append(scripts, s)
		if refuse {
			return []byte("Error: Could not process rule: Operation not supported\n"), errors.New("exit status 1")
		}
		return nil, nil
	}
	n := &egressNode{egress: &nodev1.Egress{Smtp: true}}
	c := &cli{c: n}
	for _, args := range [][]string{{"block"}, {"block", "ftp"}, {"deny", "smtp"}, {"allow", "smtp", "now"}, {"list"}} {
		if err := c.egress(ctx, args); !errors.Is(err, errUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}

	egressEuid = func() int { return 1000 }
	if err := c.egress(ctx, []string{"block", "bittorrent"}); err == nil || !strings.Contains(err.Error(), "root only") || n.sets != nil {
		t.Fatalf("not root: %v, asked %v", err, n.sets)
	}

	egressEuid = func() int { return 0 }
	refuse = true
	err := c.egress(ctx, []string{"block", "bittorrent"})
	if err == nil || !strings.Contains(err.Error(), "nothing changed") || !strings.Contains(err.Error(), "Operation not supported") || n.sets != nil {
		t.Fatalf("refused by the kernel: %v, asked %v", err, n.sets)
	}
	refuse, scripts = false, nil
	if err := c.egress(ctx, []string{"block", "bittorrent"}); err != nil || len(n.sets) != 1 ||
		n.sets[0].Bittorrent == nil || !*n.sets[0].Bittorrent || n.sets[0].Smtp != nil || !n.egress.Bittorrent {
		t.Fatalf("block bittorrent: %v, asked %v", err, n.sets)
	}
	// The dry run had the policy whole: smtp from the node, the UIDs too.
	if len(scripts) != 1 || !strings.Contains(scripts[0], `comment "smtp"`) || !strings.Contains(scripts[0], `comment "bittorrent-tcp"`) ||
		!strings.Contains(scripts[0], "add element inet raycontrol egress_uid { 0 }") {
		t.Fatalf("dry run: %q", scripts)
	}
	refuse, scripts = true, nil
	if err := c.egress(ctx, []string{"allow", "smtp"}); err != nil || len(n.sets) != 2 || n.sets[1].Smtp == nil || *n.sets[1].Smtp ||
		n.egress.Smtp || scripts != nil {
		t.Fatalf("allow smtp: %v, asked %v, dry runs %d", err, n.sets, len(scripts))
	}
	if !isLocalOnly("egress") {
		t.Error("rayctl -remote F egress goes to the remote API")
	}
}

func TestEgressInForce(t *testing.T) {
	bt := &nodev1.Egress{Bittorrent: true}
	inForce := map[string]perimeter.Drops{"bittorrent-tcp": {}, "bittorrent-utp": {Packets: 3, Bytes: 120}}
	for _, c := range []struct {
		e      *nodev1.Egress
		blocks map[string]perimeter.Drops
		err    error
		want   string
	}{
		{bt, inForce, nil, "yes"},
		{&nodev1.Egress{}, map[string]perimeter.Drops{}, nil, "yes"},
		{bt, map[string]perimeter.Drops{}, nil, "not yet"},
		{&nodev1.Egress{Smtp: true, Bittorrent: true}, inForce, nil, "not yet"},
		{bt, nil, errors.New("nft list chain egress: exit status 1"), "unknown"},
	} {
		if got := egressInForce(c.e, c.blocks, c.err); !strings.HasPrefix(got, c.want) {
			t.Errorf("%v %v %v: %q", c.e, c.blocks, c.err, got)
		}
	}
	for e, want := range map[*nodev1.Egress]string{
		{}:                             "nothing blocked (rayctl egress)",
		{Bittorrent: true}:             "blocked: bittorrent (rayctl egress)",
		{Bittorrent: true, Smtp: true}: "blocked: bittorrent, smtp (tcp 25) (rayctl egress)",
		{Smtp: true}:                   "blocked: smtp (tcp 25) (rayctl egress)",
	} {
		if got := egressLine(e); got != want {
			t.Errorf("%v: %q", e, got)
		}
	}
}
