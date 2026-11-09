package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/perimeter"
)

// connLimitNode keeps the switch as a node does, and what it was asked.
type connLimitNode struct {
	nodev1connect.NodeServiceClient
	resp *nodev1.GetConnLimitResponse
	sets []bool
}

func (n *connLimitNode) GetConnLimit(context.Context, *connect.Request[nodev1.GetConnLimitRequest]) (*connect.Response[nodev1.GetConnLimitResponse], error) {
	return connect.NewResponse(n.resp), nil
}

func (n *connLimitNode) SetConnLimit(_ context.Context, req *connect.Request[nodev1.SetConnLimitRequest]) (*connect.Response[nodev1.SetConnLimitResponse], error) {
	n.sets = append(n.sets, req.Msg.Off)
	n.resp.Off = req.Msg.Off
	return connect.NewResponse(&nodev1.SetConnLimitResponse{Off: req.Msg.Off}), nil
}

// captureStdout runs fn with os.Stdout going to a buffer.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&buf, r); close(done) }()
	ferr := fn()
	os.Stdout = old
	w.Close()
	<-done
	return buf.String(), ferr
}

// rayctl conn-limit (spec/conn-limit-v1.md §8): show for anyone the node
// lets see it; on and off root only, no numbers; the per-address counters
// for root.
func TestConnLimitCommand(t *testing.T) {
	ctx := context.Background()
	euid, drops := connLimitEuid, connLimitDrops
	t.Cleanup(func() { connLimitEuid, connLimitDrops = euid, drops })
	now := time.Now().Unix()
	n := &connLimitNode{resp: &nodev1.GetConnLimitResponse{
		Conntrack: &nodev1.Conntrack{Count: 58100, Max: 65536, DroppedRecent: 3},
		Guard:     &nodev1.ConnGuard{On: true, Since: now - 120, LastOn: now - 120, Switches: 1, Refused: 9},
		Users:     []*nodev1.ConnLimitUser{{Id: 5, Service: "nv", Refused: 1340}},
		Refused:   []*nodev1.ConnLimitRefused{{Service: "nv", Kind: "tcp", Total: 1340}, {Service: "nv", Kind: "rate", Total: 0}},
	}}
	c := &cli{c: n}
	for _, args := range [][]string{{"set"}, {"on", "now"}, {"tcp=5"}, {"off", "u5"}} {
		if err := c.connLimit(ctx, args); !errors.Is(err, errUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}
	connLimitEuid = func() int { return 1000 }
	if err := c.connLimit(ctx, []string{"off"}); err == nil || !strings.Contains(err.Error(), "root only") || len(n.sets) != 0 {
		t.Fatalf("not root: %v, %v", err, n.sets)
	}
	out, err := captureStdout(t, func() error { return c.connLimit(ctx, nil) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"limits  ", "on (rayctl conn-limit off)", "58100 of 65536 (88%)", "3 connections dropped in 15 min",
		"ON for 2m", "u5 (nv: 1340 in 15 min)", "refused nv", "tcp 1340", "only root sees it", "TCP 1024 at once"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "rate 0") {
		t.Errorf("zeros shown:\n%s", out)
	}
	connLimitEuid = func() int { return 0 }
	connLimitDrops = func() (map[string]perimeter.Drops, error) {
		return map[string]perimeter.Drops{"tcp": {Packets: 7}, "udp": {Packets: 2}}, nil
	}
	if out, _ = captureStdout(t, func() error { return c.connLimit(ctx, []string{"show"}) }); !strings.Contains(out, "TCP 7, UDP 2 packets") {
		t.Errorf("root's counters:\n%s", out)
	}
	if out, err = captureStdout(t, func() error { return c.connLimit(ctx, []string{"off"}) }); err != nil || len(n.sets) != 1 || !n.sets[0] ||
		!strings.Contains(out, "connection limits off within seconds") || !strings.Contains(out, "the guard stay") {
		t.Fatalf("off: %v %v\n%s", err, n.sets, out)
	}
	if out, _ = captureStdout(t, func() error { return c.connLimit(ctx, nil) }); !strings.Contains(out, "off (rayctl conn-limit on)") || strings.Contains(out, "TCP 1024") {
		t.Errorf("off, shown:\n%s", out)
	}
	if err := c.connLimit(ctx, []string{"on"}); err != nil || n.sets[1] {
		t.Fatalf("on: %v %v", err, n.sets)
	}
	if !isLocalOnly("conn-limit") {
		t.Error("conn-limit through the remote API")
	}
}
