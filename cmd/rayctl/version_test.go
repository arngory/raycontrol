package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// statusNode answers GetStatus with its version, or err.
type statusNode struct {
	nodev1connect.NodeServiceClient
	version string
	err     error
}

func (n statusNode) GetStatus(context.Context, *connect.Request[nodev1.GetStatusRequest]) (*connect.Response[nodev1.GetStatusResponse], error) {
	if n.err != nil {
		return nil, n.err
	}
	return connect.NewResponse(&nodev1.GetStatusResponse{Version: n.version}), nil
}

// rayctl version: this rayctl's version, the installed one when known, the
// node's through -remote; -json, a small object without what is not known.
func TestVersions(t *testing.T) {
	for _, c := range []struct {
		v    versions
		text string
		json string
	}{
		{versions{Rayctl: "v0.27.0"}, "rayctl     v0.27.0\n", `{"rayctl":"v0.27.0"}`},
		{versions{Rayctl: "v0.27.0", Installed: "v0.26.0"}, "rayctl     v0.27.0\ninstalled  v0.26.0 (rayd on this host)\n",
			`{"rayctl":"v0.27.0","installed":"v0.26.0"}`},
		{versions{Rayctl: "dev", Node: "v0.26.0"}, "rayctl     dev\nnode       v0.26.0 (its status, through the API)\n",
			`{"rayctl":"dev","node":"v0.26.0"}`},
	} {
		var text, js bytes.Buffer
		if err := c.v.write(&text, false); err != nil || text.String() != c.text {
			t.Errorf("%+v: %q %v", c.v, text.String(), err)
		}
		if err := c.v.write(&js, true); err != nil {
			t.Fatal(err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, js.Bytes()); err != nil || compact.String() != c.json {
			t.Errorf("%+v: JSON %s %v", c.v, js.String(), err)
		}
	}
	// Off Linux no rayd is asked; an argument is a usage error.
	was := thisOS
	defer func() { thisOS = was }()
	thisOS = "darwin"
	c := &cli{}
	out, err := captureStdout(t, func() error { return c.versionCmd(context.Background(), nil) })
	if err != nil || out != "rayctl     "+version+"\n" {
		t.Errorf("off Linux: %q %v", out, err)
	}
	if err := c.versionCmd(context.Background(), []string{"x"}); !errors.Is(err, errUsage) {
		t.Errorf("an argument: %v", err)
	}
	// On Linux the line of this rayctl comes first, whatever rayd says.
	thisOS = "linux"
	out, err = captureStdout(t, func() error { return c.versionCmd(context.Background(), nil) })
	if err != nil || !strings.HasPrefix(out, "rayctl     "+version+"\n") {
		t.Errorf("on Linux: %q %v", out, err)
	}
	// Through -remote: the node's version from its status, cleaned; this
	// rayctl's is said even when the node does not answer.
	thisOS = "darwin"
	c = &cli{c: statusNode{version: "v0.26.0\x1b[2J"}, identity: &remoteIdentity{}}
	out, err = captureStdout(t, func() error { return c.versionCmd(context.Background(), nil) })
	if err != nil || out != "rayctl     "+version+"\nnode       v0.26.0?[2J (its status, through the API)\n" {
		t.Errorf("-remote: %q %v", out, err)
	}
	c.c = statusNode{err: errors.New("unavailable")}
	if err := c.versionCmd(context.Background(), nil); err == nil || !strings.HasPrefix(err.Error(), "rayctl "+version+"; the node's version: ") {
		t.Errorf("-remote, no answer: %v", err)
	}
}
