package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/hostcheck"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/release"
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
	if err := misnamedUpdate(&out, names, false, false, ""); err == nil || !strings.Contains(err.Error(), "edge-api") ||
		!strings.Contains(err.Error(), "nothing was changed: rayctl update -force goes on without them") || out.Len() != 0 {
		t.Errorf("update without -force: %v %q", err, out.String())
	}
	if err := misnamedUpdate(&out, names, true, false, ""); err != nil || !strings.Contains(out.String(), "warning: ") || !strings.Contains(out.String(), "dns-in") {
		t.Errorf("update -force: %v %q", err, out.String())
	}
	if err := misnamedUpdate(&out, nil, false, true, "v0.20.1"); err != nil {
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

// Who refuses and what goes on (second review, C): the operator's
// rayctl, which passes -force on to the release's; an update by request,
// which has no one to give -force and says so first, as the status keeps
// it; a rayctl before v0.21.0 that handed the update over without -force.
func TestMisnamedRefusals(t *testing.T) {
	names := []string{`service "edge-api" (hy2-masq)`, `service "dns-in" (dnstt)`}
	for _, c := range []struct {
		name          string
		request       bool
		handedFrom    string
		want, without string
	}{
		{"by hand", false, "", "nothing was changed: rayctl update -force goes on without them", "-no-handoff"},
		{"by hand, handed over by v0.21.0", false, "v0.21.0", "rayctl update -force goes on", "-no-handoff"},
		{"by hand, handed over by v0.20.1", false, "v0.20.1", "rayctl update -no-handoff (the rayctl of v0.20.1 hands the update over without -force) goes on", "update -force goes"},
		{"by request", true, "", "an update by request does not go on without services the new version leaves out: on the node, rayctl update -force does.", "-no-handoff"},
		{"by request, handed over by v0.20.1", true, "v0.20.1", "on the node, rayctl update -no-handoff", "update -force does"},
	} {
		var out bytes.Buffer
		err := misnamedUpdate(&out, names, false, c.request, c.handedFrom)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), c.without) || !strings.Contains(err.Error(), "edge-api") || out.Len() != 0 {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		// The terminal and the status keep the start: what to do is in it,
		// however many services there are.
		many := slices.Repeat(names, 20)
		err = misnamedUpdate(&out, many, false, c.request, c.handedFrom)
		if !c.request {
			if s := printableError(err); len(s) > maxErrorText+len("…") || !strings.Contains(s, c.want) {
				t.Errorf("%s: printed as %q", c.name, s)
			}
			continue
		}
		res := filepath.Join(t.TempDir(), "result.json")
		writeResult(res, err, false, "v0.21.0", "v0.21.1")
		r, ok := nodeupdate.ReadResult(res)
		if !ok || r.State != nodeupdate.Failed || !r.Untouched || !strings.Contains(r.Error, c.want) {
			t.Errorf("%s: the status: %+v", c.name, r)
		}
	}
	for v, want := range map[string]bool{"v0.20.1": false, "v0.10.2": false, "v0.21.0": true, "v0.22.3": true, "local": true, "dev": true} {
		if leavesOut(v) != want {
			t.Errorf("leavesOut(%s): %v", v, !want)
		}
	}
}

// The operator's -force reaches the release's rayctl the update is
// handed to (second review, C), and only when given.
func TestHandoffForce(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	script := []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RAYCTL_TEST_ARGS\"\n")
	tw.WriteHeader(&tar.Header{Name: "rayctl", Mode: 0o755, Size: int64(len(script)), Typeflag: tar.TypeReg})
	tw.Write(script)
	tw.Close()
	zw.Close()
	r := release.Release{Version: "v0.21.1", Archive: buf.Bytes(), Sums: []byte("sums"), Sig: []byte("sig")}
	for _, force := range []bool{false, true} {
		argsFile := filepath.Join(t.TempDir(), "args")
		t.Setenv("RAYCTL_TEST_ARGS", argsFile)
		handed, err := handoff(r, t.TempDir(), "v0.21.0", true, force)
		if !handed || err != nil {
			t.Fatalf("force %v: %v %v", force, handed, err)
		}
		b, err := os.ReadFile(argsFile)
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Fields(string(b))
		if slices.Contains(args, "-force") != force || !slices.Contains(args, "-yes") || args[0] != "update" {
			t.Errorf("force %v: the release's rayctl ran with %q", force, args)
		}
	}
}
