package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// relaysNode answers ListRelays with its relays.
type relaysNode struct {
	nodev1connect.NodeServiceClient
	relays []*nodev1.Relay
}

func (n relaysNode) ListRelays(context.Context, *connect.Request[nodev1.ListRelaysRequest]) (*connect.Response[nodev1.ListRelaysResponse], error) {
	return connect.NewResponse(&nodev1.ListRelaysResponse{Relays: n.relays}), nil
}

// fields splits a table's line at its gaps of two spaces or more.
func fields(line string) []string {
	var out []string
	for _, f := range strings.Split(line, "  ") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// rayctl relay ports: one line a port or range of the relay host, where
// it goes and who reaches it; -json as the API has it; a relay without a
// bundle says how it gets its SPA range; a node before v0.31.0 and an
// unknown relay say so.
func TestRelayPortsCommand(t *testing.T) {
	ctx := context.Background()
	msk := &nodev1.Relay{Name: "msk", Address: "198.51.100.20", ProbePort: 51234, Ports: []*nodev1.RelayPort{
		{Name: "ssh", Protos: []string{"tcp"}, From: 2200, To: 2200, Access: "admin"},
		{Name: "spa", Protos: []string{"tcp", "udp"}, From: 43000, To: 43099, Access: "everyone"},
		{Name: "probe", Protos: []string{"tcp", "udp"}, From: 51234, To: 51234, Access: "spa"},
		{Name: "reality", Protos: []string{"tcp"}, From: 443, To: 443, Forwarded: true, Access: "spa"},
		{Name: "hy2", Protos: []string{"udp"}, From: 443, To: 443, Forwarded: true, Access: "spa"},
		{Name: "sub", Protos: []string{"tcp", "udp"}, From: 40100, To: 40100, Forwarded: true, Access: "spa"},
		{Name: "api", Protos: []string{"tcp"}, From: 40101, To: 40101, Forwarded: true, Access: "spa"},
	}}
	fresh := &nodev1.Relay{Name: "spb", Address: "198.51.100.21", Ports: []*nodev1.RelayPort{
		{Name: "ssh", Protos: []string{"tcp"}, From: 22, To: 22, Access: "admin"},
		{Name: "reality", Protos: []string{"tcp"}, From: 443, To: 443, Forwarded: true, Access: "spa"},
	}}
	node := relaysNode{relays: []*nodev1.Relay{msk, fresh}}
	out, err := captureStdout(t, func() error { return (&cli{c: node}).relay(ctx, "ports", []string{"msk"}) })
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	want := [][]string{
		{"PROTO", "PORTS", "NAME", "TO", "REACHED BY"},
		{"tcp", "2200", "ssh", "relay host", "the relay's admin addresses; after the knock for SSH devices"},
		{"tcp+udp", "43000-43099", "spa", "relay host", "everyone"},
		{"tcp+udp", "51234", "probe", "relay host", "after the knock"},
		{"tcp", "443", "reality", "the exit", "after the knock"},
		{"udp", "443", "hy2", "the exit", "after the knock"},
		{"tcp+udp", "40100", "sub", "the exit", "after the knock"},
		{"tcp", "40101", "api", "the exit", "after the knock"},
	}
	if len(lines) != len(want) {
		t.Fatalf("%d lines:\n%s", len(lines), out)
	}
	for i, w := range want {
		if got := fields(lines[i]); !slices.Equal(got, w) {
			t.Errorf("line %d: %q, want %q", i, got, w)
		}
	}
	out, err = captureStdout(t, func() error { return (&cli{c: node}).relay(ctx, "ports", []string{"spb"}) })
	if err != nil || !strings.Contains(out, "no SPA range yet: rayctl relay bundle spb makes it") {
		t.Errorf("without a bundle: %v\n%s", err, out)
	}
	out, err = captureStdout(t, func() error { return (&cli{c: node, json: true}).relay(ctx, "ports", []string{"msk"}) })
	// protojson's spaces vary on purpose.
	if flat := strings.Join(strings.Fields(out), " "); err != nil || !strings.Contains(flat, `"forwarded": true`) || !strings.Contains(flat, `"name": "msk"`) ||
		strings.Contains(out, "spb") {
		t.Errorf("-json: %v\n%s", err, out)
	}
	if err := (&cli{c: node}).relay(ctx, "ports", []string{"kzn"}); err == nil || !strings.Contains(err.Error(), "no relay kzn") {
		t.Errorf("an unknown relay: %v", err)
	}
	old := relaysNode{relays: []*nodev1.Relay{{Name: "msk", Address: "198.51.100.20", ProbePort: 51234}}}
	if err := (&cli{c: old}).relay(ctx, "ports", []string{"msk"}); err == nil || !strings.Contains(err.Error(), "before v0.31.0") {
		t.Errorf("an older node: %v", err)
	}
	for _, args := range [][]string{nil, {"msk", "spb"}} {
		if err := (&cli{c: node}).relay(ctx, "ports", args); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v", args, err)
		}
	}
}
