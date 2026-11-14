package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/hostcheck"
	"github.com/arngory/raycontrol/internal/provision"
)

// portsNode answers GetPorts with its ports.
type portsNode struct {
	nodev1connect.NodeServiceClient
	ports []*nodev1.NodePort
}

func (n portsNode) GetPorts(context.Context, *connect.Request[nodev1.GetPortsRequest]) (*connect.Response[nodev1.GetPortsResponse], error) {
	return connect.NewResponse(&nodev1.GetPortsResponse{Ports: n.ports}), nil
}

// rayctl ports: one line a port or range, who reaches it, how it was set,
// the port of this slot of a rotating range; -json as the API has it.
func TestPortsCommand(t *testing.T) {
	until := time.Date(2026, 11, 14, 14, 5, 0, 0, time.Local).Unix()
	ports := []*nodev1.NodePort{
		{Name: "spa", Protos: []string{"tcp", "udp"}, From: 40000, To: 40099, Source: "chosen", Access: "everyone", Current: 40042, CurrentUntil: until},
		{Name: "sub", Protos: []string{"tcp", "udp"}, From: 40100, To: 40100, Source: "chosen", Access: "spa"},
		{Name: "ssh", Protos: []string{"tcp"}, From: 22, To: 22, Source: "sshd", Access: "admin"},
		{Name: "hy2 rotation", Protos: []string{"udp"}, From: 41000, To: 41099, Source: "chosen", Access: "spa", Current: 41007, CurrentUntil: until},
		{Name: "acme", Protos: []string{"tcp"}, From: 80, To: 80, Source: "fixed", Access: "acme"},
	}
	out, err := captureStdout(t, func() error { return (&cli{c: portsNode{ports: ports}}).ports(context.Background(), nil) })
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	at := time.Unix(until, 0).Format("15:04 MST")
	for i, want := range [][]string{
		{"PROTO", "PORTS", "NAME", "SET", "REACHED BY", "NOW"},
		{"tcp+udp", "40000-40099", "spa", "chosen", "everyone", "40042 until " + at},
		{"tcp+udp", "40100", "sub", "chosen", "after the knock", "-"},
		{"tcp", "22", "ssh", "sshd", "admin addresses; after the knock for SSH devices", "-"},
		{"udp", "41000-41099", "hy2 rotation", "chosen", "after the knock", "41007 until " + at},
		{"tcp", "80", "acme", "fixed", "everyone while a certificate is issued (HTTP-01)", "-"},
	} {
		if i >= len(lines) {
			t.Fatalf("%d lines:\n%s", len(lines), out)
		}
		var got []string
		for _, f := range strings.Split(lines[i], "  ") {
			if f = strings.TrimSpace(f); f != "" {
				got = append(got, f)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("line %d: %q, want %q", i, got, want)
		}
	}
	out, err = captureStdout(t, func() error {
		return (&cli{c: portsNode{ports: ports}, json: true}).ports(context.Background(), nil)
	})
	if err != nil || !strings.Contains(out, `"currentUntil"`) || !strings.Contains(strings.Join(strings.Fields(out), " "), `"source": "chosen"`) {
		t.Errorf("-json: %v\n%s", err, out)
	}
	if err := (&cli{c: portsNode{}}).ports(context.Background(), []string{"x"}); !errors.Is(err, errUsage) {
		t.Errorf("an argument: %v", err)
	}
}

// The host check is given every chosen port, by its protocols.
func TestChosenPortsForCheck(t *testing.T) {
	c, err := provision.ParsePorts("spa=40000-40099,sub=40100,api=40101,rotation=41000-41399")
	if err != nil {
		t.Fatal(err)
	}
	want := []hostcheck.ChosenPorts{
		{Name: "spa", Protos: []string{"tcp", "udp"}, From: 40000, To: 40099},
		{Name: "sub", Protos: []string{"tcp", "udp"}, From: 40100, To: 40100},
		{Name: "api", Protos: []string{"tcp"}, From: 40101, To: 40101},
		{Name: "rotation", Protos: []string{"udp"}, From: 41000, To: 41399},
	}
	got := chosenPorts(c)
	if !slices.EqualFunc(got, want, func(a, b hostcheck.ChosenPorts) bool {
		return a.Name == b.Name && slices.Equal(a.Protos, b.Protos) && a.From == b.From && a.To == b.To
	}) {
		t.Errorf("%+v", got)
	}
	if got := chosenPorts(provision.PortChoice{NoRotate: true}); len(got) != 0 {
		t.Errorf("rotation=off: %+v", got)
	}
}
