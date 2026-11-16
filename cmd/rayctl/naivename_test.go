package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// What rayctl says of naive's server name (R4-42): service list's KEYS
// column shows the name in use, the published switch with its name, a next
// name waiting for its certificate, the previous one; never an unpublished
// next name. status shows the name and, once published, the next one.
func TestNaiveNameText(t *testing.T) {
	day := func(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02 15:04") }
	created := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Unix()
	for _, c := range []struct {
		settings  string
		want, not []string
	}{
		{`{"sni":"a.example.com","sni_next":"b.example.com"}`, []string{"name a.example.com since creation"}, []string{"b.example.com"}},
		{`{"sni":"a.example.com","sni_next":"b.example.com","next_from":1795000000}`,
			[]string{"name a.example.com since creation", "switch " + day(1795000000) + " to b.example.com"}, nil},
		{`{"sni":"a.example.com","sni_next":"b.example.com","prepared_at":1794000000,"rotate_sni":true}`,
			[]string{"next name waits for its certificate", "rotate_sni on"}, []string{"b.example.com"}},
		{`{"sni":"b.example.com","sni_next":"c.example.com","sni_prev":"a.example.com","rotated_at":1795000000,"rotate_sni":false}`,
			[]string{"name b.example.com since " + day(1795000000), "a.example.com accepted until a switch a period after the last", "rotate_sni off"},
			[]string{"c.example.com"}},
		// Two switches within a period: the name before the previous one too.
		{`{"sni":"c.example.com","sni_prev":"b.example.com","sni_older":[{"sni":"a.example.com","retired_at":1794990000}],"rotated_at":1795000000}`,
			[]string{"b.example.com, a.example.com accepted until a switch a period after the one that left each"}, nil},
	} {
		got := keyState(&nodev1.Service{Kind: "naive", SettingsJson: c.settings, CreatedAt: created})
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q lacks %q", c.settings, got, w)
			}
		}
		for _, n := range c.not {
			if strings.Contains(got, n) {
				t.Errorf("%s: %q shows %q", c.settings, got, n)
			}
		}
	}
	if got := naiveStatus(&nodev1.Service{Sni: "a.example.com", SniNext: "b.example.com", NextFrom: 1795000000}); got != "name a.example.com, next b.example.com from 2026-11-18 11:06 UTC" {
		t.Errorf("status: %q", got)
	}
	// A rayd before v0.29.0 fills no field: the name from the settings.
	if got := naiveStatus(&nodev1.Service{SettingsJson: `{"sni":"a.example.com"}`}); got != "name a.example.com" {
		t.Errorf("status from an older rayd: %q", got)
	}
}

// rotateNode answers RotateService as rayd does for naive.
type rotateNode struct {
	nodev1connect.NodeServiceClient
	got   *nodev1.RotateServiceRequest
	reply *nodev1.RotateServiceResponse
}

func (n *rotateNode) RotateService(_ context.Context, r *connect.Request[nodev1.RotateServiceRequest]) (*connect.Response[nodev1.RotateServiceResponse], error) {
	n.got = r.Msg
	if n.reply != nil {
		return connect.NewResponse(n.reply), nil
	}
	return connect.NewResponse(&nodev1.RotateServiceResponse{SwitchAt: 1795000000, Kind: "naive"}), nil
}

// rayctl service rotate naive -now says which previous names stay routed
// after the switch, and which it drops.
func TestRotateNaivePreviousNames(t *testing.T) {
	n := &rotateNode{reply: &nodev1.RotateServiceResponse{SwitchAt: 1795000000, Kind: "naive",
		KeptNames: []string{"c.example.com", "b.example.com", "a.example.com"}, DroppedNames: []string{"z.example.com"}}}
	c := &cli{c: n}
	out, err := captureStdout(t, func() error { return c.service(context.Background(), "rotate", []string{"nv", "-now"}) })
	if err != nil {
		t.Fatal(err)
	}
	out = strings.Join(strings.Fields(out), " ")
	for _, want := range []string{"still accepted after the switch: c.example.com (in use now), b.example.com, a.example.com",
		"no longer accepted after the switch: z.example.com", "lose naive until they fetch their subscription"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q lacks %q", out, want)
		}
	}
}

func TestRotateNaive(t *testing.T) {
	for _, args := range [][]string{{"nv"}, {"nv", "-now"}} {
		n := &rotateNode{}
		c := &cli{c: n}
		out, err := captureStdout(t, func() error { return c.service(context.Background(), "rotate", args) })
		if err != nil {
			t.Fatal(err)
		}
		if n.got.Name != "nv" || n.got.Now != (len(args) == 2) || !strings.Contains(strings.Join(strings.Fields(out), " "), "previous name stays accepted until the switch after") ||
			strings.Contains(out, "keys") {
			t.Errorf("rotate %v: %+v\n%s", args, n.got, out)
		}
	}
}
