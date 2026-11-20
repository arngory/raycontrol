package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/store"
)

// rayctl relay list: the relays, then their names (relay-names-v1 §3), a
// line each with whether clients may be given it; no names, no table.
func TestRelayListNames(t *testing.T) {
	ctx := context.Background()
	msk := &nodev1.Relay{Name: "msk", Address: "198.51.100.20", CreatedAt: 1, Names: []*nodev1.RelayName{
		{Service: "reality", Name: "abc.example.com", Ready: true},
		{Service: "naive", Name: "def.example.com", Problem: "resolves to 203.0.113.7, not to the relay's 198.51.100.20 alone"},
	}}
	spb := &nodev1.Relay{Name: "spb", Address: "198.51.100.21", CreatedAt: 1}
	out, err := captureStdout(t, func() error { return (&cli{c: relaysNode{relays: []*nodev1.Relay{msk, spb}}}).relay(ctx, "list", nil) })
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	want := [][]string{
		{"NAME", "ADDRESS", "PROBE", "ADDED"},
		{"msk", "198.51.100.20", "-", "1970-01-01"},
		{"spb", "198.51.100.21", "-", "1970-01-01"},
		nil,
		{"RELAY", "SERVICE", "NAME", "READY"},
		{"msk", "reality", "abc.example.com", "yes"},
		{"msk", "naive", "def.example.com", "no: resolves to 203.0.113.7, not to the relay's 198.51.100.20 alone"},
	}
	if len(lines) != len(want) {
		t.Fatalf("%d lines:\n%s", len(lines), out)
	}
	for i, w := range want {
		if got := fields(lines[i]); !slices.Equal(got, w) {
			t.Errorf("line %d: %q, want %q", i, got, w)
		}
	}
	out, err = captureStdout(t, func() error { return (&cli{c: relaysNode{relays: []*nodev1.Relay{spb}}}).relay(ctx, "list", nil) })
	if err != nil || strings.Contains(out, "READY") {
		t.Errorf("no names: %v\n%s", err, out)
	}
}

// A rollback that puts the database back keeps the relays' names as they
// are now, as it does the node's own name: clients were given them.
func TestRollbackKeepsRelayNames(t *testing.T) {
	f := rollbackFix(t, "v0.34.0")
	ctx := context.Background()
	s, err := store.Open(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	now := map[string]string{node.DNSNameSetting: "own.example.com", node.RelayNamesSetting: `{"msk":{"3":"abc.example.com"}}`}
	for k, v := range now {
		if err := s.SetSetting(ctx, k, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	if err := (&cli{}).rollback(ctx, "asked for", true, carryMust); !errors.Is(err, errInstalled) {
		t.Fatalf("rollback: %v", err)
	}
	s, err = store.OpenReadOnly(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for k, v := range now {
		if b, err := s.GetSetting(ctx, k); err != nil || string(b) != v {
			t.Errorf("%s after the rollback: %s %v", k, b, err)
		}
	}
}

// rayctl relay ports names TCP 80 of an exit without a DNS provider as
// open to everyone for the certificate's orders only (relay-names-v1 §6).
func TestRelayPortsACME(t *testing.T) {
	msk := &nodev1.Relay{Name: "msk", Address: "198.51.100.20", Ports: []*nodev1.RelayPort{
		{Name: "ssh", Protos: []string{"tcp"}, From: 22, To: 22, Access: "admin"},
		{Name: "acme", Protos: []string{"tcp"}, From: 80, To: 80, Forwarded: true, Access: "acme"},
	}}
	fake := relaysNode{relays: []*nodev1.Relay{msk}}
	out, err := captureStdout(t, func() error { return (&cli{c: fake}).relay(context.Background(), "ports", []string{"msk"}) })
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	want := []string{"tcp", "80", "acme", "the exit", "everyone, while the exit orders a certificate with the relay's names (up to 3 minutes)"}
	if len(lines) < 3 || !slices.Equal(fields(lines[2]), want) {
		t.Fatalf("relay ports:\n%s", out)
	}
}
