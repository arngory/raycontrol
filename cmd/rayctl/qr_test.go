package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/node"
	"rsc.io/qr"
)

// The drawing reads back to the code's modules, with the quiet zone, and an
// invite of a node fits a terminal of 100 columns.
func TestWriteQR(t *testing.T) {
	b := node.Bundle{Version: 1, Host: "203.0.113.207", SPA: node.SPAParams{NodeID: strings.Repeat("a", 32), EpochLenS: 3600,
		SlotLenS: 30, PortKey: strings.Repeat("b", 64), PortBase: 40000, PortRange: 20000, LenMin: 120, LenMax: 1200},
		DeviceID: "d-k3f9x2qa", DeviceKey: strings.Repeat("c", 64), API: &node.BundleSub{Port: 18443, Pin: strings.Repeat("d", 43)},
		Expires: 1800000000}
	text, err := b.EncodeInvite()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeQR(&out, text); err != nil {
		t.Fatal(err)
	}
	code, _ := qr.Encode(text, qr.L)
	size := code.Size + 8
	if size > 100 {
		t.Fatalf("%d columns for %d characters", size, len(text))
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != (size+1)/2 {
		t.Fatalf("%d lines, want %d", len(lines), (size+1)/2)
	}
	for row, line := range lines {
		cells := strings.Split(strings.TrimSuffix(line, "\x1b[0m"), "▀")
		cells = cells[:len(cells)-1]
		if len(cells) != size {
			t.Fatalf("line %d: %d cells", row, len(cells))
		}
		for x, cell := range cells {
			for half, y := range []int{2 * row, 2*row + 1} {
				want := x >= 4 && y >= 4 && x-4 < code.Size && y-4 < code.Size && code.Black(x-4, y-4)
				got := strings.Contains(cell, map[int]string{0: "[38;5;16;", 1: ";48;5;16m"}[half])
				if got != want {
					t.Fatalf("module %d,%d: dark %v, want %v (%q)", x, y, got, want, cell)
				}
			}
		}
	}
}
