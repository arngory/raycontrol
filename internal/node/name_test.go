package node_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/store"
)

// Node names (subscription-v1 §3): spaces are tidied, everything a client
// would not show as is is refused, not cut out.
func TestCleanName(t *testing.T) {
	// Code points by number: some of them would hide in the source.
	r := func(cps ...rune) string { return string(cps) }
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"Амстердам " + r(0x1F642), "Амстердам " + r(0x1F642)},
		{"  Amsterdam" + r(0xA0) + " " + r(0x3000) + " 2 ", "Amsterdam 2"},
		{"Zürich (CH) №1 — ok!", "Zürich (CH) №1 — ok!"},
		{r(0x1F1F3, 0x1F1F1) + " NL", r(0x1F1F3, 0x1F1F1) + " NL"}, // a flag: regional indicators
		{r(0x2764, 0xFE0F), r(0x2764, 0xFE0F)},                     // VS16 is a mark
		{"東京", "東京"},
		{"Ti" + r(0x1EBF) + "ng Vi" + r(0x0065, 0x0323, 0x0302) + "t", "Ti" + r(0x1EBF) + "ng Vi" + r(0x0065, 0x0323, 0x0302) + "t"}, // marks on a base
		{"נתניה", "נתניה"}, // right to left: clients show it isolated
		{strings.Repeat("я", node.MaxNameLen), strings.Repeat("я", node.MaxNameLen)},
	} {
		got, err := node.CleanName(c.in)
		if err != nil || got != c.want {
			t.Errorf("CleanName(%+q) = %+q, %v; want %+q", c.in, got, err, c.want)
		}
	}
	for _, in := range []string{
		"Амстердам " + r(0x1F642, 0x202E) + "evil",              // right-to-left override
		"a" + r(0x200D) + "b",                                   // zero-width joiner
		r(0x1F468, 0x200D, 0x1F469),                             // an emoji sequence with ZWJ
		"a" + r(0x2066) + "b" + r(0x2069),                       // isolates
		"a" + r(0x200B) + "b",                                   // zero-width space (Cf)
		r(0xFEFF) + "name",                                      // BOM
		"a" + r(0xAD) + "b",                                     // soft hyphen
		"a\nb", "a\tb", "a\x00b", "a\x7fb", "a" + r(0x85) + "b", // controls
		"a" + r(0x2028) + "b", "a" + r(0x2029) + "b", // line and paragraph separators
		"a" + r(0xE000) + "b",              // private use
		"a" + r(0xE0041) + "b",             // a tag character
		"a" + r(0x10FFFE) + "b",            // a noncharacter (unassigned)
		"\xff\xfe",                         // not UTF-8
		strings.Repeat(r(0x3164), 3),       // Hangul fillers: a blank name
		"a" + r(0x115F) + "b",              // another filler
		"a" + r(0x034F) + "b",              // the combining grapheme joiner
		"a" + r(0xE0100) + "b",             // a variation selector supplement
		r(0xFE0F) + "a",                    // VS16 with nothing before it
		r(0x0301) + "abc",                  // a mark at the start
		"a " + r(0x0301) + "b",             // a mark after a space
		"a" + strings.Repeat(r(0x0336), 5), // marks stacked
		strings.Repeat("я", node.MaxNameLen+1),
	} {
		if got, err := node.CleanName(in); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("CleanName(%+q) = %+q, %v; want refused", in, got, err)
		}
	}
}

func TestSetName(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if n, err := node.Name(ctx, st); err != nil || n != "" {
		t.Fatalf("no name yet: %q, %v", n, err)
	}
	if n, err := node.SetName(ctx, st, "  Амстердам   1 "); err != nil || n != "Амстердам 1" {
		t.Fatalf("SetName: %q, %v", n, err)
	}
	if _, err := node.SetName(ctx, st, "x"+string(rune(0x202E))); err == nil {
		t.Fatal("a bidi override was taken")
	}
	if n, _ := node.Name(ctx, st); n != "Амстердам 1" {
		t.Fatalf("a refused name changed it: %q", n)
	}
	if n, err := node.SetName(ctx, st, ""); err != nil || n != "" {
		t.Fatalf("removing: %q, %v", n, err)
	}
	if n, _ := node.Name(ctx, st); n != "" {
		t.Fatalf("removed name is %q", n)
	}
}
