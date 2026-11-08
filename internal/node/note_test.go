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

// A node's note takes what scripts and emoji need, and nothing that would
// reorder, hide or break what a client shows around it.
func TestCleanNote(t *testing.T) {
	for in, want := range map[string]string{
		"  Узел в Амстердаме,   до 1 Гбит/с  ":                                  "Узел в Амстердаме, до 1 Гбит/с",
		"👨\u200D👩\u200D👧 семья, 🏳️\u200D🌈, 👍🏽, 1️⃣":                             "👨\u200D👩\u200D👧 семья, 🏳️\u200D🌈, 👍🏽, 1️⃣",
		"🏴\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F England": "🏴\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F England",
		"می\u200Cخواهم":      "می\u200Cخواهم", // ZWNJ in Persian
		"שלום עולם, مرحبا":   "שלום עולם, مرحبا",
		"東京ノード、速い":           "東京ノード、速い",
		"Tiếng Việt, हिन्दी": "Tiếng Việt, हिन्दी",
		"🇳🇱 NL":              "🇳🇱 NL",
		"":                   "",
	} {
		got, err := node.CleanNote(in)
		if err != nil || got != want {
			t.Errorf("CleanNote(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for name, in := range map[string]string{
		"newline":              "one\ntwo",
		"tab":                  "one\ttwo",
		"bidi override":        "abc\u202Edef",
		"bidi isolate":         "abc\u2066def",
		"right-to-left mark":   "abc\u200Fdef",
		"zero-width space":     "a\u200Bb",
		"BOM":                  "\uFEFFnote",
		"joiner at the start":  "\u200Dnote",
		"joiner at the end":    "note\u200D",
		"joiner by a space":    "note \u200Dmore",
		"two joiners":          "a\u200D\u200Db",
		"tag without its flag": "a\U000E0067\U000E007F",
		"tag not closed":       "🏴\U000E0067\U000E0062",
		"cancel tag alone":     "🏴\U000E007F",
		"private use":          "ab",
		"line separator":       "a b",
		"Hangul filler":        "ㅤ",
		"mark at the start":    "́a",
		"stacked marks":        "á́́́́",
		"too long":             strings.Repeat("ж", node.MaxNoteLen+1),
		"invalid UTF-8":        "a\xffb",
	} {
		if got, err := node.CleanNote(in); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: CleanNote(%q) = %q, %v", name, in, got, err)
		}
	}
	if got, err := node.CleanNote(strings.Repeat("ж", node.MaxNoteLen)); err != nil || len([]rune(got)) != node.MaxNoteLen {
		t.Errorf("200 characters: %v", err)
	}
	// A name stays stricter: no joiners.
	if _, err := node.CleanName("👨\u200D👩\u200D👧"); err == nil {
		t.Error("a name took a joiner")
	}
}

func TestNote(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if n, err := node.Note(ctx, st); err != nil || n != "" {
		t.Fatalf("no note: %q %v", n, err)
	}
	if n, err := node.SetNote(ctx, st, "  до 1 Гбит/с 🚀 "); err != nil || n != "до 1 Гбит/с 🚀" {
		t.Fatalf("set: %q %v", n, err)
	}
	if _, err := node.SetNote(ctx, st, "a\u202Eb"); err == nil {
		t.Fatal("a bad note kept")
	}
	if n, _ := node.Note(ctx, st); n != "до 1 Гбит/с 🚀" {
		t.Fatalf("after a refused one: %q", n)
	}
	if n, err := node.SetNote(ctx, st, ""); err != nil || n != "" {
		t.Fatalf("removed: %q %v", n, err)
	}
}
