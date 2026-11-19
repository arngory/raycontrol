package provision

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/store"
)

// The node's own name (spec/names-v1.md §2): none without a domain; made
// once, one label under the domain, then kept; never a service's name;
// a new one when the domain changes.
func TestNodeDNSName(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if n, err := NodeDNSName(ctx, st); err != nil || n != "" {
		t.Fatalf("without a domain: %q %v", n, err)
	}
	if _, err := Init(ctx, st, Options{Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	first, err := NodeDNSName(ctx, st)
	label, ok := strings.CutSuffix(first, ".example.com")
	if err != nil || !ok || len(label) != 3 || strings.Contains(label, ".") {
		t.Fatalf("name %q %v", first, err)
	}
	if again, _ := NodeDNSName(ctx, st); again != first {
		t.Fatalf("moved: %q, then %q", first, again)
	}
	// Services after it take other names, and none may take it as a zone.
	for range 20 {
		all, _ := st.ListServices(ctx)
		z, err := newZone(ctx, st, all)
		if err != nil || z == first {
			t.Fatalf("a zone %q %v", z, err)
		}
	}
	if why, err := nodeNameClash(ctx, st, nil, first); err != nil || !strings.Contains(why, "own name") {
		t.Fatalf("clash %q %v", why, err)
	}
	if _, err := Init(ctx, st, Options{Domain: "example.net"}); err != nil {
		t.Fatal(err)
	}
	moved, err := NodeDNSName(ctx, st)
	if err != nil || !strings.HasSuffix(moved, ".example.net") {
		t.Fatalf("after the domain changed: %q %v", moved, err)
	}
}
