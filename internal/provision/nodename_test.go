package provision

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// Review of names-v1: no name while the host is a name (no address to fall
// back to nor to hold the name to); a name kept only while one label under
// the domain (a parent domain gets a new one, which *.<domain> covers);
// lower case without the final dot whatever the stored domain; none, at
// once, while a zone holds the domain.
func TestNodeDNSNameEdges(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Host: "node.example.net", Domain: "sub.example.com"}); err != nil {
		t.Fatal(err)
	}
	if n, err := NodeDNSName(ctx, st); err != nil || n != "" {
		t.Fatalf("the host a name: %q %v", n, err)
	}
	if _, err := st.GetSetting(ctx, settingNodeDNSName); err == nil {
		t.Fatal("a name stored for a host that is a name")
	}
	if _, err := Init(ctx, st, Options{Host: "2001:db8::7"}); err != nil {
		t.Fatal(err)
	}
	sub, err := NodeDNSName(ctx, st)
	if err != nil || !oneLabelUnder(sub, "sub.example.com") {
		t.Fatalf("under sub.example.com: %q %v", sub, err)
	}
	if _, err := Init(ctx, st, Options{Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	parent, err := NodeDNSName(ctx, st)
	if err != nil || !oneLabelUnder(parent, "example.com") {
		t.Fatalf("after the parent domain: %q %v", parent, err)
	}
	// A domain stored before Init canonicalized it.
	if err := st.SetSetting(ctx, settingDomain, []byte("Example.NET.")); err != nil {
		t.Fatal(err)
	}
	canon, err := NodeDNSName(ctx, st)
	if err != nil || !oneLabelUnder(canon, "example.net") {
		t.Fatalf("under Example.NET.: %q %v", canon, err)
	}
	// A zone at the domain, stored as v0.13 took it.
	if err := st.SetSetting(ctx, settingDomain, []byte("example.org")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateService(ctx, store.Service{Kind: "masterdns", Name: "old", Enabled: true, Settings: `{"zone":"example.org"}`}); err != nil {
		t.Fatal(err)
	}
	// At once: not waiting for the lock a rotation may hold.
	settingsMu.Lock()
	var n string
	done := make(chan struct{})
	go func() { n, err = NodeDNSName(ctx, st); close(done) }()
	select {
	case <-done:
		settingsMu.Unlock()
	case <-time.After(5 * time.Second):
		settingsMu.Unlock() // the tests after it take the lock too
		<-done
		t.Fatal("waited for settingsMu")
	}
	if err != nil || n != "" {
		t.Fatalf("a zone holds the domain: %q %v", n, err)
	}
}
