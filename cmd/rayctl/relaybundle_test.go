package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// bundleNode issues relay bundles, or refuses them with err, and counts
// what it issued: each one changes the relay's keys.
type bundleNode struct {
	nodev1connect.NodeServiceClient
	err    error
	issued int
}

func (n *bundleNode) IssueRelayBundle(context.Context, *connect.Request[nodev1.IssueRelayBundleRequest]) (*connect.Response[nodev1.IssueRelayBundleResponse], error) {
	if n.err != nil {
		return nil, n.err
	}
	n.issued++
	return connect.NewResponse(&nodev1.IssueRelayBundleResponse{Bundle: "rcrelay1:new", SshPort: 22, Admin: []string{"192.0.2.7"}}), nil
}

// rayctl relay bundle -o FILE makes the file before the bundle is issued:
// a file already there (a second run with the same -o) or a directory
// that takes none leaves the relay's keys and the bundle before as they
// were, and a bundle the node refuses leaves no file behind.
func TestRelayBundleOutput(t *testing.T) {
	saved := needRoot
	needRoot = func() error { return nil }
	t.Cleanup(func() { needRoot = saved })
	ctx := context.Background()
	dir := t.TempDir()
	bundle := func(n *bundleNode, out string) error {
		return (&cli{c: n}).relay(ctx, "bundle", []string{"-admin", "192.0.2.7", "-o", out, "msk"})
	}

	n := &bundleNode{}
	out := filepath.Join(dir, "msk.bundle")
	if err := bundle(n, out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil || string(b) != "rcrelay1:new\n" || n.issued != 1 {
		t.Fatalf("bundle %q %v, issued %d", b, err, n.issued)
	}
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}

	// Again with the same file: refused before anything is issued.
	if err := os.WriteFile(out, []byte("rcrelay1:before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = bundle(n, out)
	if !errors.Is(err, os.ErrExist) || !strings.Contains(err.Error(), "nothing issued") || n.issued != 1 {
		t.Fatalf("an existing file: %v, issued %d", err, n.issued)
	}
	if b, _ := os.ReadFile(out); string(b) != "rcrelay1:before\n" {
		t.Fatalf("the file before became %q", b)
	}
	// A directory that is not there.
	if err := bundle(n, filepath.Join(dir, "none", "msk.bundle")); !errors.Is(err, os.ErrNotExist) || n.issued != 1 {
		t.Fatalf("no directory: %v, issued %d", err, n.issued)
	}

	// The node refuses: no file is left behind for the next run to trip on.
	refused := &bundleNode{err: connect.NewError(connect.CodeNotFound, errors.New("no relay msk"))}
	other := filepath.Join(dir, "other.bundle")
	if err := bundle(refused, other); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("refused: %v", err)
	}
	if _, err := os.Lstat(other); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused bundle left its file: %v", err)
	}
	// Then issued into it.
	if err := bundle(n, other); err != nil || n.issued != 2 {
		t.Fatalf("after a refusal: %v, issued %d", err, n.issued)
	}
}
