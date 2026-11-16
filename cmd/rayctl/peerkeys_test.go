package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// peerKeysNode answers GetYggdrasilPeerKeys with r, or with err.
type peerKeysNode struct {
	nodev1connect.NodeServiceClient
	r   *nodev1.GetYggdrasilPeerKeysResponse
	err error
}

func (n peerKeysNode) GetYggdrasilPeerKeys(_ context.Context, req *connect.Request[nodev1.GetYggdrasilPeerKeysRequest]) (*connect.Response[nodev1.GetYggdrasilPeerKeysResponse], error) {
	if n.err != nil {
		return nil, n.err
	}
	if req.Msg.Service != n.r.Service {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such service"))
	}
	return connect.NewResponse(n.r), nil
}

// captureBoth runs fn with the standard output and error in pipes and
// returns what it printed on each.
func captureBoth(t *testing.T, fn func() error) (stdout, stderr string, err error) {
	t.Helper()
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	saved := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	stdout, err = captureStdout(t, fn)
	os.Stderr = saved
	w.Close()
	return stdout, <-done, err
}

var samplePeerKeys = &nodev1.GetYggdrasilPeerKeysResponse{
	Service: "ygg", NodeKey: strings.Repeat("0a", 32), NodeAddress: "200:1234::1",
	Keys: []*nodev1.YggdrasilPeerKey{
		{PublicKey: strings.Repeat("1b", 32), User: "alice", Credential: "current"},
		{PublicKey: strings.Repeat("2c", 32), User: "alice", DeviceId: "3f2a9c1d", Device: "phone", Credential: "current"},
		{PublicKey: strings.Repeat("3d", 32), User: "alice", DeviceId: "3f2a9c1d", Device: "phone", Credential: "next",
			From: time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC).Unix()},
		{PublicKey: strings.Repeat("4e", 32), User: "bob", DeviceId: "77aa01", Device: "laptop", Credential: "previous",
			Until: time.Date(2026, 11, 18, 9, 30, 0, 0, time.UTC).Unix()},
	},
}

// rayctl service peer-keys: an AllowedPublicKeys block of HJSON, the
// node's key first, a comment above each key saying whose (and from or
// until when, for the keys of a credential switch); the note on stderr;
// -json as the API has it.
func TestPeerKeysCommand(t *testing.T) {
	ctx := context.Background()
	node := peerKeysNode{r: samplePeerKeys}
	out, note, err := captureBoth(t, func() error { return (&cli{c: node}).service(ctx, "peer-keys", []string{"ygg"}) })
	if err != nil {
		t.Fatal(err)
	}
	want := `# The keys the node's Yggdrasil service ygg lets in, for AllowedPublicKeys of a peer of yours
# (yggdrasil-go 0.5, HJSON): public keys only, a comment above each saying whose.
AllowedPublicKeys: [
  # the node (200:1234::1), which peers with yours
  "` + strings.Repeat("0a", 32) + `"
  # user alice: the user's own key (links of rayctl user export)
  "` + strings.Repeat("1b", 32) + `"
  # user alice, device phone (3f2a9c1d)
  "` + strings.Repeat("2c", 32) + `"
  # user alice, device phone (3f2a9c1d), next: from 2026-12-01 10:00 UTC
  "` + strings.Repeat("3d", 32) + `"
  # user bob, device laptop (77aa01), previous: until 2026-11-18 09:30 UTC
  "` + strings.Repeat("4e", 32) + `"
]
`
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
	if !strings.Contains(note, "they change") || !strings.Contains(note, "Leaving AllowedPublicKeys empty is the simpler choice") {
		t.Errorf("the note:\n%s", note)
	}
	out, _, err = captureBoth(t, func() error { return (&cli{c: node, json: true}).service(ctx, "peer-keys", []string{"ygg"}) })
	if flat := strings.Join(strings.Fields(out), " "); err != nil || !strings.Contains(flat, `"nodeKey": "`+strings.Repeat("0a", 32)+`"`) ||
		!strings.Contains(flat, `"deviceId": "3f2a9c1d"`) || !strings.Contains(flat, `"credential": "next"`) {
		t.Errorf("-json: %v\n%s", err, out)
	}

	// A node's answer is not trusted into a config: a key that is not one
	// is refused, a name that would end its comment is defused.
	bad := &nodev1.GetYggdrasilPeerKeysResponse{Service: "ygg", NodeKey: strings.Repeat("0a", 32),
		Keys: []*nodev1.YggdrasilPeerKey{{PublicKey: `aa"` + "\n]\nPeers: [tls://evil:1]", User: "x"}}}
	if out, _, err := captureBoth(t, func() error { return (&cli{c: peerKeysNode{r: bad}}).service(ctx, "peer-keys", []string{"ygg"}) }); err == nil || out != "" ||
		!strings.Contains(err.Error(), "not one") {
		t.Errorf("a key that is not one: %v", err)
	}
	odd := &nodev1.GetYggdrasilPeerKeysResponse{Service: "ygg", NodeKey: strings.Repeat("0a", 32), NodeAddress: "200::1\n]",
		Keys: []*nodev1.YggdrasilPeerKey{{PublicKey: strings.Repeat("1b", 32), User: "x\n]\nPeers: [", DeviceId: "d", Device: "a\r\nb"}}}
	out, _, err = captureBoth(t, func() error { return (&cli{c: peerKeysNode{r: odd}}).service(ctx, "peer-keys", []string{"ygg"}) })
	if err != nil || strings.Count(out, "\n") != 8 || strings.Contains(out, "Peers: [") {
		t.Errorf("odd names: %v\n%s", err, out)
	}

	unimplemented := peerKeysNode{err: connect.NewError(connect.CodeUnimplemented, errors.New("no"))}
	if err := (&cli{c: unimplemented}).service(ctx, "peer-keys", []string{"ygg"}); err == nil || !strings.Contains(err.Error(), "before v0.31.0") {
		t.Errorf("an older node: %v", err)
	}
	if err := (&cli{c: node}).service(ctx, "peer-keys", []string{"nope"}); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an unknown service: %v", err)
	}
	for _, args := range [][]string{nil, {"ygg", "more"}} {
		if err := (&cli{c: node}).service(ctx, "peer-keys", args); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v", args, err)
		}
	}
}
