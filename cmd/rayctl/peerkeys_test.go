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
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// peerKeysNode answers GetYggdrasilPeerKeys with r, or with err: the
// names only when asked, as rayd does, unless leak.
type peerKeysNode struct {
	nodev1connect.NodeServiceClient
	r     *nodev1.GetYggdrasilPeerKeysResponse
	err   error
	leak  bool
	asked *[]bool // the requests' names
}

func (n peerKeysNode) GetYggdrasilPeerKeys(_ context.Context, req *connect.Request[nodev1.GetYggdrasilPeerKeysRequest]) (*connect.Response[nodev1.GetYggdrasilPeerKeysResponse], error) {
	if n.asked != nil {
		*n.asked = append(*n.asked, req.Msg.Names)
	}
	if n.err != nil {
		return nil, n.err
	}
	if req.Msg.Service != n.r.Service {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such service"))
	}
	r := proto.Clone(n.r).(*nodev1.GetYggdrasilPeerKeysResponse)
	if !req.Msg.Names && !n.leak {
		for _, k := range r.Keys {
			k.User, k.Device = "", ""
		}
	}
	return connect.NewResponse(r), nil
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
		{PublicKey: strings.Repeat("1b", 32), User: "alice", Credential: "current", Label: "u3"},
		{PublicKey: strings.Repeat("2c", 32), User: "alice", DeviceId: "3f2a9c1d", Device: "phone", Credential: "current", Label: "u3-3f2a9c1d"},
		{PublicKey: strings.Repeat("3d", 32), User: "alice", DeviceId: "3f2a9c1d", Device: "phone", Credential: "next",
			From: time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC).Unix(), Label: "u3-3f2a9c1d-n"},
		{PublicKey: strings.Repeat("4e", 32), User: "bob", DeviceId: "77aa01", Device: "laptop", Credential: "previous",
			Until: time.Date(2026, 11, 18, 9, 30, 0, 0, time.UTC).Unix(), Label: "u7-77aa01-p"},
	},
}

const peerKeysHeader = `# The keys the node's Yggdrasil service ygg lets in, for AllowedPublicKeys of a peer of yours
# (yggdrasil-go 0.5, HJSON): public keys only. Labels as in the node's users file: u<user id>
# (rayctl -json user list), -<device id> (rayctl device list), -n the next key, -p the previous one.
AllowedPublicKeys: [
  # the node (200:1234::1), which peers with yours
  "` + "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a" + `"
`

// rayctl service peer-keys: an AllowedPublicKeys block of HJSON, the
// node's key first, a comment above each key with its label in the node's
// users file (and from or until when, for the keys of a credential
// switch); the users' and devices' names only with -names, which asks
// rayd for them and warns on stderr; the note on stderr; -json as the API
// has it, without names unless -names.
func TestPeerKeysCommand(t *testing.T) {
	ctx := context.Background()
	var asked []bool
	node := peerKeysNode{r: samplePeerKeys, asked: &asked}
	out, note, err := captureBoth(t, func() error { return (&cli{c: node}).service(ctx, "peer-keys", []string{"ygg"}) })
	if err != nil {
		t.Fatal(err)
	}
	want := peerKeysHeader + `  # u3: the user's own key (links of rayctl user export)
  "` + strings.Repeat("1b", 32) + `"
  # u3-3f2a9c1d: a device's key
  "` + strings.Repeat("2c", 32) + `"
  # u3-3f2a9c1d-n: a device's key, next: from 2026-12-01 10:00 UTC
  "` + strings.Repeat("3d", 32) + `"
  # u7-77aa01-p: a device's key, previous: until 2026-11-18 09:30 UTC
  "` + strings.Repeat("4e", 32) + `"
]
`
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
	if !strings.Contains(note, "they change") || !strings.Contains(note, "Leaving AllowedPublicKeys empty is simpler but open") ||
		strings.Contains(note, "warning") {
		t.Errorf("the note:\n%s", note)
	}

	// -names, before or after the service: rayd is asked for them, the
	// comments carry them, stderr warns.
	for _, args := range [][]string{{"-names", "ygg"}, {"ygg", "-names"}} {
		out, note, err := captureBoth(t, func() error { return (&cli{c: node}).service(ctx, "peer-keys", args) })
		if err != nil {
			t.Fatal(args, err)
		}
		want := peerKeysHeader + `  # u3: user alice, the user's own key (links of rayctl user export)
  "` + strings.Repeat("1b", 32) + `"
  # u3-3f2a9c1d: user alice, device phone
  "` + strings.Repeat("2c", 32) + `"
  # u3-3f2a9c1d-n: user alice, device phone, next: from 2026-12-01 10:00 UTC
  "` + strings.Repeat("3d", 32) + `"
  # u7-77aa01-p: user bob, device laptop, previous: until 2026-11-18 09:30 UTC
  "` + strings.Repeat("4e", 32) + `"
]
`
		if out != want {
			t.Fatalf("%q: got\n%s\nwant\n%s", args, out, want)
		}
		if !strings.Contains(note, "warning: with -names the block names users and devices on a host outside the node") {
			t.Errorf("%q: no warning:\n%s", args, note)
		}
	}
	if len(asked) != 3 || asked[0] || !asked[1] || !asked[2] {
		t.Errorf("names asked %v", asked)
	}

	// -json: the labels; the names only with -names.
	out, _, err = captureBoth(t, func() error { return (&cli{c: node, json: true}).service(ctx, "peer-keys", []string{"ygg"}) })
	if flat := strings.Join(strings.Fields(out), " "); err != nil || !strings.Contains(flat, `"nodeKey": "`+strings.Repeat("0a", 32)+`"`) ||
		!strings.Contains(flat, `"deviceId": "3f2a9c1d"`) || !strings.Contains(flat, `"credential": "next"`) ||
		!strings.Contains(flat, `"label": "u3-3f2a9c1d-n"`) || strings.Contains(out, "alice") || strings.Contains(out, "phone") {
		t.Errorf("-json: %v\n%s", err, out)
	}
	out, _, err = captureBoth(t, func() error { return (&cli{c: node, json: true}).service(ctx, "peer-keys", []string{"-names", "ygg"}) })
	if err != nil || !strings.Contains(out, "alice") || !strings.Contains(out, "phone") {
		t.Errorf("-json -names: %v\n%s", err, out)
	}
	// A node that gives names unasked: none printed all the same.
	leaky := peerKeysNode{r: samplePeerKeys, leak: true}
	for _, json := range []bool{false, true} {
		out, _, err := captureBoth(t, func() error { return (&cli{c: leaky, json: json}).service(ctx, "peer-keys", []string{"ygg"}) })
		if err != nil || strings.Contains(out, "alice") || strings.Contains(out, "laptop") {
			t.Errorf("names unasked (-json %v): %v\n%s", json, err, out)
		}
	}

	// A node's answer is not trusted into a config: a key that is not one
	// is refused, a label or name that would end its comment is defused.
	bad := &nodev1.GetYggdrasilPeerKeysResponse{Service: "ygg", NodeKey: strings.Repeat("0a", 32),
		Keys: []*nodev1.YggdrasilPeerKey{{PublicKey: `aa"` + "\n]\nPeers: [tls://evil:1]", User: "x"}}}
	if out, _, err := captureBoth(t, func() error { return (&cli{c: peerKeysNode{r: bad}}).service(ctx, "peer-keys", []string{"ygg"}) }); err == nil || out != "" ||
		!strings.Contains(err.Error(), "not one") {
		t.Errorf("a key that is not one: %v", err)
	}
	odd := &nodev1.GetYggdrasilPeerKeysResponse{Service: "ygg", NodeKey: strings.Repeat("0a", 32), NodeAddress: "200::1\n]",
		Keys: []*nodev1.YggdrasilPeerKey{{PublicKey: strings.Repeat("1b", 32), User: "x\n]\nPeers: [", DeviceId: "d", Device: "a\r\nb",
			Label: "u1\n]\nPeers: ["}}}
	out, _, err = captureBoth(t, func() error {
		return (&cli{c: peerKeysNode{r: odd}}).service(ctx, "peer-keys", []string{"-names", "ygg"})
	})
	if err != nil || strings.Count(out, "\n") != 9 || strings.Contains(out, "Peers: [") {
		t.Errorf("odd names: %v\n%s", err, out)
	}

	unimplemented := peerKeysNode{err: connect.NewError(connect.CodeUnimplemented, errors.New("no"))}
	if err := (&cli{c: unimplemented}).service(ctx, "peer-keys", []string{"ygg"}); err == nil || !strings.Contains(err.Error(), "before v0.31.0") {
		t.Errorf("an older node: %v", err)
	}
	if err := (&cli{c: node}).service(ctx, "peer-keys", []string{"nope"}); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an unknown service: %v", err)
	}
	for _, args := range [][]string{nil, {"ygg", "more"}, {"-names"}, {"-name", "ygg"}, {"ygg", "-names", "more"}} {
		if _, _, err := captureBoth(t, func() error { return (&cli{c: node}).service(ctx, "peer-keys", args) }); !errors.Is(err, errUsage) {
			t.Errorf("%q: %v", args, err)
		}
	}
}
