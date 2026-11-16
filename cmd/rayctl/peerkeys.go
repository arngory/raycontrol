package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// peerKeys prints the public keys a Yggdrasil peer of the operator's own
// (yggdrasil-go 0.5, peers=) lets in with AllowedPublicKeys
// (GetYggdrasilPeerKeys): the node's, then each user's and device's, as
// an HJSON block for its config, a comment above each key with its label
// in the node's users file. The users' and devices' names only with
// -names: the block goes to a host outside the node (lan-v1 §4.3). What
// changes it goes to stderr.
func (c *cli) peerKeys(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("service peer-keys", flag.ContinueOnError)
	withNames := fs.Bool("names", false, "name the users and devices too, in the comments and in -json: the block then "+
		"names people on a host outside the node")
	// -names before or after the service's name.
	if err := fs.Parse(args); err != nil || fs.NArg() < 1 {
		return errUsage
	}
	name := fs.Arg(0)
	if err := fs.Parse(fs.Args()[1:]); err != nil || fs.NArg() != 0 {
		return errUsage
	}
	r, err := c.c.GetYggdrasilPeerKeys(ctx, connect.NewRequest(&nodev1.GetYggdrasilPeerKeysRequest{Service: name, Names: *withNames}))
	if connect.CodeOf(err) == connect.CodeUnimplemented {
		return errors.New("the node runs a version before v0.31.0, which does not list the keys its Yggdrasil service lets in")
	}
	if err != nil {
		return err
	}
	// The node's answer goes into the operator's config: keys that are
	// keys only, names that cannot end a comment, and none unless asked.
	for _, k := range append([]string{r.Msg.NodeKey}, keysOf(r.Msg.Keys)...) {
		if !publicKeyHex(k) {
			return fmt.Errorf("the node gave %q as a key, which is not one", k)
		}
	}
	if !*withNames {
		for _, k := range r.Msg.Keys {
			k.User, k.Device = "", ""
		}
	}
	if err := c.print(r.Msg, func(w *tabwriter.Writer) { writePeerKeys(w, r.Msg) }); err != nil {
		return err
	}
	if *withNames {
		fmt.Fprint(os.Stderr, peerKeysNamesWarning)
	}
	fmt.Fprint(os.Stderr, peerKeysNote)
	return nil
}

// peerKeysNamesWarning says on stderr what -names costs.
const peerKeysNamesWarning = "warning: with -names the block names users and devices on a host outside the node: whoever reads its\n" +
	"config there can tie a peering's address to a person; without -names it carries the node's own numbers only\n"

// peerKeysNote says on stderr why the list is a moving one.
const peerKeysNote = `note: these are the keys the node lets in now, and they change: a device added or revoked, a user
enabled, disabled, expired or over the limit, and each user's credential switch (every -cred-period,
30 days by default: the next keys are listed from -cred-lead, 3 days, before it, the previous ones for
-cred-grace, 2 days, after). A peer that keeps to AllowedPublicKeys must take each change, or the clients
it leaves out lose their path through it. Leaving AllowedPublicKeys empty is simpler but open: anyone who
learns the peer's address can then peer with it, ask it for its peers' keys (the node's and the devices'
connected now) and send frames to clients that go through it past the node's filter (spec/lan-v1.md §2.1,
§2.3), as with a public peer.
`

func keysOf(keys []*nodev1.YggdrasilPeerKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.PublicKey)
	}
	return out
}

// publicKeyHex reports an ed25519 public key in hex, as yggdrasil-go's
// AllowedPublicKeys takes it.
func publicKeyHex(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}

// commentSafe is s for a comment line of HJSON: the store's names are
// [a-z0-9._-] already, a node's answer is not trusted to keep to it.
func commentSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-:", r) {
			return r
		}
		return '?'
	}, s)
}

// writePeerKeys writes the AllowedPublicKeys block: HJSON, as yggdrasil-go
// reads its config (comments with #, one quoted key a line). Each comment
// starts with the key's label (u<user id>, -<device id>, -n, -p), and
// names the user and the device only when the answer has their names.
func writePeerKeys(w io.Writer, r *nodev1.GetYggdrasilPeerKeysResponse) {
	day := func(unix int64) string { return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04 UTC") }
	fmt.Fprintf(w, "# The keys the node's Yggdrasil service %s lets in, for AllowedPublicKeys of a peer of yours\n"+
		"# (yggdrasil-go 0.5, HJSON): public keys only. Labels as in the node's users file: u<user id>\n"+
		"# (rayctl -json user list), -<device id> (rayctl device list), -n the next key, -p the previous one.\n",
		commentSafe(r.Service))
	fmt.Fprintln(w, "AllowedPublicKeys: [")
	fmt.Fprintf(w, "  # the node (%s), which peers with yours\n  %q\n", commentSafe(r.NodeAddress), r.NodeKey)
	for _, k := range r.Keys {
		var who []string
		if k.User != "" {
			who = append(who, "user "+commentSafe(k.User))
		}
		switch {
		case k.DeviceId == "":
			who = append(who, "the user's own key (links of rayctl user export)")
		case k.Device != "":
			who = append(who, "device "+commentSafe(k.Device))
		default:
			who = append(who, "a device's key")
		}
		switch k.Credential {
		case "next":
			who = append(who, "next: from "+day(k.From))
		case "previous":
			who = append(who, "previous: until "+day(k.Until))
		}
		fmt.Fprintf(w, "  # %s: %s\n  %q\n", commentSafe(k.Label), strings.Join(who, ", "), k.PublicKey)
	}
	fmt.Fprintln(w, "]")
}
