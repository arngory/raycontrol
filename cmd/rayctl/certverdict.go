package main

import (
	"fmt"
	"time"

	"github.com/arngory/raycontrol/internal/roots"
)

// certVerdict tells the administrator, after rayctl service cert, what
// clients will accept (spec/cert-pin-v1.md §7): naive verifies the chain
// as Chrome does and matches its root against the app's own list; the
// chain is checked here against the node's embedded list, the same one.
// A warning, never a refusal: a private CA is a legitimate choice.
func certVerdict(chainPEM []byte, now time.Time) string {
	const how = "(naive verifies it as Chrome does and matches its root against the app's list, Chrome's without CAs based\n" +
		"in China or Mozilla's; roots installed on the phone count only with an app setting, over HTTP/2; QUIC: a further switch)\n"
	c := roots.CheckChain(chainPEM, now)
	var v string
	switch {
	case c.Kind == roots.Public:
		v = fmt.Sprintf("the chain leads to %s, a public root clients know: naive and DoH clients accept it\n", c.Root)
	case c.Kind == roots.Private:
		v = fmt.Sprintf("warning: the chain leads to %s, a root that is not in the clients' list: naive and DoH clients will\n"+
			"refuse it unless the root is added in the certificate field of each profile; over QUIC it works only so\n", c.Root)
	case c.Top == "":
		v = "warning: the chain is incomplete: no certificate in it could be read\n"
	default:
		v = fmt.Sprintf("warning: the chain is incomplete: it ends at %s, issued by %s, in neither the chain nor the clients'\n"+
			"list: import the whole chain (leaf, then intermediates); a private CA's, clients accept only with its root in each profile\n",
			c.Top, c.Issuer)
	}
	return v + how
}
