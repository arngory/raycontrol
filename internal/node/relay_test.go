package node

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/perimeter"
)

// A relay's bundle whose exit address has a zone is refused: netip takes
// any text after the "%" as the zone, newlines too, and rayspa -relay put
// the address into its nft table as it is, where the rest was nft commands
// of the bundle's, run by root on the relay.
// testdata/fuzz/FuzzDecodeRelayBundle/exit-zone.
func TestRelayBundleExitZone(t *testing.T) {
	evil := "fe80::1%x\nflush ruleset\n"
	a, err := netip.ParseAddr(evil)
	if err != nil || !strings.Contains((&perimeter.NFT{RelayTo: a}).Ruleset(), "\nflush ruleset\n") {
		t.Fatalf("the zone no longer goes into the table as it is (%v): this test says nothing", err)
	}
	for _, exit := range []string{evil, "fe80::1%eth0", "2001:db8::7%1"} {
		j := `{"v":1,"name":"r","exit":"` + strings.ReplaceAll(exit, "\n", `\n`) + `","api":{"port":1,"pin":"p"},"cert":"c"}`
		if b, err := DecodeRelayBundle(RelayBundlePrefix + base64.RawURLEncoding.EncodeToString([]byte(j))); err == nil {
			t.Errorf("exit %q taken: %+v", exit, b)
		}
	}
	ok := `{"v":1,"name":"r","exit":"2001:db8::7","api":{"port":1,"pin":"p"},"cert":"c"}`
	if _, err := DecodeRelayBundle(RelayBundlePrefix + base64.RawURLEncoding.EncodeToString([]byte(ok))); err != nil {
		t.Fatal(err)
	}
}
