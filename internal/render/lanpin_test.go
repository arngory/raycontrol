package render

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestLANRelayPin: render writes lan_relay_mbps (lan-v1 §4.4) whenever an
// administrator sets lan_relay, and niko-server before v0.16.0 refuses the
// option, and with it the whole Yggdrasil backend: every user of the node
// cut. A pin to an older niko-server must stop writing it first. LAN groups
// and the traffic line come with v0.16.0 too.
func TestLANRelayPin(t *testing.T) {
	f, err := os.Open("../../deploy/versions.env")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tag := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "NIKO_SERVER_TAG="); ok {
			tag = strings.Trim(v, `"`)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(strings.TrimPrefix(tag, "v"), ".", 3)
	if len(parts) != 3 {
		t.Fatalf("NIKO_SERVER_TAG %q is not vX.Y.Z", tag)
	}
	var n [3]int
	for i, p := range parts {
		p, _, _ = strings.Cut(p, "-")
		if n[i], err = strconv.Atoi(p); err != nil {
			t.Fatalf("NIKO_SERVER_TAG %q: %v", tag, err)
		}
	}
	if n[0] == 0 && n[1] < 16 {
		t.Fatalf("niko-server %s is older than v0.16.0, but render writes lan_relay_mbps and LAN groups", tag)
	}
}
