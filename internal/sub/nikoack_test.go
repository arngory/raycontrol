package sub

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestNikoAckPin: HysteriaLink promises niko-ack=1, which only niko-server
// v0.14.1 and later keep (the TCP response right after the dial). A pin to an
// older niko-server must drop the parameter first.
func TestNikoAckPin(t *testing.T) {
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
	if n[0] == 0 && (n[1] < 14 || n[1] == 14 && n[2] < 1) {
		t.Fatalf("niko-server %s is older than v0.14.1, but hysteria2 links carry niko-ack=1", tag)
	}
}
