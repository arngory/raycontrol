// Package deploy gives the Go code the pins of versions.env, the file CI,
// the release workflow and scripts/niko-server.sh read: one source, so
// what render writes for a data-plane binary follows the binary a release
// ships with it.
package deploy

import (
	_ "embed"
	"strings"
)

//go:embed versions.env
var versionsEnv string

// Pin is a variable of versions.env without its quotes, "" when the file
// has none of that name.
func Pin(name string) string {
	for _, line := range strings.Split(versionsEnv, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), name+"="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// NikoServerTag is the niko-server release raycontrol ships (vX.Y.Z).
var NikoServerTag = Pin("NIKO_SERVER_TAG")
