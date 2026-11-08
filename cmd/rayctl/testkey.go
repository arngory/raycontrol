//go:build releasetest

package main

import "os"

// A test build (go build -tags releasetest) checks releases with the key
// in RAYCONTROL_TEST_RELEASE_KEY: the CI signs a release of its own build
// to test the update's handoff. Release builds have no such tag
// (TestReleaseBuildHasNoTestKey).
func init() {
	if k := os.Getenv("RAYCONTROL_TEST_RELEASE_KEY"); k != "" {
		releaseKey = k
	}
}
