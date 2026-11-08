package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/release"
)

// archiveMembers are the files the Release workflow puts in the archive.
func archiveMembers(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`tar -czf "raycontrol-linux-\$\{GOARCH\}\.tar\.gz" -C dist (.+)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("no archive line in release.yml")
	}
	return strings.Fields(string(m[1]))
}

// The archive's format is what every rayctl since v0.15.0 takes
// (docs/RELEASE.md): plain files with plain names, at most 64; a new
// component (a transport's binary) is one more such file, and this rayctl
// installs every one of them, whichever rayctl ran the update (it applies
// with RAYCONTROL_UPDATE_STAGE). A layout those rayctls refuse needs a
// stepping-stone release first; a name rayctl before v0.15.0 refuses is
// release.TestArchiveFiles's.
func TestArchiveMembersInstalled(t *testing.T) {
	members := archiveMembers(t)
	for _, want := range []string{"rayctl", "VERSIONS"} {
		if !slices.Contains(members, want) {
			t.Errorf("the archive has no %s: every rayctl needs it", want)
		}
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range members {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: 1, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if names, err := release.Extract(buf.Bytes(), t.TempDir()); err != nil || len(names) != len(members) {
		t.Fatalf("Extract (as rayctl since v0.15.0 has it): %v, %v", names, err)
	}
	for _, name := range members {
		if _, ok := nodeBinaries[name]; ok || name == "VERSIONS" || slices.Contains(deploy.DataFiles, name) {
			continue
		}
		t.Errorf("%s is in the archive, and rayctl update does not install it: add it to nodeBinaries (or deploy.DataFiles)", name)
	}
}
