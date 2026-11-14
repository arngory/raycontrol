package release

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// ErrNotFound: the server has no such file (HTTP 404), as for a release
// that was never published or was taken down.
var ErrNotFound = errors.New("not found")

// MaxPatchProbes bounds the releases NewestPatch asks for in one call:
// each one found costs two requests (SHA256SUMS and its signature), each
// one missing one.
const MaxPatchProbes = 8

// NewestPatch is the newest patch release of the minor version of
// installed (vX.Y.Z) newer than it, "" when there is none: GitHub's
// "latest" names only the newest release overall, and a node that keeps
// to its minor version (the auto update, spec/node-update-v1.md §1) would
// never see v0.26.1 once v0.27.0 is out. Releases are not listed (no
// GitHub API and its limits): the next patch numbers are asked for by
// their files, vX.Y.Z+1 and up, each verified as Latest verifies (the
// version is the one its signature names, and must be the one asked for).
// One missing number is stepped over (a release taken down, its fix
// after it); two in a row end the search, and so does MaxPatchProbes.
// An error other than a missing release ends it too, with what it found.
func (f *Fetcher) NewestPatch(ctx context.Context, pubKey, installed string) (string, error) {
	p := parts(installed)
	if p == nil {
		return "", fmt.Errorf("%q is not a release", installed)
	}
	newest, missed := "", 0
	for n := p[2] + 1; n <= p[2]+MaxPatchProbes; n++ {
		v := "v" + strconv.Itoa(p[0]) + "." + strconv.Itoa(p[1]) + "." + strconv.Itoa(n)
		switch err := f.signed(ctx, v, pubKey); {
		case errors.Is(err, ErrNotFound):
			if missed++; missed == 2 {
				return newest, nil
			}
		case err != nil:
			return newest, err
		default:
			newest, missed = v, 0
		}
	}
	return newest, nil
}

// signed checks that release v is published and signed as v.
func (f *Fetcher) signed(ctx context.Context, v, pubKey string) error {
	sums, err := f.Get(ctx, v, "SHA256SUMS", 1<<16)
	if err != nil {
		return err
	}
	sig, err := f.Get(ctx, v, "SHA256SUMS.minisig", 1<<12)
	if err != nil {
		return err
	}
	trusted, err := Verify(sums, sig, pubKey)
	if err != nil {
		return fmt.Errorf("SHA256SUMS of %s: %w", v, err)
	}
	got, err := VersionOf(trusted)
	if err == nil && got != v {
		err = fmt.Errorf("SHA256SUMS of %s is signed as %s", v, got)
	}
	return err
}
