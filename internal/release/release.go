// Package release fetches and verifies raycontrol releases for rayctl
// update (docs/08-decisions.md, R4-12): the archive of an architecture,
// SHA256SUMS and its minisign signature, checked with the same key as
// install/bootstrap.sh. The version comes from the signed trusted comment,
// so a mirror cannot pass an older release off as the latest one.
package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Repo is where releases are published.
const Repo = "arngory/raycontrol"

// PubKey is the minisign public key of releases, key ID A9C7802E23B87A01
// (docs/RELEASE.md); install/bootstrap.sh carries the same line.
const PubKey = "RWQBergjLoDHqeme5vyIuIRXJLjTj1EF3jR1nlWBVJO3rWxgy9SZj4bD"

// DefaultMirrors are URL prefixes tried when github.com does not answer,
// as in bootstrap.sh; the signature makes any mirror safe to use.
var DefaultMirrors = []string{"https://ghfast.top/", "https://gh-proxy.com/"}

// Files are what an archive may hold; anything else is refused.
var Files = []string{"rayd", "rayspa", "rayctl", "xray", "niko-server", "VERSIONS", "ipinfo_lite.mmdb", "NOTICE"}

// Verify checks a minisign signature of msg with a public key (the base64
// line of a .pub file) and returns the trusted comment. Both the
// signature of the file (Ed25519 over BLAKE2b-512, or over the file for
// legacy signatures) and the global signature over the trusted comment
// must hold.
func Verify(msg, sigFile []byte, pubKey string) (trusted string, err error) {
	pk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubKey))
	if err != nil || len(pk) != 42 || string(pk[:2]) != "Ed" {
		return "", errors.New("minisign: bad public key")
	}
	lines := strings.Split(strings.ReplaceAll(string(sigFile), "\r\n", "\n"), "\n")
	if len(lines) < 4 {
		return "", errors.New("minisign: short signature file")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil || len(sig) != 74 {
		return "", errors.New("minisign: bad signature")
	}
	if !bytes.Equal(sig[2:10], pk[2:10]) {
		return "", errors.New("minisign: signed with another key")
	}
	key := ed25519.PublicKey(pk[10:])
	signed := msg
	switch string(sig[:2]) {
	case "ED":
		h := blake2b.Sum512(msg)
		signed = h[:]
	case "Ed":
	default:
		return "", errors.New("minisign: unknown signature algorithm")
	}
	if !ed25519.Verify(key, signed, sig[10:]) {
		return "", errors.New("minisign: signature does not verify")
	}
	trusted, ok := strings.CutPrefix(lines[2], "trusted comment: ")
	if !ok {
		return "", errors.New("minisign: no trusted comment")
	}
	global, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil || len(global) != 64 || !ed25519.Verify(key, append(slices.Clone(sig[10:]), trusted...), global) {
		return "", errors.New("minisign: trusted comment does not verify")
	}
	return trusted, nil
}

// VersionOf reads the version from a release's trusted comment
// ("raycontrol v0.2.0").
func VersionOf(trusted string) (string, error) {
	v, ok := strings.CutPrefix(trusted, "raycontrol ")
	if !ok || !semver.MatchString(v) {
		return "", fmt.Errorf("not a raycontrol release: %q", trusted)
	}
	return v, nil
}

var semver = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// IsRelease reports whether v names a release (vX.Y.Z), not a dev build or
// a CI build's commit.
func IsRelease(v string) bool { return semver.MatchString(v) }

// Newer reports whether release version a is newer than b. Anything that is
// not vX.Y.Z (a "dev" build) is older than every release.
func Newer(a, b string) bool {
	pa, pb := parts(a), parts(b)
	if pa == nil {
		return false
	}
	if pb == nil {
		return true
	}
	for i := range 3 {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parts(v string) []int {
	if !semver.MatchString(v) {
		return nil
	}
	var out []int
	for _, s := range strings.Split(v[1:], ".") {
		n, _ := strconv.Atoi(s)
		out = append(out, n)
	}
	return out
}

// Fetcher downloads release files from GitHub, then from mirrors.
type Fetcher struct {
	Repo    string       // Repo when empty
	Base    string       // https://github.com when empty (a test seam)
	Mirrors []string     // URL prefixes
	HTTP    *http.Client // with timeouts when nil
	Log     func(format string, args ...any)
}

// URL is where a file of a version ("latest" or vX.Y.Z) is.
func (f *Fetcher) URL(version, file string) string {
	base, repo := f.Base, f.Repo
	if base == "" {
		base = "https://github.com"
	}
	if repo == "" {
		repo = Repo
	}
	if version == "latest" {
		return fmt.Sprintf("%s/%s/releases/latest/download/%s", base, repo, file)
	}
	return fmt.Sprintf("%s/%s/releases/download/%s/%s", base, repo, version, file)
}

// Get downloads a file of a version into memory (at most limit bytes).
func (f *Fetcher) Get(ctx context.Context, version, file string, limit int64) ([]byte, error) {
	hc := f.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Minute}
	}
	url := f.URL(version, file)
	var errs []error
	for _, prefix := range append([]string{""}, f.Mirrors...) {
		if prefix != "" && f.Log != nil {
			f.Log("github.com did not answer, trying %s (the signature still protects the files)", prefix)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, prefix+url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		_ = resp.Body.Close()
		switch {
		case err != nil:
			errs = append(errs, err)
		case resp.StatusCode != http.StatusOK:
			errs = append(errs, fmt.Errorf("%s: %s", prefix+url, resp.Status))
		case int64(len(b)) > limit:
			return nil, fmt.Errorf("%s: larger than %d bytes", file, limit)
		default:
			return b, nil
		}
	}
	return nil, fmt.Errorf("downloading %s: %w", file, errors.Join(errs...))
}

// Release is a verified release.
type Release struct {
	Version string
	Archive []byte // raycontrol-linux-<arch>.tar.gz
}

// Archive is the archive name of an architecture.
func Archive(arch string) string { return "raycontrol-linux-" + arch + ".tar.gz" }

// Fetch downloads and verifies a release ("latest" or vX.Y.Z) for an
// architecture: the signature of SHA256SUMS with pubKey, the version in
// it, then the archive's checksum.
func (f *Fetcher) Fetch(ctx context.Context, version, arch, pubKey string) (Release, error) {
	sums, err := f.Get(ctx, version, "SHA256SUMS", 1<<16)
	if err != nil {
		return Release{}, err
	}
	sig, err := f.Get(ctx, version, "SHA256SUMS.minisig", 1<<12)
	if err != nil {
		return Release{}, err
	}
	return f.verified(ctx, version, arch, pubKey, sums, sig)
}

// Latest is the version of the latest release, from its signed SHA256SUMS
// (the trusted comment, as Fetch reads it): what rayctl update would
// install, with no archive downloaded.
func (f *Fetcher) Latest(ctx context.Context, pubKey string) (string, error) {
	sums, err := f.Get(ctx, "latest", "SHA256SUMS", 1<<16)
	if err != nil {
		return "", err
	}
	sig, err := f.Get(ctx, "latest", "SHA256SUMS.minisig", 1<<12)
	if err != nil {
		return "", err
	}
	trusted, err := Verify(sums, sig, pubKey)
	if err != nil {
		return "", fmt.Errorf("SHA256SUMS: %w", err)
	}
	return VersionOf(trusted)
}

// Local verifies a release from a directory holding SHA256SUMS, its
// signature and the archive, as downloaded from the release page: for
// nodes that cannot reach GitHub or a mirror.
func Local(dir, arch, pubKey string) (Release, error) {
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, name)) } //nolint:gosec // G304: the operator's directory
	sums, err := read("SHA256SUMS")
	if err != nil {
		return Release{}, err
	}
	sig, err := read("SHA256SUMS.minisig")
	if err != nil {
		return Release{}, err
	}
	return check("latest", arch, pubKey, sums, sig, func(string) ([]byte, error) { return read(Archive(arch)) })
}

func (f *Fetcher) verified(ctx context.Context, version, arch, pubKey string, sums, sig []byte) (Release, error) {
	return check(version, arch, pubKey, sums, sig, func(signed string) ([]byte, error) {
		return f.Get(ctx, signed, Archive(arch), 512<<20)
	})
}

func check(version, arch, pubKey string, sums, sig []byte, archiveOf func(signed string) ([]byte, error)) (Release, error) {
	trusted, err := Verify(sums, sig, pubKey)
	if err != nil {
		return Release{}, fmt.Errorf("SHA256SUMS: %w", err)
	}
	signed, err := VersionOf(trusted)
	if err != nil {
		return Release{}, err
	}
	if version != "latest" && signed != version {
		return Release{}, fmt.Errorf("asked for %s, the signature says %s", version, signed)
	}
	want, err := sumOf(sums, Archive(arch))
	if err != nil {
		return Release{}, err
	}
	archive, err := archiveOf(signed)
	if err != nil {
		return Release{}, err
	}
	if got := sha256.Sum256(archive); !strings.EqualFold(hex.EncodeToString(got[:]), want) {
		return Release{}, fmt.Errorf("%s: checksum mismatch", Archive(arch))
	}
	return Release{Version: signed, Archive: archive}, nil
}

func sumOf(sums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS has no %s", name)
}

// Extract writes the archive's files to dir: only the names in Files, plain
// files, nothing outside dir. It returns the names written.
func Extract(archive []byte, dir string) ([]string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	var names []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return names, err
		}
		name := filepath.Clean(h.Name)
		if h.Typeflag != tar.TypeReg || !slices.Contains(Files, name) || slices.Contains(names, name) {
			return names, fmt.Errorf("unexpected %q in the archive", h.Name)
		}
		out, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755) //nolint:gosec // G302,G304: a name from Files in our temp dir
		if err != nil {
			return names, err
		}
		_, err = io.Copy(out, io.LimitReader(tr, 256<<20))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return names, err
		}
		names = append(names, name)
	}
}
