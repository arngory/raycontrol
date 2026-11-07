package appmirror

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// ghRelease is what the GitHub API says of a release.
type ghRelease struct {
	Tag        string    `json:"tag_name"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Assets     []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"browser_download_url"`
}

var (
	// Tags are semver, and a path segment of their own.
	tagRe = regexp.MustCompile(`^v[0-9A-Za-z.+-]{1,64}$`)
	// Names in SHA256SUMS: a file name, nothing that walks a path.
	nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

func validTag(tag string) bool { return tagRe.MatchString(tag) && semverValid(tag) }

func validName(name string) bool {
	return nameRe.MatchString(name) && name != "." && name != ".." && name != manifestName
}

func (m *Mirror) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return &http.Client{
		// A file a minute at the least; the context bounds a release.
		Timeout: 30 * time.Minute,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: httpsOnly,
	}
}

// httpsOnly follows GitHub's redirects to its asset hosts, over HTTPS only.
func httpsOnly(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("redirect to %s", req.URL.Scheme)
	}
	return nil
}

// Sync brings the mirror to the newest releases (app-update-v1 §3): those
// it holds stay, a new one is fetched and verified whole before it takes
// the place of the one before it; a release that fails leaves the one it
// was to replace.
func (m *Mirror) Sync(ctx context.Context) error {
	list, err := m.list(ctx)
	if err == nil {
		err = m.syncWith(ctx, list)
	}
	m.mu.Lock()
	m.checked = time.Now()
	m.lastErr = ""
	if err != nil {
		m.lastErr = err.Error()
	}
	m.mu.Unlock()
	return err
}

func (m *Mirror) syncWith(ctx context.Context, list []ghRelease) error {
	stable, pre := choose(list)
	m.mu.Lock()
	held := slices.Clone(m.held)
	m.mu.Unlock()
	var next []Release
	var errs []error
	take := func(gr *ghRelease, prerelease bool) {
		if gr == nil {
			return
		}
		if i := slices.IndexFunc(held, func(r Release) bool { return r.Tag == gr.Tag }); i >= 0 {
			next = append(next, held[i])
			return
		}
		r, err := m.fetch(ctx, *gr, prerelease)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", gr.Tag, err))
			if i := slices.IndexFunc(held, func(r Release) bool { return r.Prerelease == prerelease }); i >= 0 {
				next = append(next, held[i])
			}
			return
		}
		m.log().Info("client release mirrored", "app", App, "tag", r.Tag, "files", len(r.Files), "bytes", r.Bytes())
		next = append(next, r)
	}
	take(stable, false)
	take(pre, true)
	next = pick(next)
	m.mu.Lock()
	m.held = next
	m.mu.Unlock()
	m.prune(next)
	return errors.Join(errs...)
}

// choose is the newest stable release and the newest pre-release newer
// than it, among those whose tags are semver; drafts are left.
func choose(list []ghRelease) (stable, pre *ghRelease) {
	for i := range list {
		r := &list[i]
		if r.Draft || !validTag(r.Tag) {
			continue
		}
		if r.Prerelease {
			if pre == nil || semverCompare(r.Tag, pre.Tag) > 0 {
				pre = r
			}
		} else if stable == nil || semverCompare(r.Tag, stable.Tag) > 0 {
			stable = r
		}
	}
	if pre != nil && stable != nil && semverCompare(pre.Tag, stable.Tag) <= 0 {
		pre = nil
	}
	return stable, pre
}

// list asks GitHub for the client's latest releases, unauthenticated (the
// repository is public).
func (m *Mirror) list(ctx context.Context) ([]ghRelease, error) {
	api := m.API
	if api == "" {
		api = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api+"/repos/"+Repo+"/releases?per_page=30", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "raycontrol")
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("the client's releases: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the client's releases: %s", resp.Status)
	}
	var list []ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&list); err != nil {
		return nil, fmt.Errorf("the client's releases: %w", err)
	}
	return list, nil
}

// fetch downloads a release into a directory of its own, verifies it whole
// and only then moves it into place.
func (m *Mirror) fetch(ctx context.Context, gr ghRelease, prerelease bool) (Release, error) {
	assets := map[string]ghAsset{}
	for _, a := range gr.Assets {
		assets[a.Name] = a
	}
	sums, err := m.small(ctx, assets, sumsName, maxSums)
	if err != nil {
		return Release{}, err
	}
	sig, err := m.small(ctx, assets, sigName, maxSig)
	if err != nil {
		return Release{}, err
	}
	if err := m.verify(gr.Tag, sums, sig); err != nil {
		return Release{}, err
	}
	listed, err := parseSums(sums)
	if err != nil {
		return Release{}, err
	}
	var total int64
	for _, f := range listed {
		a, ok := assets[f.Name]
		switch {
		case !ok:
			return Release{}, fmt.Errorf("%s is listed but not in the release", f.Name)
		case a.Size <= 0 || a.Size > MaxFile:
			return Release{}, fmt.Errorf("%s: %d bytes (at most %d)", f.Name, a.Size, MaxFile)
		}
		total += a.Size
	}
	if total > MaxRelease {
		return Release{}, fmt.Errorf("%d bytes in all (at most %d)", total, MaxRelease)
	}
	if err := os.MkdirAll(m.appDir(), 0o700); err != nil {
		return Release{}, err
	}
	stage, err := os.MkdirTemp(m.appDir(), ".fetch-")
	if err != nil {
		return Release{}, err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	r := Release{Tag: gr.Tag, Prerelease: prerelease}
	for _, f := range []struct {
		name string
		b    []byte
	}{{sumsName, sums}, {sigName, sig}} {
		if err := os.WriteFile(filepath.Join(stage, f.name), f.b, 0o600); err != nil {
			return Release{}, err
		}
		sum := sha256.Sum256(f.b)
		r.Files = append(r.Files, File{Name: f.name, Size: int64(len(f.b)), SHA256: hex.EncodeToString(sum[:])})
	}
	for _, f := range listed {
		a := assets[f.Name]
		if err := m.download(ctx, a, filepath.Join(stage, f.Name), f.SHA256); err != nil {
			return Release{}, fmt.Errorf("%s: %w", f.Name, err)
		}
		r.Files = append(r.Files, File{Name: f.Name, Size: a.Size, SHA256: f.SHA256})
	}
	r.Verified = time.Now().UTC()
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return Release{}, err
	}
	if err := os.WriteFile(filepath.Join(stage, manifestName), b, 0o600); err != nil {
		return Release{}, err
	}
	final := filepath.Join(m.appDir(), r.Tag)
	if err := os.RemoveAll(final); err != nil {
		return Release{}, err
	}
	if err := os.Rename(stage, final); err != nil {
		return Release{}, err
	}
	return r, nil
}

// small downloads a release's small file into memory.
func (m *Mirror) small(ctx context.Context, assets map[string]ghAsset, name string, limit int64) ([]byte, error) {
	a, ok := assets[name]
	if !ok {
		return nil, fmt.Errorf("no %s in the release", name)
	}
	var buf bytes.Buffer
	if err := m.get(ctx, a.URL, limit, &buf); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return buf.Bytes(), nil
}

// download writes an asset to path, exactly its size, and checks its
// SHA-256 against SHA256SUMS.
func (m *Mirror) download(ctx context.Context, a ghAsset, path, want string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a checked name in rayd's staging directory
	if err != nil {
		return err
	}
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(f, h)}
	err = m.get(ctx, a.URL, a.Size, cw)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return err
	case cw.n != a.Size:
		return fmt.Errorf("%d bytes, the release says %d", cw.n, a.Size)
	case hex.EncodeToString(h.Sum(nil)) != want:
		return errors.New("SHA-256 differs from SHA256SUMS")
	}
	return nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// get copies at most limit bytes of an HTTPS URL to w; more is an error.
func (m *Mirror) get(ctx context.Context, raw string, limit int64, w io.Writer) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return fmt.Errorf("asset URL %q", raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "raycontrol")
	resp, err := m.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("more than %d bytes", limit)
	}
	return nil
}

// parseSums reads SHA256SUMS ("<hex>  <name>" a line, sha256sum's form);
// every name a plain file name, once.
func parseSums(b []byte) ([]File, error) {
	var out []File
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		sum, name, ok := strings.Cut(line, " ")
		name = strings.TrimPrefix(strings.TrimLeft(name, " "), "*")
		if _, err := hex.DecodeString(sum); !ok || err != nil || len(sum) != 64 {
			return nil, fmt.Errorf("SHA256SUMS: line %q", line)
		}
		if !validName(name) || name == sumsName || name == sigName {
			return nil, fmt.Errorf("SHA256SUMS: name %q", name)
		}
		if slices.ContainsFunc(out, func(f File) bool { return f.Name == name }) {
			return nil, fmt.Errorf("SHA256SUMS: %s twice", name)
		}
		out = append(out, File{Name: name, SHA256: strings.ToLower(sum)})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("SHA256SUMS lists nothing")
	}
	return out, nil
}
