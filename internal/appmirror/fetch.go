package appmirror

import (
	"bufio"
	"bytes"
	"cmp"
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

// ghRelease is what the GitHub API says of a release. Its prerelease flag
// is not used: the kind is the tag's (a "-" in it), which the trusted
// comment binds; GitHub's flag is not signed.
type ghRelease struct {
	Tag    string    `json:"tag_name"`
	Draft  bool      `json:"draft"`
	Assets []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"browser_download_url"`
}

const (
	// maxTries: newer releases of a kind fetched in one check, newest
	// first; one that does not verify is not tried again for failMemory,
	// one not yet whole on GitHub (errIncomplete) costs no try.
	maxTries   = 3
	failMemory = 24 * time.Hour
	// releaseTimeout bounds the fetch of a release (a host that drips).
	releaseTimeout = 45 * time.Minute
	// spare is the room left beside a release being fetched.
	spare = 64 << 20
)

var (
	// errUnverified marks a release that does not verify (signature,
	// names, sizes, hashes), as against one the network failed to bring.
	errUnverified = errors.New("does not verify")
	// errIncomplete marks a release whose assets are not all up (yet):
	// its upload still going, or dead. Seen from the listing and
	// SHA256SUMS, it costs no try: a few of them do not hold back an older
	// release that is whole.
	errIncomplete = errors.New("not whole")
)

func unverified(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errUnverified, fmt.Sprintf(format, a...))
}

var (
	// Tags are semver, and a path segment of their own.
	tagRe = regexp.MustCompile(`^v[0-9A-Za-z.+-]{1,64}$`)
	// Names in SHA256SUMS: a file name, nothing that walks a path.
	nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

func validTag(tag string) bool { return tagRe.MatchString(tag) && semverValid(tag) }

// isPre: a pre-release tag (v1.39.0-rc1), as the client's release
// workflow marks them on GitHub.
func isPre(tag string) bool {
	core, _, _ := strings.Cut(tag, "+")
	return strings.Contains(core, "-")
}

func validName(name string) bool {
	return nameRe.MatchString(name) && name != "." && name != ".." && name != manifestName
}

func (m *Mirror) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	m.clientOnce.Do(func() {
		m.ownClient = &http.Client{
			Timeout: 30 * time.Minute, // a file; releaseTimeout bounds a release
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   30 * time.Second,
				ResponseHeaderTimeout: 60 * time.Second,
				IdleConnTimeout:       90 * time.Second,
				ForceAttemptHTTP2:     true,
			},
			CheckRedirect: m.redirect,
		}
	})
	return m.ownClient
}

// redirect follows GitHub's redirects to its asset hosts, over HTTPS only
// (AllowHTTP: a test source).
func (m *Mirror) redirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if !m.urlOK(req.URL) {
		return fmt.Errorf("redirect to %s://%s", req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// urlOK: GitHub's hosts over HTTPS; a test source (API set) any host, plain
// HTTP too with AllowHTTP.
func (m *Mirror) urlOK(u *url.URL) bool {
	if u.Scheme != "https" && (!m.AllowHTTP || u.Scheme != "http") {
		return false
	}
	if m.API != "" {
		return true
	}
	h := u.Hostname()
	return h == "github.com" || strings.HasSuffix(h, ".githubusercontent.com")
}

// Sync brings the mirror to the newest releases (app-update-v1 §3).
func (m *Mirror) Sync(ctx context.Context) error {
	defer m.client().CloseIdleConnections()
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

// syncWith keeps, of each kind, the held release unless a newer one
// verifies: never an older one in its place (a release deleted or hidden on
// GitHub), nothing dropped for a list without candidates, and a newer one
// that fails leaves the held one. A pre-release stays only while it is
// newer than the stable release kept.
func (m *Mirror) syncWith(ctx context.Context, list []ghRelease) error {
	m.mu.Lock()
	held := slices.Clone(m.held)
	m.mu.Unlock()
	var heldStable, heldPre *Release
	for i := range held {
		if held[i].Prerelease {
			heldPre = &held[i]
		} else {
			heldStable = &held[i]
		}
	}
	var stables, pres []ghRelease
	for _, r := range list {
		switch {
		case r.Draft || !validTag(r.Tag):
		case isPre(r.Tag):
			pres = append(pres, r)
		default:
			stables = append(stables, r)
		}
	}
	newest := func(a, b ghRelease) int { return semverCompare(b.Tag, a.Tag) }
	slices.SortStableFunc(stables, newest)
	slices.SortStableFunc(pres, newest)
	var errs []error
	stable := m.newest(ctx, stables, heldStable, &errs)
	if stable != nil {
		pres = slices.DeleteFunc(pres, func(r ghRelease) bool { return semverCompare(r.Tag, stable.Tag) <= 0 })
	}
	pre := m.newest(ctx, pres, heldPre, &errs)
	var next []Release
	for _, r := range []*Release{stable, pre} {
		if r != nil {
			next = append(next, *r)
		}
	}
	next = pick(next)
	m.mu.Lock()
	m.held = next
	m.mu.Unlock()
	m.prune(next)
	return errors.Join(errs...)
}

// newest is the newest release of a kind the mirror can hold: the held
// one, unless one of the candidates newer than it (newest first) verifies.
func (m *Mirror) newest(ctx context.Context, cands []ghRelease, held *Release, errs *[]error) *Release {
	tries := 0
	for _, c := range cands {
		if held != nil && semverCompare(c.Tag, held.Tag) <= 0 {
			break
		}
		if m.failedLately(c.Tag) {
			continue
		}
		if tries == maxTries || ctx.Err() != nil {
			break
		}
		r, err := m.fetch(ctx, c)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("%s: %w", c.Tag, err))
			switch {
			case errors.Is(err, errIncomplete):
			case errors.Is(err, errUnverified):
				m.remember(c.Tag)
				tries++
			default:
				tries++
			}
			continue
		}
		m.log().Info("client release mirrored", "app", App, "tag", r.Tag, "files", len(r.Files), "bytes", r.Bytes())
		return &r
	}
	return held
}

func (m *Mirror) failedLately(tag string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.failed[tag]
	return ok && time.Since(t) < failMemory
}

func (m *Mirror) remember(tag string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed == nil {
		m.failed = map[string]time.Time{}
	}
	for t, at := range m.failed {
		if time.Since(at) >= failMemory {
			delete(m.failed, t)
		}
	}
	m.failed[tag] = time.Now()
}

// list asks GitHub for the client's latest releases, unauthenticated (the
// repository is public).
func (m *Mirror) list(ctx context.Context) ([]ghRelease, error) {
	api := m.API
	if api == "" {
		api = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api+"/repos/"+Repo+"/releases?per_page=100", nil)
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list); err != nil {
		return nil, fmt.Errorf("the client's releases: %w", err)
	}
	return list, nil
}

// fetch downloads a release into a directory of its own, verifies it whole
// and only then moves it into place.
func (m *Mirror) fetch(ctx context.Context, gr ghRelease) (Release, error) {
	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()
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
		return Release{}, fmt.Errorf("%w: %w", errUnverified, err)
	}
	listed, err := parseSums(sums)
	if err != nil {
		return Release{}, fmt.Errorf("%w: %w", errUnverified, err)
	}
	var total int64
	for _, f := range listed {
		a, ok := assets[f.Name]
		switch {
		case !ok:
			return Release{}, fmt.Errorf("%w: %s is listed but not in the release", errIncomplete, f.Name)
		case a.Size <= 0 || a.Size > MaxFile:
			return Release{}, unverified("%s: %d bytes (at most %d)", f.Name, a.Size, MaxFile)
		}
		total += a.Size
	}
	if total > MaxRelease {
		return Release{}, unverified("%d bytes in all (at most %d)", total, MaxRelease)
	}
	if err := os.MkdirAll(m.appDir(), 0o700); err != nil {
		return Release{}, err
	}
	if free, err := freeBytes(m.appDir()); err != nil {
		return Release{}, err
	} else if free < uint64(total)+spare {
		return Release{}, fmt.Errorf("%d MiB free in %s, the release takes %d MiB", free>>20, m.appDir(), total>>20)
	}
	stage, err := os.MkdirTemp(m.appDir(), ".fetch-")
	if err != nil {
		return Release{}, err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	r := Release{Tag: gr.Tag, Prerelease: isPre(gr.Tag)}
	for _, f := range []struct {
		name string
		b    []byte
	}{{sumsName, sums}, {sigName, sig}} {
		if err := writeSynced(filepath.Join(stage, f.name), f.b); err != nil {
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
	if err := writeSynced(filepath.Join(stage, manifestName), b); err != nil {
		return Release{}, err
	}
	if err := syncDir(stage); err != nil {
		return Release{}, err
	}
	final := filepath.Join(m.appDir(), r.Tag)
	if err := os.RemoveAll(final); err != nil {
		return Release{}, err
	}
	if err := os.Rename(stage, final); err != nil {
		return Release{}, err
	}
	return r, syncDir(m.appDir())
}

// writeSynced writes a new file and flushes it to the disk: a release is
// whole on the disk before it is moved into place.
func writeSynced(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a checked name in rayd's staging directory
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	return cmp.Or(err, f.Close())
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: rayd's own directory
	if err != nil {
		return err
	}
	err = d.Sync()
	return cmp.Or(err, d.Close())
}

// small downloads a release's small file into memory.
func (m *Mirror) small(ctx context.Context, assets map[string]ghAsset, name string, limit int64) ([]byte, error) {
	a, ok := assets[name]
	if !ok {
		return nil, fmt.Errorf("%w: no %s in the release", errIncomplete, name)
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
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return err
	case cw.n != a.Size:
		return unverified("%d bytes, the release says %d", cw.n, a.Size)
	case hex.EncodeToString(h.Sum(nil)) != want:
		return unverified("SHA-256 differs from SHA256SUMS")
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

// get copies at most limit bytes of a URL to w; more is an error.
func (m *Mirror) get(ctx context.Context, raw string, limit int64, w io.Writer) error {
	u, err := url.Parse(raw)
	if err != nil || !m.urlOK(u) {
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
		return unverified("more than %d bytes", limit)
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
