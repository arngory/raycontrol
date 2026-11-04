package asn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Provider is an online lookup service. It is only ever asked about a
// network address (Network), never about a client's own address.
type Provider interface {
	Name() string
	Lookup(ctx context.Context, network netip.Addr) (Info, error)
}

// Providers are the services an administrator may turn on, by name.
var Providers = map[string]func(token string, hc *http.Client) Provider{
	"ipinfo": func(token string, hc *http.Client) Provider { return &IPinfo{Token: token, HTTP: hc} },
}

// IPinfo is the IPinfo Lite API (api.ipinfo.io/lite): ASN, AS name and
// country, no limits on the free plan. The token goes in a header, not in
// the URL.
type IPinfo struct {
	Token   string
	BaseURL string // https://api.ipinfo.io by default
	HTTP    *http.Client
}

// Name is the provider's name.
func (p *IPinfo) Name() string { return "ipinfo" }

// Lookup asks about one address.
func (p *IPinfo) Lookup(ctx context.Context, network netip.Addr) (Info, error) {
	base := p.BaseURL
	if base == "" {
		base = "https://api.ipinfo.io"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/lite/"+network.String(), nil)
	if err != nil {
		return Info{}, err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Accept", "application/json")
	hc := p.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := hc.Do(req) //nolint:gosec // G107: a fixed host, the path is an address
	if err != nil {
		return Info{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Info{}, fmt.Errorf("ipinfo: %s", resp.Status)
	}
	var body struct {
		ASN         string `json:"asn"`
		ASName      string `json:"as_name"`
		CountryCode string `json:"country_code"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return Info{}, err
	}
	n, ok := ParseASN(body.ASN)
	if !ok {
		return Info{}, errNoAS
	}
	return Info{ASN: n, Name: body.ASName, Country: body.CountryCode}, nil
}

var errNoAS = errors.New("no AS for this network")

// API is a Source over a Provider: one question per network, the answers
// kept in memory (a day; a failure an hour), at most MaxCached networks.
type API struct {
	Provider Provider
	now      func() time.Time

	mu    sync.Mutex
	cache map[netip.Prefix]cached
}

type cached struct {
	info    Info
	ok      bool
	expires time.Time
}

// MaxCached bounds the networks an API source remembers.
const MaxCached = 10000

func (a *API) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// Lookup asks the provider about the address's network, unless it is not
// public or the answer is cached.
func (a *API) Lookup(ctx context.Context, addr netip.Addr) (Info, bool) {
	if a == nil || a.Provider == nil || !Public(addr) {
		return Info{}, false
	}
	network := Network(addr)
	now := a.clock()
	a.mu.Lock()
	if c, ok := a.cache[network]; ok && now.Before(c.expires) {
		a.mu.Unlock()
		return c.info, c.ok
	}
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	info, err := a.Provider.Lookup(ctx, network.Addr())
	c := cached{info: info, ok: err == nil, expires: now.Add(24 * time.Hour)}
	if err != nil {
		c.expires = now.Add(time.Hour)
	}
	a.mu.Lock()
	if a.cache == nil || len(a.cache) >= MaxCached {
		a.cache = map[netip.Prefix]cached{} // forget all rather than grow
	}
	a.cache[network] = c
	a.mu.Unlock()
	return c.info, c.ok
}
