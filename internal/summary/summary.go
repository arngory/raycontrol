// Package summary is the node's side of the client summaries
// (docs/08-decisions.md, R4-21; docs/spec/probe-v1.md §6): with the user's
// consent a client tells the node, once a day per network, how its profiles
// fared there, in coarse buckets. The node keeps counters by day, AS and
// service for 30 days, and gives clients in a network with enough reports
// a hint at the order of their profiles. It is an optional metric: off
// until the administrator turns it on.
package summary

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/arngory/raycontrol/internal/asn"
	"github.com/arngory/raycontrol/internal/store"
)

// Limits and thresholds (R4-21).
const (
	K        = 10      // reports from a network before it gets a hint
	Keep     = 30      // days the counters are kept
	Window   = 7       // days a hint is counted over
	Majority = 0.6     // the share that makes avoid, udp_blocked, tcp_stall_kib
	MaxObs   = 16      // observations in a report
	MaxBody  = 4 << 10 // bytes of a report
	day      = 24 * time.Hour
	dayS     = int64(day / time.Second)
)

// Buckets a report may use.
var (
	Nets    = []string{"cellular", "wifi", "ethernet", "other"}
	Results = []string{"works", "degraded", "fails"}
	UDP     = []string{"0-1", "1-5", "5-20", "20-50", "50-100", "none"}
	Mbps    = []string{"<1", "1-5", "5-20", "20-100", "100+"}
	Stalls  = []int{8, 16, 32, 64, 128}
)

// Report is what a client sends (probe-v1 §6).
type Report struct {
	V   int    `json:"v"`
	Net string `json:"net"`
	Obs []Obs  `json:"obs"`
}

// Obs is one profile's outcome in the network.
type Obs struct {
	Svc         int64  `json:"svc"`
	Result      string `json:"result"`
	TCPStallKiB int    `json:"tcp_stall_kib,omitempty"`
	UDP         string `json:"udp,omitempty"`
	Mbps        string `json:"mbps,omitempty"`
}

// Errors of Report, for the endpoint's status codes.
var (
	ErrDisabled = errors.New("the node takes no reports")
	ErrRepeated = errors.New("this network was reported today")
	ErrInvalid  = errors.New("bad report")
)

// Settings keys.
const (
	settingEnabled = "summary_enabled"
	settingAPI     = "summary_api"
	settingToken   = "summary_api_token"
)

// Collector takes reports and gives hints.
type Collector struct {
	Store *store.Store
	ASN   asn.Source
	now   func() time.Time

	mu   sync.Mutex
	day  int64
	salt [32]byte
	seen map[[32]byte]bool
}

func (c *Collector) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Enabled reports whether the administrator turned the reports on.
func Enabled(ctx context.Context, st *store.Store) bool {
	v, err := st.GetSetting(ctx, settingEnabled)
	return err == nil && string(v) == "1"
}

// SetEnabled turns the reports on or off.
func SetEnabled(ctx context.Context, st *store.Store, on bool) error {
	if !on {
		return st.DeleteSetting(ctx, settingEnabled)
	}
	return st.SetSetting(ctx, settingEnabled, []byte("1"))
}

// API returns the lookup service the administrator turned on, if any.
func API(ctx context.Context, st *store.Store) (provider, token string) {
	p, err := st.GetSetting(ctx, settingAPI)
	if err != nil {
		return "", ""
	}
	t, _ := st.GetSetting(ctx, settingToken)
	return string(p), string(t)
}

// SetAPI turns an online lookup on (asn.Providers names it) or off ("").
// The token is checked by one lookup of a well-known network.
func SetAPI(ctx context.Context, st *store.Store, provider, token string) error {
	if provider == "" || provider == "none" {
		if err := st.DeleteSetting(ctx, settingAPI); err != nil {
			return err
		}
		return st.DeleteSetting(ctx, settingToken)
	}
	mk, ok := asn.Providers[provider]
	if !ok {
		return fmt.Errorf("%w: lookup API %q (known: ipinfo)", store.ErrInvalid, provider)
	}
	if token == "" {
		return fmt.Errorf("%w: %s needs a token", store.ErrInvalid, provider)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := mk(token, nil).Lookup(ctx, netip.MustParseAddr("1.1.1.0")); err != nil {
		return fmt.Errorf("%w: %s does not answer with this token: %w", store.ErrInvalid, provider, err)
	}
	if err := st.SetSetting(ctx, settingToken, []byte(token)); err != nil {
		return err
	}
	return st.SetSetting(ctx, settingAPI, []byte(provider))
}

// Parse reads and checks a report: known fields only, buckets only, one
// observation per service, at most MaxObs.
func Parse(body io.Reader) (Report, error) {
	b, err := io.ReadAll(io.LimitReader(body, MaxBody+1))
	if err != nil {
		return Report{}, err
	}
	if len(b) > MaxBody {
		return Report{}, fmt.Errorf("%w: over %d bytes", ErrInvalid, MaxBody)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Report
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if r.V != 1 {
		return r, fmt.Errorf("%w: version %d", ErrInvalid, r.V)
	}
	if !slices.Contains(Nets, r.Net) {
		return r, fmt.Errorf("%w: net %q", ErrInvalid, r.Net)
	}
	if len(r.Obs) == 0 || len(r.Obs) > MaxObs {
		return r, fmt.Errorf("%w: 1 to %d observations", ErrInvalid, MaxObs)
	}
	seen := map[int64]bool{}
	for _, o := range r.Obs {
		switch {
		case o.Svc < 1 || o.Svc > 65535 || seen[o.Svc]:
			return r, fmt.Errorf("%w: svc %d", ErrInvalid, o.Svc)
		case !slices.Contains(Results, o.Result):
			return r, fmt.Errorf("%w: result %q", ErrInvalid, o.Result)
		case o.TCPStallKiB != 0 && !slices.Contains(Stalls, o.TCPStallKiB):
			return r, fmt.Errorf("%w: tcp_stall_kib %d", ErrInvalid, o.TCPStallKiB)
		case o.UDP != "" && !slices.Contains(UDP, o.UDP):
			return r, fmt.Errorf("%w: udp %q", ErrInvalid, o.UDP)
		case o.Mbps != "" && !slices.Contains(Mbps, o.Mbps):
			return r, fmt.Errorf("%w: mbps %q", ErrInvalid, o.Mbps)
		}
		seen[o.Svc] = true
	}
	return r, nil
}

// once reports whether the device has not reported from this AS today. It
// keeps keyed hashes in memory under a key of the day, and forgets both
// when the day ends: nothing ties a device to a network on disk.
func (c *Collector) once(device string, as uint32, today int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil || c.day != today {
		c.day, c.seen = today, map[[32]byte]bool{}
		_, _ = rand.Read(c.salt[:])
	}
	m := hmac.New(sha256.New, c.salt[:])
	m.Write([]byte(device))
	m.Write([]byte{0})
	m.Write([]byte(strconv.FormatUint(uint64(as), 10)))
	var k [32]byte
	copy(k[:], m.Sum(nil))
	if c.seen[k] {
		return false
	}
	c.seen[k] = true
	return true
}

// Take records a report from a device at addr. The AS comes from the
// address; the address itself is not kept. Observations of services the
// device's user has no access to are refused.
func (c *Collector) Take(ctx context.Context, device string, addr netip.Addr, body io.Reader) error {
	if !Enabled(ctx, c.Store) {
		return ErrDisabled
	}
	r, err := Parse(body)
	if err != nil {
		return err
	}
	d, _, err := c.Store.ActiveDevice(ctx, device)
	if err != nil {
		return err
	}
	u, err := c.Store.UserByName(ctx, d.UserName)
	if err != nil {
		return err
	}
	for _, o := range r.Obs {
		if !slices.Contains(u.Services, o.Svc) {
			return fmt.Errorf("%w: svc %d is not the user's", ErrInvalid, o.Svc)
		}
	}
	// The databases answer for any address they hold (a test database may
	// map a test network); an online lookup only for public ones.
	var info asn.Info
	if c.ASN != nil {
		info, _ = c.ASN.Lookup(ctx, addr)
	}
	today := c.clock().Unix() / dayS
	if !c.once(device, info.ASN, today) {
		return ErrRepeated
	}
	row := func(svc int64, field, bucket string) store.SummaryCount {
		return store.SummaryCount{Day: today, ASN: info.ASN, Svc: svc, Field: field, Bucket: bucket, N: 1}
	}
	counts := []store.SummaryCount{row(0, "reports", ""), row(0, "net", r.Net)}
	for _, o := range r.Obs {
		counts = append(counts, row(o.Svc, "result", o.Result))
		if o.TCPStallKiB != 0 {
			counts = append(counts, row(o.Svc, "stall", strconv.Itoa(o.TCPStallKiB)))
		}
		if o.UDP != "" {
			counts = append(counts, row(o.Svc, "udp", o.UDP))
		}
		if o.Mbps != "" {
			counts = append(counts, row(o.Svc, "mbps", o.Mbps))
		}
	}
	return c.Store.AddSummary(ctx, counts, info.Name, info.Country)
}

// Prune drops the counters older than Keep days.
func (c *Collector) Prune(ctx context.Context) (int64, error) {
	return c.Store.PruneSummary(ctx, c.clock().Unix()/dayS-Keep+1)
}
