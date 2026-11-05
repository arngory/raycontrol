// Package cloudflare keeps the node's DNS records in a Cloudflare zone and
// answers ACME DNS-01 challenges there (docs/08-decisions.md, R4-10): the
// wildcard record every subdomain of the node resolves through, the NS
// delegation of DNS tunnel zones, and the TXT records of certificate
// orders. It changes only records it created, marked with Owner in their
// comment, and never proxies them: REALITY and DNS tunnels need the node's
// own address, not Cloudflare's edge.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// API is Cloudflare's API v4.
const API = "https://api.cloudflare.com/client/v4"

// Owner marks the records raycontrol manages (their comment).
const Owner = "raycontrol"

// Client talks to the API with a token that may edit the zone's DNS
// (Zone.DNS:Edit, Zone.Zone:Read): a user's token or an account's.
type Client struct {
	Token   string
	BaseURL string       // API when empty
	HTTP    *http.Client // a client with a timeout when nil
}

// Zone is a DNS zone on Cloudflare.
type Zone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	NameServers []string `json:"name_servers"`
}

// Record is a DNS record.
type Record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"` // 1 is automatic
	Proxied *bool  `json:"proxied,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// Ours reports whether raycontrol created the record.
func (r Record) Ours() bool { return r.Comment == Owner || strings.HasPrefix(r.Comment, Owner+" ") }

func (r Record) proxied() bool { return r.Proxied != nil && *r.Proxied }

// Error is an API failure.
type Error struct {
	Status   int
	Codes    []int
	Messages []string
}

// invalidToken: the API does not know the token (code 1000).
const invalidToken = 1000

func (e *Error) Error() string {
	return fmt.Sprintf("cloudflare: HTTP %d: %s", e.Status, strings.Join(e.Messages, "; "))
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, result any) error {
	base := c.BaseURL
	if base == "" {
		base = API
	}
	u := base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&env); err != nil {
		return fmt.Errorf("cloudflare: HTTP %d: %w", resp.StatusCode, err)
	}
	if !env.Success || resp.StatusCode >= 300 {
		e := &Error{Status: resp.StatusCode}
		for _, m := range env.Errors {
			e.Codes = append(e.Codes, m.Code)
			e.Messages = append(e.Messages, fmt.Sprintf("%d %s", m.Code, m.Message))
		}
		return e
	}
	if result != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, result)
	}
	return nil
}

// Verify checks that the token is valid and active. A token of an account
// (Manage Account, API Tokens) is unknown to /user/tokens/verify, which
// answers 1000 Invalid API Token: it is checked under the accounts of the
// zones it can read.
func (c *Client) Verify(ctx context.Context) error {
	err := c.verify(ctx, "/user/tokens/verify")
	var e *Error
	if err == nil || !errors.As(err, &e) || !slices.Contains(e.Codes, invalidToken) {
		return err
	}
	var zones []struct {
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	if c.do(ctx, http.MethodGet, "/zones", url.Values{"per_page": {"50"}}, nil, &zones) == nil {
		var seen []string
		for _, z := range zones {
			id := z.Account.ID
			if id == "" || slices.Contains(seen, id) {
				continue
			}
			seen = append(seen, id)
			aerr := c.verify(ctx, "/accounts/"+url.PathEscape(id)+"/tokens/verify")
			if aerr == nil {
				return nil
			}
			var ae *Error
			if !errors.As(aerr, &ae) || !slices.Contains(ae.Codes, invalidToken) {
				return aerr // the account knows the token: expired, disabled
			}
		}
	}
	return fmt.Errorf("%w (give the token's value, shown once when it is made, not its ID; "+
		"a user's token or an account's, with Zone.Zone:Read and Zone.DNS:Edit on the node's zone)", err)
}

func (c *Client) verify(ctx context.Context, path string) error {
	var r struct {
		Status string `json:"status"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &r); err != nil {
		return err
	}
	if r.Status != "active" {
		return fmt.Errorf("cloudflare: the token is %s", r.Status)
	}
	return nil
}

// ZoneFor finds the zone a domain belongs to: the domain itself or the
// nearest parent the token can see.
func (c *Client) ZoneFor(ctx context.Context, domain string) (Zone, error) {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(domain), "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		var zones []Zone
		if err := c.do(ctx, http.MethodGet, "/zones", url.Values{"name": {name}}, nil, &zones); err != nil {
			return Zone{}, err
		}
		if len(zones) > 0 {
			return zones[0], nil
		}
	}
	return Zone{}, fmt.Errorf("cloudflare: no zone for %s that this token can see (Zone.Zone:Read, Zone.DNS:Edit on it)", domain)
}

// Records lists records; empty filters match everything.
func (c *Client) Records(ctx context.Context, zone, name, typ, comment string) ([]Record, error) {
	var all []Record
	for page := 1; ; page++ {
		q := url.Values{"per_page": {"100"}, "page": {fmt.Sprint(page)}}
		if name != "" {
			q.Set("name", name)
		}
		if typ != "" {
			q.Set("type", typ)
		}
		if comment != "" {
			q.Set("comment.exact", comment)
		}
		var recs []Record
		if err := c.do(ctx, http.MethodGet, "/zones/"+zone+"/dns_records", q, nil, &recs); err != nil {
			return nil, err
		}
		all = append(all, recs...)
		if len(recs) < 100 {
			return all, nil
		}
	}
}

// Create adds a record.
func (c *Client) Create(ctx context.Context, zone string, r Record) (Record, error) {
	var out Record
	err := c.do(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", nil, r, &out)
	return out, err
}

// Update replaces a record.
func (c *Client) Update(ctx context.Context, zone string, r Record) (Record, error) {
	var out Record
	err := c.do(ctx, http.MethodPut, "/zones/"+zone+"/dns_records/"+r.ID, nil, r, &out)
	return out, err
}

// Delete removes a record.
func (c *Client) Delete(ctx context.Context, zone, id string) error {
	return c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+id, nil, nil, nil)
}

// Sync makes the zone hold the desired records (DNS only, marked as ours)
// and removes records of ours that are no longer desired. Records that are
// not ours stay as they are: one that already says the same and is not
// proxied serves; any other one under the same name is a conflict, and
// Sync leaves that name alone rather than mix its answers with ours.
func Sync(ctx context.Context, c *Client, zone string, desired []Record) (changes, conflicts []string, err error) {
	off := false
	want := map[string]bool{}
	for _, d := range desired {
		d.Comment, d.Proxied = Owner, &off
		if d.TTL == 0 {
			d.TTL = 300
		}
		want[recordKey(d)] = true
		existing, err := c.Records(ctx, zone, d.Name, "", "")
		if err != nil {
			return changes, conflicts, err
		}
		var ours *Record
		satisfied, conflict := false, ""
		for i, r := range existing {
			same := strings.EqualFold(r.Content, d.Content)
			switch {
			case r.Type != d.Type && r.Type != "CNAME":
				// Other types under the name (MX, TXT) do not interfere.
			case r.Ours() && r.Type == d.Type && (same || d.Type != "NS") && ours == nil:
				ours = &existing[i]
			case r.Ours():
			case r.Type == d.Type && same && !r.proxied():
				satisfied = true
			default:
				conflict = fmt.Sprintf("%s %s: a record not made by raycontrol says %s %s", d.Type, d.Name, r.Type, r.Content)
				if r.proxied() {
					conflict += " and is proxied by Cloudflare (REALITY and DNS tunnels need DNS only)"
				}
			}
		}
		switch {
		case conflict != "":
			conflicts = append(conflicts, conflict)
		case ours != nil:
			if strings.EqualFold(ours.Content, d.Content) && !ours.proxied() && ours.TTL == d.TTL {
				continue
			}
			d.ID = ours.ID
			if _, err := c.Update(ctx, zone, d); err != nil {
				return changes, conflicts, err
			}
			changes = append(changes, "updated "+d.Type+" "+d.Name)
		case !satisfied:
			if _, err := c.Create(ctx, zone, d); err != nil {
				return changes, conflicts, err
			}
			changes = append(changes, "created "+d.Type+" "+d.Name)
		}
	}
	mine, err := c.Records(ctx, zone, "", "", Owner)
	if err != nil {
		return changes, conflicts, err
	}
	for _, r := range mine {
		if want[recordKey(r)] {
			continue
		}
		if err := c.Delete(ctx, zone, r.ID); err != nil {
			return changes, conflicts, err
		}
		changes = append(changes, "removed "+r.Type+" "+r.Name)
	}
	return changes, conflicts, nil
}

func recordKey(r Record) string { return strings.ToLower(r.Type + " " + r.Name + " " + r.Content) }

// RemoveOwn deletes every record raycontrol created in the zone, ACME
// leftovers included.
func RemoveOwn(ctx context.Context, c *Client, zone string) ([]string, error) {
	var removed []string
	for _, comment := range []string{Owner, Owner + " acme"} {
		mine, err := c.Records(ctx, zone, "", "", comment)
		if err != nil {
			return removed, err
		}
		for _, r := range mine {
			if err := c.Delete(ctx, zone, r.ID); err != nil {
				return removed, err
			}
			removed = append(removed, r.Type+" "+r.Name)
		}
	}
	return removed, nil
}

// Solver answers ACME DNS-01 challenges with TXT records in the zone.
type Solver struct {
	Client *Client
	Zone   Zone
	// LookupTXT reads TXT records as the world will; nil asks the zone's
	// own name servers, so the CA finds what Present published.
	LookupTXT func(ctx context.Context, fqdn string) ([]string, error)
	// Poll is the interval of the visibility check (2 s when zero).
	Poll time.Duration

	mu  sync.Mutex
	ids map[string]string // fqdn + value -> record ID
}

// Present publishes the TXT record and returns once it is visible.
func (s *Solver) Present(ctx context.Context, fqdn, value string) error {
	r, err := s.Client.Create(ctx, s.Zone.ID, Record{Type: "TXT", Name: fqdn, Content: value, TTL: 60, Comment: Owner + " acme"})
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.ids == nil {
		s.ids = map[string]string{}
	}
	s.ids[fqdn+" "+value] = r.ID
	s.mu.Unlock()

	lookup := s.LookupTXT
	if lookup == nil {
		lookup = s.authoritative
	}
	poll := s.Poll
	if poll == 0 {
		poll = 2 * time.Second
	}
	for {
		if vals, err := lookup(ctx, fqdn); err == nil && slices.Contains(vals, value) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("TXT %s not visible: %w", fqdn, ctx.Err())
		case <-time.After(poll):
		}
	}
}

// CleanUp removes the TXT record Present published.
func (s *Solver) CleanUp(ctx context.Context, fqdn, value string) error {
	s.mu.Lock()
	id := s.ids[fqdn+" "+value]
	delete(s.ids, fqdn+" "+value)
	s.mu.Unlock()
	if id == "" {
		return nil
	}
	return s.Client.Delete(ctx, s.Zone.ID, id)
}

// authoritative asks the zone's name servers, one after another.
func (s *Solver) authoritative(ctx context.Context, fqdn string) ([]string, error) {
	if len(s.Zone.NameServers) == 0 {
		return net.DefaultResolver.LookupTXT(ctx, fqdn)
	}
	var errs []error
	for _, ns := range s.Zone.NameServers {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(ns, "53"))
		}}
		vals, err := r.LookupTXT(ctx, fqdn)
		if err == nil {
			return vals, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}
