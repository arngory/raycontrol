// Package cftest is a fake of the part of Cloudflare's API raycontrol uses,
// for tests.
package cftest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/arngory/raycontrol/internal/cloudflare"
)

// API is the part of Cloudflare's API raycontrol uses: one zone, example.com,
// and the token "good". Record filters: name, type, comment.exact.
type API struct {
	mu      sync.Mutex
	token   string
	Zones   []cloudflare.Zone
	Records map[string]cloudflare.Record // by ID
	next    int
	calls   []string
}

func New(t testing.TB) (*API, *cloudflare.Client) {
	f := &API{token: "good", Zones: []cloudflare.Zone{{ID: "z1", Name: "example.com", NameServers: []string{"ns1.example.net"}}}, Records: map[string]cloudflare.Record{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &cloudflare.Client{Token: "good", BaseURL: srv.URL}
}

func (f *API) Add(r cloudflare.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	r.ID = fmt.Sprint("r", f.next)
	f.Records[r.ID] = r
}

func (f *API) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req.Method+" "+req.URL.Path)
	reply := func(code int, result any, errs ...string) {
		env := map[string]any{"success": code < 300, "result": result, "errors": []any{}}
		var e []map[string]any
		for _, m := range errs {
			e = append(e, map[string]any{"code": 1000, "message": m})
		}
		if e != nil {
			env["errors"] = e
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(env)
	}
	if req.Header.Get("Authorization") != "Bearer "+f.token {
		reply(403, nil, "Invalid API Token")
		return
	}
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	q := req.URL.Query()
	switch {
	case req.URL.Path == "/user/tokens/verify":
		reply(200, map[string]string{"status": "active"})
	case req.URL.Path == "/zones":
		var out []cloudflare.Zone
		for _, z := range f.Zones {
			if z.Name == q.Get("name") {
				out = append(out, z)
			}
		}
		reply(200, out)
	case len(parts) >= 3 && parts[0] == "zones" && parts[2] == "dns_records":
		switch {
		case req.Method == http.MethodGet:
			out := []cloudflare.Record{}
			for _, r := range f.Records {
				if (q.Get("name") == "" || r.Name == q.Get("name")) && (q.Get("type") == "" || r.Type == q.Get("type")) &&
					(q.Get("comment.exact") == "" || r.Comment == q.Get("comment.exact")) {
					out = append(out, r)
				}
			}
			slices.SortFunc(out, func(a, b cloudflare.Record) int { return strings.Compare(a.ID, b.ID) })
			reply(200, out)
		case req.Method == http.MethodPost:
			var r cloudflare.Record
			_ = json.NewDecoder(req.Body).Decode(&r)
			f.next++
			r.ID = fmt.Sprint("r", f.next)
			f.Records[r.ID] = r
			reply(200, r)
		case req.Method == http.MethodPut && len(parts) == 4:
			var r cloudflare.Record
			_ = json.NewDecoder(req.Body).Decode(&r)
			r.ID = parts[3]
			f.Records[r.ID] = r
			reply(200, r)
		case req.Method == http.MethodDelete && len(parts) == 4:
			delete(f.Records, parts[3])
			reply(200, map[string]string{"id": parts[3]})
		}
	default:
		reply(404, nil, "no route")
	}
}

func (f *API) List() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.Records {
		out = append(out, fmt.Sprintf("%s %s %s proxied=%v ours=%v", r.Type, r.Name, r.Content, r.Proxied != nil && *r.Proxied, r.Ours()))
	}
	slices.Sort(out)
	return out
}

// Snapshot returns a copy of the records.
func (f *API) Snapshot() []cloudflare.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []cloudflare.Record
	for _, r := range f.Records {
		out = append(out, r)
	}
	return out
}
