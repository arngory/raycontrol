package clientver

import (
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		h       string
		product string
		version string
		ok      bool
	}{
		{"niko/1.59.0 (android; arm64-v8a)", "niko", "1.59.0", true},
		{"niko/2.0.0 (windows; amd64)", "niko", "2.0.0", true},
		{"niko/1.59.0-pre.20261120.1 (linux; amd64)", "niko", "1.59.0-pre.20261120.1", true},
		{"niko/1.59.0", "niko", "1.59.0", true},
		{"", "", "", false},
		{"niko", "", "", false},
		{"niko/v1.59.0", "", "", false},
		{"niko/1.59", "", "", false},
		{"niko/1.59.0+build.1", "", "", false},
		{"niko/01.59.0", "", "", false},
		{"niko/1.59.0-pre.01", "", "", false},
		{"Niko/1.59.0", "", "", false},
		{"niko/1.59.0 android", "", "", false},
		{"niko/1.59.0 (android)\x00", "", "", false},
		{"niko/1.59.0 (" + strings.Repeat("a", 120) + ")", "", "", false},
	} {
		c, ok := Parse(tc.h)
		if ok != tc.ok || (ok && (c.Product != tc.product || c.Version.String() != tc.version)) {
			t.Errorf("Parse(%q) = %+v %v, want %s %s %v", tc.h, c, ok, tc.product, tc.version, tc.ok)
		}
	}
}

// The order semver 2.0 §11 gives as its example, and the client's preview
// builds below their release (client-min-v1 §9.2).
func TestCompare(t *testing.T) {
	order := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.58.0", "1.59.0-pre.20261120.1", "1.59.0-pre.20261120.2",
		"1.59.0-pre.20261121.1", "1.59.0", "1.59.1", "1.60.0", "2.0.0"}
	vs := make([]Version, len(order))
	for i, s := range order {
		v, err := ParseVersion(s)
		if err != nil {
			t.Fatal(err)
		}
		vs[i] = v
	}
	for i := range vs {
		for j := range vs {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := Compare(vs[i], vs[j]); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
}

func TestPolicy(t *testing.T) {
	now := time.Unix(1768435200, 0)
	niko := func(v string) Client {
		c, ok := Parse("niko/" + v + " (android; arm64-v8a)")
		if !ok {
			t.Fatal(v)
		}
		return c
	}
	var none Policy
	if none.Refuses(Client{}, false, now) || none.Field(false, now) != nil {
		t.Fatal("no policy refuses or says something")
	}
	p := Policy{Min: map[string]string{"niko": "1.59.0"}}
	for v, refused := range map[string]bool{"1.58.0": true, "1.59.0-pre.20261120.1": true, "1.59.0": false, "2.0.0": false} {
		if got := p.Refuses(niko(v), true, now); got != refused {
			t.Errorf("min 1.59.0, %s: refused %v", v, got)
		}
	}
	if p.Refuses(Client{}, false, now) {
		t.Error("no header refused while unknown clients are allowed")
	}
	other, _ := Parse("other/0.1.0")
	if p.Refuses(other, true, now) {
		t.Error("a product the policy does not name is refused")
	}
	p.RefuseUnknown = true
	if !p.Refuses(Client{}, false, now) {
		t.Error("no header taken while unknown clients are refused")
	}
	// Ahead: nobody refused, the field says when.
	ahead := Policy{Min: p.Min, From: now.Unix() + 86400, RefuseUnknown: true}
	if ahead.Refuses(niko("1.0.0"), true, now) || ahead.Refuses(Client{}, false, now) {
		t.Error("refused before from")
	}
	if f := ahead.Field(false, now); f == nil || f.From != ahead.From || f.Refused {
		t.Errorf("field ahead: %+v", f)
	}
	if f := ahead.Field(false, time.Unix(ahead.From, 0)); f == nil || f.From != 0 {
		t.Errorf("field once from has come: %+v", f)
	}
	if !ahead.Refuses(niko("1.0.0"), true, time.Unix(ahead.From, 0)) {
		t.Error("not refused at from")
	}
}

func TestPolicyStored(t *testing.T) {
	p := Policy{Min: map[string]string{"niko": "2.0.0"}, From: 1768435200, RefuseUnknown: true}
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Unmarshal(b)
	if err != nil || q.Min["niko"] != "2.0.0" || q.From != p.From || !q.RefuseUnknown {
		t.Fatalf("round trip: %+v %v", q, err)
	}
	if q, err := Unmarshal(nil); err != nil || len(q.Min) != 0 {
		t.Fatalf("nothing stored: %+v %v", q, err)
	}
	for _, bad := range []Policy{{Min: map[string]string{"niko": "v2"}}, {Min: map[string]string{"Niko": "2.0.0"}}, {Min: map[string]string{"niko": "2.0.0"}, From: -1}} {
		if _, err := bad.Check(); err == nil {
			t.Errorf("%+v passes", bad)
		}
	}
	// A policy without a minimum keeps nothing else.
	if q, err := (Policy{From: 5, RefuseUnknown: true}).Check(); err != nil || q.From != 0 || q.RefuseUnknown {
		t.Errorf("empty policy kept %+v %v", q, err)
	}
}
