// Package clientver reads the client's version from X-Raycontrol-Client and
// holds the node's minimum (spec/client-min-v1.md).
package clientver

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Header is the request header a client names itself in (client-min-v1 §1).
const Header = "X-Raycontrol-Client"

// MetadataKey is the same in the remote API's metadata.
const MetadataKey = "x-raycontrol-client"

// FeaturesHeader lists what a client does beyond what its version tells
// (spec/names-v1.md §4): words separated by commas; a node skips the ones
// it does not know.
const FeaturesHeader = "X-Raycontrol-Features"

// FeatureNames: the client resolves the node's names and falls back to its
// addresses (spec/names-v1.md §5).
const FeatureNames = "names"

// HasFeature reports whether a FeaturesHeader value lists f.
func HasFeature(h, f string) bool {
	if len(h) > 4*MaxLen {
		return false
	}
	for _, w := range strings.Split(h, ",") {
		if strings.TrimSpace(w) == f {
			return true
		}
	}
	return false
}

// MaxLen is the longest header taken, in bytes.
const MaxLen = 128

// Client is what the header says: the product and its version. The platform
// after them is neither kept nor read.
type Client struct {
	Product string
	Version Version
}

var productRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}$`)

// Parse reads `<product>/<version>[ (<platform>; <ABI>)]`. ok is false for
// a missing or unreadable header: the node treats both as no header.
func Parse(h string) (Client, bool) {
	if h == "" || len(h) > MaxLen {
		return Client{}, false
	}
	for i := 0; i < len(h); i++ {
		if h[i] < 0x20 || h[i] > 0x7e {
			return Client{}, false
		}
	}
	head := h
	if i := strings.IndexByte(h, ' '); i >= 0 {
		head = h[:i]
		rest := h[i+1:]
		if !strings.HasPrefix(rest, "(") || !strings.HasSuffix(rest, ")") {
			return Client{}, false
		}
	}
	product, version, found := strings.Cut(head, "/")
	if !found || !productRe.MatchString(product) {
		return Client{}, false
	}
	v, err := ParseVersion(version)
	if err != nil {
		return Client{}, false
	}
	return Client{Product: product, Version: v}, true
}

// Version is a semver 2.0 version without build metadata.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 []string // pre-release identifiers; none for a release
}

var numRe = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var preRe = regexp.MustCompile(`^[0-9A-Za-z-]+$`)

// ParseVersion reads `X.Y.Z[-pre]` (semver 2.0, no `+build`, no leading `v`).
func ParseVersion(s string) (Version, error) {
	var v Version
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("version %q: want X.Y.Z", s)
	}
	nums := []*uint64{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		if !numRe.MatchString(p) {
			return v, fmt.Errorf("version %q: %q is not a number", s, p)
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, fmt.Errorf("version %q: %w", s, err)
		}
		*nums[i] = n
	}
	if hasPre {
		for _, id := range strings.Split(pre, ".") {
			if !preRe.MatchString(id) {
				return v, fmt.Errorf("version %q: pre-release %q", s, pre)
			}
			if isNum(id) && !numRe.MatchString(id) {
				return v, fmt.Errorf("version %q: %q has a leading zero", s, id)
			}
			v.Pre = append(v.Pre, id)
		}
	}
	return v, nil
}

func isNum(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if len(v.Pre) > 0 {
		s += "-" + strings.Join(v.Pre, ".")
	}
	return s
}

// Compare is semver 2.0 precedence: -1, 0 or 1. A pre-release is below its
// release; numeric identifiers compare as numbers and below alphanumeric
// ones; a longer list of identifiers wins when the shorter is its prefix.
func Compare(a, b Version) int {
	for _, d := range [][2]uint64{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; i < len(a.Pre) && i < len(b.Pre); i++ {
		x, y := a.Pre[i], b.Pre[i]
		if x == y {
			continue
		}
		xn, yn := isNum(x), isNum(y)
		switch {
		case xn && yn:
			if len(x) != len(y) { // no leading zeros: the longer is larger
				if len(x) < len(y) {
					return -1
				}
				return 1
			}
			if x < y {
				return -1
			}
			return 1
		case xn:
			return -1
		case yn:
			return 1
		case x < y:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(a.Pre) < len(b.Pre):
		return -1
	case len(a.Pre) > len(b.Pre):
		return 1
	}
	return 0
}

// Policy is the node's minimum (client-min-v1 §2). The zero Policy has none.
type Policy struct {
	// Min is the lowest version taken, by product; empty: no policy.
	Min map[string]string `json:"min,omitempty"`
	// From is when it starts; zero: it holds already.
	From int64 `json:"from,omitempty"`
	// RefuseUnknown refuses a client without the header too.
	RefuseUnknown bool `json:"refuse_unknown,omitempty"`
}

// ErrInvalid is a policy that does not hold together.
var ErrInvalid = errors.New("invalid client policy")

// MaxProducts and MaxVersionLen bound a policy: every subscription carries
// it, and a version longer than this would not fit the header with its
// product anyway.
const (
	MaxProducts   = 8
	MaxVersionLen = 64
)

// ValidProduct reports whether s can name a product.
func ValidProduct(s string) bool { return productRe.MatchString(s) }

// Check returns the policy as kept, or why it cannot be. The error names
// nothing from the policy: it may hold anything a caller sent.
func (p Policy) Check() (Policy, error) {
	if len(p.Min) > MaxProducts {
		return Policy{}, fmt.Errorf("%w: %d products, at most %d", ErrInvalid, len(p.Min), MaxProducts)
	}
	for product, min := range p.Min {
		if !productRe.MatchString(product) {
			return Policy{}, fmt.Errorf("%w: a product is not [a-z][a-z0-9-]{0,15}", ErrInvalid)
		}
		if len(min) > MaxVersionLen {
			return Policy{}, fmt.Errorf("%w: a version longer than %d bytes", ErrInvalid, MaxVersionLen)
		}
		if _, err := ParseVersion(min); err != nil {
			return Policy{}, fmt.Errorf("%w: %s: not a semver version X.Y.Z[-pre]", ErrInvalid, product)
		}
	}
	if len(p.Min) == 0 {
		return Policy{}, nil
	}
	if p.From < 0 {
		return Policy{}, fmt.Errorf("%w: from %d", ErrInvalid, p.From)
	}
	return p, nil
}

// Marshal and Unmarshal are the policy as the node stores it.
func (p Policy) Marshal() ([]byte, error) { return json.Marshal(p) }

// Unmarshal reads a stored policy; nothing stored is no policy.
func Unmarshal(b []byte) (Policy, error) {
	var p Policy
	if len(b) == 0 {
		return p, nil
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	return p.Check()
}

// Active reports whether the policy holds at now.
func (p Policy) Active(now time.Time) bool {
	return len(p.Min) > 0 && (p.From == 0 || now.Unix() >= p.From)
}

// Refuses reports whether the policy refuses this client at now: a version
// below the minimum of its product, or no readable header when unknown
// clients are refused. A product the policy does not name is taken.
func (p Policy) Refuses(c Client, known bool, now time.Time) bool {
	if !p.Active(now) {
		return false
	}
	if !known {
		return p.RefuseUnknown
	}
	min, ok := p.Min[c.Product]
	if !ok {
		return false
	}
	mv, err := ParseVersion(min)
	if err != nil {
		return false // Check keeps such a policy out
	}
	return Compare(c.Version, mv) < 0
}

// Field is the subscription's client field (client-min-v1 §3).
type Field struct {
	V       int               `json:"v"`
	Min     map[string]string `json:"min"`
	From    int64             `json:"from,omitempty"`
	Refused bool              `json:"refused,omitempty"`
}

// Field returns the subscription's field for a device: none without a
// policy; from only while the policy is ahead.
func (p Policy) Field(refused bool, now time.Time) *Field {
	if len(p.Min) == 0 {
		return nil
	}
	f := &Field{V: 1, Min: p.Min, Refused: refused}
	if p.From != 0 && now.Unix() < p.From {
		f.From = p.From
	}
	return f
}
