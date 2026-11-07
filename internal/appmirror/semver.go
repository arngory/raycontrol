package appmirror

import (
	"regexp"
	"strconv"
	"strings"
)

// The client's tags: vMAJOR.MINOR.PATCH, a pre-release after "-" (v1.39.0-rc1),
// build metadata after "+" (ignored in order), as semver 2.0.0 has them.
var semverRe = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})` +
	`(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func semverValid(tag string) bool { return semverRe.MatchString(tag) }

// semverCompare orders two valid tags by semver precedence: -1, 0 or 1.
func semverCompare(a, b string) int {
	ma, mb := semverRe.FindStringSubmatch(a), semverRe.FindStringSubmatch(b)
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if c := cmpInt(x, y); c != 0 {
			return c
		}
	}
	pa, pb := ma[4], mb[4]
	switch {
	case pa == pb:
		return 0
	case pa == "": // a release is newer than its pre-releases
		return 1
	case pb == "":
		return -1
	}
	xa, xb := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := 0; i < len(xa) && i < len(xb); i++ {
		na, ea := number(xa[i])
		nb, eb := number(xb[i])
		switch {
		case ea == nil && eb == nil:
			if c := cmpInt(na, nb); c != 0 {
				return c
			}
		case ea == nil: // numbers before words
			return -1
		case eb == nil:
			return 1
		default:
			if c := strings.Compare(xa[i], xb[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(xa), len(xb))
}

// number reads a numeric identifier: digits only ("-1" is a word).
func number(s string) (int, error) {
	if strings.Trim(s, "0123456789") != "" {
		return 0, strconv.ErrSyntax
	}
	return strconv.Atoi(s)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
