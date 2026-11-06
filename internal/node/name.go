package node

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/arngory/raycontrol/internal/store"
)

const settingName = "node_name"

// MaxNameLen is the longest node name, in code points (subscription-v1 §3).
const MaxNameLen = 48

// CleanName checks a node name and returns it as kept: runs of spaces as one
// U+0020, none at the ends. Only letters, marks, numbers, punctuation,
// symbols and spaces pass: no control or format characters (bidi overrides,
// zero-width joiners), no private use, unassigned code points or line and
// paragraph separators. A client shows the name next to the node's address,
// so it must not reorder or hide what is around it. Empty means no name.
func CleanName(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%w: the node name is not UTF-8", store.ErrInvalid)
	}
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Zs, r):
			space = b.Len() > 0
			continue
		case !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S):
			return "", fmt.Errorf("%w: the node name has %U, which a client would not show as is (letters, marks, numbers, punctuation, symbols and spaces only)", store.ErrInvalid, r)
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	name := b.String()
	if n := utf8.RuneCountInString(name); n > MaxNameLen {
		return "", fmt.Errorf("%w: the node name has %d characters, at most %d", store.ErrInvalid, n, MaxNameLen)
	}
	return name, nil
}

// Name returns the node's name, "" if it has none.
func Name(ctx context.Context, st *store.Store) (string, error) {
	b, err := st.GetSetting(ctx, settingName)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return string(b), err
}

// SetName checks and stores the node's name; "" removes it. It returns the
// name as kept.
func SetName(ctx context.Context, st *store.Store, name string) (string, error) {
	name, err := CleanName(name)
	if err != nil {
		return "", err
	}
	return name, st.SetSetting(ctx, settingName, []byte(name))
}
