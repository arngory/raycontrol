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

// maxMarks is the most marks one character of a name bears (Vietnamese and
// Devanagari take two or three).
const maxMarks = 4

// CleanName checks a node name and returns it as kept: runs of spaces as one
// U+0020, none at the ends. Only letters, marks, numbers, punctuation,
// symbols and spaces pass: no control or format characters (bidi overrides,
// zero-width joiners), no private use, unassigned code points or line and
// paragraph separators. A client shows the name next to the node's address,
// so it must not reorder or hide what is around it. Empty means no name.
func CleanName(s string) (string, error) { return cleanText(s, "node name", MaxNameLen, false) }

// MaxNoteLen is the longest node note, in code points (subscription-v1 §3).
const MaxNoteLen = 200

// CleanNote checks a node note as CleanName does a name, at most MaxNoteLen
// code points on one line, and lets through what emoji and some scripts
// need: U+200C and U+200D between two characters (👨‍👩‍👧, Persian), and
// tag sequences after U+1F3F4 closed by U+E007F (🏴 of England). An emoji
// sequence counts as all its code points.
func CleanNote(s string) (string, error) { return cleanText(s, "node note", MaxNoteLen, true) }

// cleanText is CleanName and CleanNote: what is a label, at most limit code
// points, with joiners and emoji tags when joiners.
func cleanText(s, what string, limit int, joiners bool) (string, error) {
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%w: the %s is not UTF-8", store.ErrInvalid, what)
	}
	var b strings.Builder
	space := false
	marks := -1     // marks in a row on the last base; -1: none to bear one
	joined := false // the last character is a joiner: a character must follow
	tags := -1      // tags in the open tag sequence; -1: none open
	var last rune
	for _, r := range s {
		isTag := r >= 0xE0020 && r <= 0xE007F
		switch {
		case tags >= 0 && !isTag:
			return "", fmt.Errorf("%w: the %s has a tag sequence not closed by U+E007F", store.ErrInvalid, what)
		case joiners && isTag:
			// Tags spell a subdivision after U+1F3F4 (🏴 of England,
			// Scotland, Wales) and nowhere else.
			if r == 0xE007F {
				if tags < 1 {
					return "", fmt.Errorf("%w: the %s has U+E007F with no tag before it", store.ErrInvalid, what)
				}
				tags = -1
			} else if tags < 0 && last != 0x1F3F4 || tags >= 8 {
				return "", fmt.Errorf("%w: the %s has the tag %U out of a flag", store.ErrInvalid, what, r)
			} else {
				tags = max(tags, 0) + 1
			}
			b.WriteRune(r)
			last = r
			continue
		case joiners && (r == 0x200C || r == 0x200D):
			// Between two characters only: at an end or by a space it
			// joins the note to what the client shows around it.
			if marks < 0 || space || joined {
				return "", fmt.Errorf("%w: the %s has %U with no character before it", store.ErrInvalid, what, r)
			}
			joined = true
			b.WriteRune(r)
			last = r
			continue
		case unicode.Is(unicode.Zs, r):
			if joined {
				return "", fmt.Errorf("%w: the %s has a joiner with no character after it", store.ErrInvalid, what)
			}
			space = b.Len() > 0
			marks = -1
			continue
		case !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S):
			return "", fmt.Errorf("%w: the %s has %U, which a client would not show as is (letters, marks, numbers, punctuation, symbols and spaces only)", store.ErrInvalid, what, r)
		case unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
			// Shown as nothing (Hangul fillers, U+034F): a blank text.
			return "", fmt.Errorf("%w: the %s has %U, which shows as nothing", store.ErrInvalid, what, r)
		case unicode.Is(unicode.Variation_Selector, r) && (r < 0xFE0E || r > 0xFE0F || marks < 0):
			return "", fmt.Errorf("%w: the %s has the variation selector %U (only U+FE0E and U+FE0F, after a character)", store.ErrInvalid, what, r)
		case unicode.Is(unicode.M, r):
			// A mark goes on the character before it: at the start it
			// would go on what the client shows before the text, and
			// stacked ones run over the line (review).
			if marks < 0 || space || joined {
				return "", fmt.Errorf("%w: the %s has the mark %U with no character before it", store.ErrInvalid, what, r)
			}
			if marks++; marks > maxMarks {
				return "", fmt.Errorf("%w: the %s stacks more than %d marks on one character", store.ErrInvalid, what, maxMarks)
			}
		default:
			marks = 0
		}
		joined = false
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
		last = r
	}
	if joined {
		return "", fmt.Errorf("%w: the %s ends with a joiner", store.ErrInvalid, what)
	}
	if tags >= 0 {
		return "", fmt.Errorf("%w: the %s has a tag sequence not closed by U+E007F", store.ErrInvalid, what)
	}
	text := b.String()
	if n := utf8.RuneCountInString(text); n > limit {
		return "", fmt.Errorf("%w: the %s has %d characters, at most %d", store.ErrInvalid, what, n, limit)
	}
	return text, nil
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

const settingNote = "node_note"

// Note returns the node's note for clients, "" if it has none.
func Note(ctx context.Context, st *store.Store) (string, error) {
	b, err := st.GetSetting(ctx, settingNote)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return string(b), err
}

// SetNote checks and stores the node's note; "" removes it. It returns the
// note as kept.
func SetNote(ctx context.Context, st *store.Store, note string) (string, error) {
	note, err := CleanNote(note)
	if err != nil {
		return "", err
	}
	return note, st.SetSetting(ctx, settingNote, []byte(note))
}
