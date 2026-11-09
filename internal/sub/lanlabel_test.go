package sub_test

import (
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// DNS labels (lan-v1 §1.3), against an independent reading of the rules.
func TestLANLabel(t *testing.T) {
	for _, c := range []struct{ name, want string }{
		{"work.laptop", "work-laptop"},
		{"phone", "phone"},
		{"ноутбук", "noutbuk"},
		{"Ноутбук Маші", "noutbuk-mashi"},
		// The whole table, small and capital letters (ь is nothing).
		{"абвгґдеєёжзиіїйклмнопрстуўфхцчшщъыьэюя", "abvggdeieezhziiiiklmnoprstuufkhtschshshchieyeiuia"},
		{"АБВГҐДЕЄЁЖЗИІЇЙКЛМНОПРСТУЎФХЦЧШЩЪЫЬЭЮЯ", "abvggdeieezhziiiiklmnoprstuufkhtschshshchieyeiuia"},
		// Ukrainian і ї є ґ, Belarusian ў.
		{"Київ", "kiiv"},
		{"Ґанок", "ganok"},
		{"Євгенія", "ievgeniia"},
		{"Їжак", "izhak"},
		{"Дім 🏠 №2", "dim-2"},
		{"Праўда", "prauda"},
		{"Ўсход", "uskhod"},
		{"Беларусь", "belarus"},
		// Russian ъ and ь, ё, й.
		{"объект", "obieekt"},
		{"Ольга", "olga"},
		{"Ъ", "ie"},
		{"ЖЁЛТЫЙ", "zheltyi"},
		{"ьa", "a"},
		{"aьb", "ab"},
		{"a-ь-b", "a-b"},
		// A letter typed as a base and a mark is the letter (NFC).
		{"Мои\u0306", "moi"},
		{"е\u0308лка", "elka"},
		{"Ї", "i"},
		{"i\u0308", ""}, // Latin i and a diaeresis: ï, not a-z
		// Mixed scripts, other scripts, other Cyrillic, Latin with marks.
		{"Мой iPhone 15 Pro", "moi-iphone-15-pro"},
		{"Laptop Ноутбук", "laptop-noutbuk"},
		{"Санкт-Петербург", "sankt-peterburg"},
		{"Мамин телефон", "mamin-telefon"},
		{"Амстердам", "amsterdam"},
		{"电话", ""},
		{"Ελένη", ""},
		{"Đorđe", "or-e"},
		{"ђак", "ak"},
		{"Café", "caf"},
		// Emoji: dashes, then none at the ends.
		{"📱 Phone", "phone"},
		{"📱", ""},
		{"a👍b", "a-b"},
		{"👨\u200d👩\u200d👧 home", "home"},
		// Dashes: collapsed and trimmed; never two in a row, so no xn--.
		{"--a--b--", "a-b"},
		{"a_b c.d", "a-b-c-d"},
		{"xn--abc", "xn-abc"},
		{"", ""},
		{"   ", ""},
		{"___", ""},
		{"123", "123"},
		// Long: 58 at most, and no dash at the cut.
		{strings.Repeat("a", 70), strings.Repeat("a", 58)},
		{strings.Repeat("a", 57) + " b", strings.Repeat("a", 57)},
		{strings.Repeat("щ", 20), strings.Repeat("shch", 14) + "sh"},
		{strings.Repeat("я", 40), strings.Repeat("ia", 29)},
	} {
		got := sub.LANLabel(c.name)
		if got != c.want {
			t.Errorf("LANLabel(%q) = %q, want %q", c.name, got, c.want)
		}
		if len(got) > 58 || strings.Contains(got, "--") || strings.HasPrefix(got, "-") || strings.HasSuffix(got, "-") ||
			strings.Trim(got, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			t.Errorf("LANLabel(%q) = %q: not a label", c.name, got)
		}
	}
}

func TestNodeLabel(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	for name, want := range map[string]string{
		"":           "n-01234567",
		"Амстердам":  "amsterdam",
		"🇳🇱":         "n-01234567",
		"NL-1 (ams)": "nl-1-ams",
	} {
		if got := sub.NodeLabel(name, id); got != want {
			t.Errorf("NodeLabel(%q) = %q, want %q", name, got, want)
		}
	}
}

// A label taken by a device added earlier: -<id[:4]>, then d-<id>; nothing
// left of the name: d-<id[:8]>. The order of adding decides, not the IDs.
func TestLANLabels(t *testing.T) {
	long := strings.Repeat("x", 70)
	devices := []store.LANDevice{ // in the order they were added
		{ID: "ffff000000000001", Name: "phone"},
		{ID: "aaaa000000000002", Name: "phone"},
		{ID: "aaaa000000000003", Name: "phone"},      // phone-aaaa is taken too
		{ID: "bbbb000000000004", Name: "phone-aaaa"}, // its own name is taken
		{ID: "cccc000000000005", Name: "📱"},
		{ID: "cccc000000000006", Name: "電話"},      // d-cccc0000 is taken
		{ID: "dddd000000000007", Name: "Ноутбук"}, // noutbuk
		{ID: "eeee000000000008", Name: "noutbuk"}, // the same label
		{ID: "1111000000000009", Name: long},
		{ID: "2222000000000010", Name: long + "y"},
	}
	want := map[string]string{
		"ffff000000000001": "phone",
		"aaaa000000000002": "phone-aaaa",
		"aaaa000000000003": "d-aaaa000000000003",
		"bbbb000000000004": "phone-aaaa-bbbb",
		"cccc000000000005": "d-cccc0000",
		"cccc000000000006": "d-cccc0000-cccc",
		"dddd000000000007": "noutbuk",
		"eeee000000000008": "noutbuk-eeee",
		"1111000000000009": strings.Repeat("x", 58),
		"2222000000000010": strings.Repeat("x", 58) + "-2222",
	}
	got := sub.LANLabels(devices)
	seen := map[string]bool{}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: %q, want %q", id, got[id], w)
		}
		if seen[got[id]] || len(got[id]) > 63 {
			t.Errorf("%s: %q twice or too long", id, got[id])
		}
		seen[got[id]] = true
	}
	if len(got) != len(want) {
		t.Errorf("%d labels, want %d", len(got), len(want))
	}
	// The other order: the first of two takes the name.
	got = sub.LANLabels([]store.LANDevice{devices[1], devices[0]})
	if got["aaaa000000000002"] != "phone" || got["ffff000000000001"] != "phone-ffff" {
		t.Errorf("%v", got)
	}
}

// The multicast password (lan-v1 §3), against vectors made apart from this
// code: base64url without padding of HMAC-SHA256(key, label ‖ UUID).
func TestLANPassword(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	for uuid, want := range map[string]string{
		"0b9f6c1e-3d2a-4c5b-8e7f-1a2b3c4d5e6f": "31IKHjGEEdP4eVHUGbPv-McBPzDR7I0aJdu9YpDFkV8",
		"5d41402a-bc4b-4a76-b971-9d911017c592": "CQ8BwX9P8ZF66znD4FgxzDkeQHjo_XXPUewj4qhJOTw",
	} {
		got := sub.LANPasswordFor(key, uuid)
		if got != want || len(got) != 43 {
			t.Errorf("%s: %s, want %s", uuid, got, want)
		}
	}
	other := append([]byte{}, key...)
	other[0] ^= 1
	if sub.LANPasswordFor(other, "0b9f6c1e-3d2a-4c5b-8e7f-1a2b3c4d5e6f") == "31IKHjGEEdP4eVHUGbPv-McBPzDR7I0aJdu9YpDFkV8" {
		t.Error("another key, the same password")
	}
}
