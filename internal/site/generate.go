// Package site makes and serves the node's decoy site: the target of
// REALITY in self-steal mode, which anyone who is not a client sees
// (docs/08-decisions.md, E-4, R2-12). Every install gets its own site from
// its own seed: a small studio site with a journal, plausible and dull.
package site

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"html/template"
	"math/rand/v2"
	"strings"
	"time"
)

var (
	adjectives = []string{"Northfield", "Quiet", "Linden", "Harbor", "Saltmarsh", "Birchwood", "Low Tide", "Ashgrove",
		"Fernhill", "Greywater", "Old Mill", "Kestrel", "Slate", "Juniper", "Meridian", "Copperleaf", "Hollow Oak", "Stillwater"}
	nouns  = []string{"Studio", "Workshop", "Atelier", "Works", "Collective", "Press", "House", "Bureau", "Lab", "Practice"}
	crafts = []struct{ field, thing, verb string }{
		{"ceramics", "pots", "throw"}, {"furniture", "chairs", "build"}, {"bookbinding", "books", "bind"},
		{"letterpress printing", "prints", "set"}, {"landscape design", "gardens", "plan"}, {"photography", "photographs", "take"},
		{"textile weaving", "blankets", "weave"}, {"woodturning", "bowls", "turn"}, {"typeface design", "typefaces", "draw"},
		{"stained glass", "panels", "cut"}, {"leatherwork", "bags", "stitch"}, {"architectural models", "models", "make"},
	}
	cities = []string{"Tallinn", "Porto", "Ljubljana", "Ghent", "Utrecht", "Bergen", "Tartu", "Aarhus", "Graz", "Malmö",
		"Cork", "Leiden", "Trondheim", "Lyon", "Bologna", "Kraków", "Brno", "Turku"}
	firsts = []string{"Anna", "Marta", "Jonas", "Elias", "Lena", "Tomas", "Ida", "Mikkel", "Clara", "Oskar", "Nora", "Pieter"}
	lasts  = []string{"Varga", "Lind", "Novak", "Berg", "Kask", "Moreau", "Holm", "Visser", "Kowal", "Sandoval", "Reid", "Okafor"}
	topics = []string{"Notes from the winter fair", "A slower glaze", "Why we keep the old tools", "On ordering wood a year ahead",
		"Studio hours for spring", "A visit to the paper mill", "Repairing instead of replacing", "What the first batch taught us",
		"Three things we stopped doing", "Small runs, long waits", "The light in the back room", "Packing for the autumn market"}
	lines = []string{
		"Most of the work happens slowly, and most of it is waiting.",
		"We keep a short list of commissions and close it when it fills.",
		"Everything here is made in small runs, so no two pieces are quite the same.",
		"The workshop is open to visitors on the first Saturday of the month.",
		"We source materials locally where we can and write down where they came from.",
		"Repairs are welcome, including pieces we did not make.",
		"Lead times are long; we would rather say so up front.",
		"Some of the tools we use are older than the building.",
		"We teach an occasional evening class when there is room in the schedule.",
		"Orders ship once a week, wrapped in paper from the print room.",
		"Most of what we know we learned from people who did this before us.",
		"The studio is small, and we like it that way.",
	}
	accents = []string{"#7a4e2d", "#2f5d50", "#3d4f7a", "#7a2f3b", "#5a6b2f", "#4a4a4a", "#8a5a12", "#2d5f7a"}
	fonts   = []string{`Georgia, "Times New Roman", serif`, `"Iowan Old Style", Palatino, serif`,
		`"Helvetica Neue", Arial, sans-serif`, `system-ui, -apple-system, "Segoe UI", sans-serif`}
)

type post struct {
	Slug, Title, Date string
	Body              []string
}

type model struct {
	Name, Field, FieldTitle, Thing, Verb, City, Owner, Email, Domain, Accent, Font string
	Founded, Year                                                                  int
	Intro                                                                          []string
	Posts                                                                          []post
}

func pick[T any](r *rand.Rand, list []T) T { return list[r.IntN(len(list))] }

// paragraphs of three sentences each, no sentence twice.
func paragraphs(r *rand.Rand, n int) []string {
	idx := r.Perm(len(lines))
	out := make([]string, n)
	for i := range out {
		j := 3 * i % (len(lines) - 2)
		out[i] = lines[idx[j]] + " " + lines[idx[j+1]] + " " + lines[idx[j+2]]
	}
	return out
}

func slug(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case c == ' ' || c == '-':
			b.WriteByte('-')
		}
	}
	return b.String()
}

// Generate returns the site's files (path relative to the root -> content)
// for a seed and the site's name. The same seed and name give the same
// files, so re-rendering changes nothing.
func Generate(seed []byte, domain string, now time.Time) (map[string][]byte, error) {
	sum := sha256.Sum256(append([]byte("raycontrol-site "), seed...))
	r := rand.New(rand.NewChaCha8(sum)) //nolint:gosec // G404: deterministic content from a secret seed, not key material
	craft := pick(r, crafts)
	first, last := pick(r, firsts), pick(r, lasts)
	m := model{
		Name: pick(r, adjectives) + " " + pick(r, nouns), Field: craft.field, Thing: craft.thing, Verb: craft.verb,
		FieldTitle: strings.ToUpper(craft.field[:1]) + craft.field[1:],
		City:       pick(r, cities), Owner: first + " " + last, Domain: domain,
		Email:  "studio@" + domain,
		Accent: pick(r, accents), Font: pick(r, fonts),
		Year: now.Year(), Founded: now.Year() - 3 - r.IntN(12),
		Intro: paragraphs(r, 2),
	}
	// Posts dated back from the start of the month: recent, and the files
	// change once a month at most.
	day := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -r.IntN(10))
	for _, i := range r.Perm(len(topics))[:4+r.IntN(3)] {
		day = day.AddDate(0, 0, -(6 + r.IntN(30)))
		m.Posts = append(m.Posts, post{Slug: slug(topics[i]), Title: topics[i], Date: day.Format("2 January 2006"), Body: paragraphs(r, 2+r.IntN(3))})
	}

	files := map[string][]byte{}
	render := func(name, text string, data any) error {
		t, err := template.New(name).Parse(layout + text)
		if err != nil {
			return err
		}
		var b bytes.Buffer
		if err := t.Execute(&b, data); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		files[name] = b.Bytes()
		return nil
	}
	pages := []struct{ path, text string }{
		{"index.html", indexPage}, {"about.html", aboutPage}, {"journal/index.html", journalPage}, {"404.html", notFoundPage},
	}
	for _, p := range pages {
		if err := render(p.path, p.text, m); err != nil {
			return nil, err
		}
	}
	for _, p := range m.Posts {
		if err := render("journal/"+p.Slug+".html", postPage, struct {
			model
			Post post
		}{m, p}); err != nil {
			return nil, err
		}
	}
	files["style.css"] = []byte(fmt.Sprintf(style, m.Font, m.Accent))
	files["robots.txt"] = []byte("User-agent: *\nDisallow:\n")
	return files, nil
}

const layout = `{{define "head"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{template "title" .}}</title>
<meta name="description" content="{{.Name}}: {{.Field}} in {{.City}}.">
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header><a class="brand" href="/">{{.Name}}</a>
<nav><a href="/journal/">Journal</a> <a href="/about.html">About</a></nav></header>
<main>{{end}}
{{define "foot"}}</main>
<footer>&copy; {{.Founded}}&ndash;{{.Year}} {{.Name}}, {{.City}} &middot; <a href="mailto:{{.Email}}">{{.Email}}</a></footer>
</body>
</html>
{{end}}`

const indexPage = `{{define "title"}}{{.Name}}{{end}}{{template "head" .}}
<h1>{{.FieldTitle}} from {{.City}}</h1>
{{range .Intro}}<p>{{.}}</p>
{{end}}<h2>Recent notes</h2>
<ul class="posts">{{range .Posts}}<li><a href="/journal/{{.Slug}}.html">{{.Title}}</a> <time>{{.Date}}</time></li>
{{end}}</ul>
{{template "foot" .}}`

const aboutPage = `{{define "title"}}About &middot; {{.Name}}{{end}}{{template "head" .}}
<h1>About</h1>
<p>{{.Name}} is a small {{.Field}} workshop in {{.City}}, run by {{.Owner}} since {{.Founded}}.
We {{.Verb}} {{.Thing}} to order and in small batches.</p>
<p>For commissions and visits, write to <a href="mailto:{{.Email}}">{{.Email}}</a>.</p>
{{template "foot" .}}`

const journalPage = `{{define "title"}}Journal &middot; {{.Name}}{{end}}{{template "head" .}}
<h1>Journal</h1>
<ul class="posts">{{range .Posts}}<li><a href="/journal/{{.Slug}}.html">{{.Title}}</a> <time>{{.Date}}</time></li>
{{end}}</ul>
{{template "foot" .}}`

const postPage = `{{define "title"}}{{.Post.Title}} &middot; {{.Name}}{{end}}{{template "head" .}}
<article><h1>{{.Post.Title}}</h1><time>{{.Post.Date}}</time>
{{range .Post.Body}}<p>{{.}}</p>
{{end}}</article>
{{template "foot" .}}`

const notFoundPage = `{{define "title"}}Not found &middot; {{.Name}}{{end}}{{template "head" .}}
<h1>Not found</h1>
<p>That page is not here. Try the <a href="/journal/">journal</a>.</p>
{{template "foot" .}}`

const style = `body{margin:0 auto;max-width:42rem;padding:2rem 1.25rem;font:17px/1.6 %s;color:#222;background:#fbfaf7}
header{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:2.5rem}
a{color:%s}
.brand{font-weight:bold;text-decoration:none;color:#222}
nav a{margin-left:1rem}
h1{font-size:1.8rem;line-height:1.25}
.posts{list-style:none;padding:0}
.posts li{margin:.4rem 0}
time{color:#777;font-size:.9rem;margin-left:.5rem}
footer{margin-top:3rem;font-size:.85rem;color:#777}
`
