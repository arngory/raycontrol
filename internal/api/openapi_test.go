package api

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// openAPIDoc is what TestOpenAPIRoles reads of a generated document: its
// paths, and the proto names (each property's title) of the properties of
// each schema. The generator writes YAML of a fixed shape: two spaces a
// level, a path or a schema a key of its own line.
type openAPIDoc struct {
	paths  []string
	fields map[string][]string // message full name → its fields' proto names
}

func readOpenAPI(t *testing.T, file string) openAPIDoc {
	t.Helper()
	b, err := os.ReadFile("../../api/openapi/" + file)
	if err != nil {
		t.Fatal(err)
	}
	doc := openAPIDoc{fields: map[string][]string{}}
	// key is a line's key at indent spaces: "" when the line is not one.
	key := func(line string, indent int) string {
		if len(line) <= indent || strings.TrimLeft(line[:indent], " ") != "" || line[indent] == ' ' || !strings.HasSuffix(line, ":") {
			return ""
		}
		return strings.Trim(strings.TrimSuffix(line[indent:], ":"), `"'`)
	}
	var section, schema, property string
	var inProperties bool
	// untitled: a property of ours with no title before the next one or
	// the schema's end (Connect's own schemas have none).
	untitled := func() {
		if property != "" && strings.HasPrefix(schema, "raycontrol.") {
			t.Errorf("%s: %s.%s has no title", file, schema, property)
		}
		property = ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k := key(line, 0); k != "" || (line != "" && line[0] != ' ') {
			untitled()
			section, schema = k, ""
			continue
		}
		switch section {
		case "paths":
			if k := key(line, 2); k != "" {
				doc.paths = append(doc.paths, k)
			}
		case "components":
			if k := key(line, 2); k != "" || (len(line) > 2 && line[2] != ' ') {
				section, schema = "components", ""
				if k == "schemas" {
					section = "schemas"
				}
			}
		case "schemas":
			switch {
			case key(line, 2) != "" || (len(line) > 2 && line[2] != ' '):
				untitled()
				section, schema = "components", ""
			case key(line, 4) != "":
				untitled()
				schema, inProperties = key(line, 4), false
				doc.fields[schema] = []string{}
			case len(line) > 6 && line[6] != ' ':
				untitled()
				inProperties = line == "      properties:"
			case inProperties && key(line, 8) != "":
				untitled()
				property = key(line, 8)
			case inProperties && property != "" && strings.HasPrefix(line, "          title: "):
				doc.fields[schema] = append(doc.fields[schema], strings.TrimPrefix(line, "          title: "))
				property = ""
			}
		}
	}
	if len(doc.paths) == 0 || len(doc.fields) == 0 {
		t.Fatalf("%s: no paths or no schemas read", file)
	}
	return doc
}

// TestOpenAPIRoles: the OpenAPI documents of the integrations' roles
// in api/openapi (integrations-v1 §5.1) list the methods the gate lets the
// role call, no more and no fewer, and each message of their answers has
// the fields the role sees (testdata/integration-fields.txt), no more and
// no fewer: both come from the same visibility rules, and a document made
// from an older proto would differ.
func TestOpenAPIRoles(t *testing.T) {
	golden, err := os.ReadFile("testdata/integration-fields.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		file, role string
		labels     []string
	}{
		{"billing.openapi.yaml", labelBilling, []string{labelBilling}},
		{"support.openapi.yaml", labelSupport, []string{labelSupport, labelNotes}},
	} {
		doc := readOpenAPI(t, tc.file)
		var gate []string
		for p, labels := range methodRoles {
			if slices.ContainsFunc(tc.labels, func(l string) bool { return slices.Contains(labels, l) }) {
				gate = append(gate, p)
			}
		}
		slices.Sort(doc.paths)
		slices.Sort(gate)
		if !slices.Equal(doc.paths, gate) {
			t.Errorf("%s: the document has %q,\nthe gate lets the role call %q (scripts/gen.sh)", tc.file, doc.paths, gate)
		}

		// What the role sees of each message of its answers: support's notes
		// too, the document being of all support may be let see.
		sees := map[string][]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(golden)), "\n") {
			role, field, _ := strings.Cut(strings.TrimSuffix(line, " (if the administrator allows)"), " ")
			if role != tc.role {
				continue
			}
			i := strings.LastIndex(field, ".")
			sees[field[:i]] = append(sees[field[:i]], field[i+1:])
		}
		for msg, want := range sees {
			got, ok := doc.fields[msg]
			if !ok {
				t.Errorf("%s: no schema of %s", tc.file, msg)
				continue
			}
			got, want = slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))
			if !slices.Equal(got, want) {
				t.Errorf("%s: %s has %q, the role sees %q", tc.file, msg, got, want)
			}
		}
	}
}
