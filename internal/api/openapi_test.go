package api

import (
	"bufio"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestOpenAPIRoles: the OpenAPI documents of the integrations' roles
// (api/openapi, integrations-v1 §5.1) list the methods the gate lets the
// role call, no more and no fewer: both come from the same visibility
// rules, and a document made from an older proto would differ.
func TestOpenAPIRoles(t *testing.T) {
	for _, tc := range []struct {
		file   string
		labels []string
	}{
		{"billing.openapi.yaml", []string{labelBilling}},
		{"support.openapi.yaml", []string{labelSupport, labelNotes}},
	} {
		f, err := os.Open("../../api/openapi/" + tc.file)
		if err != nil {
			t.Fatal(err)
		}
		var doc []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// A path of the document: two spaces, the procedure, a colon.
			if line := sc.Text(); strings.HasPrefix(line, "  /raycontrol.") && strings.HasSuffix(line, ":") {
				doc = append(doc, strings.TrimSuffix(strings.TrimSpace(line), ":"))
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
		var gate []string
		for p, labels := range methodRoles {
			if slices.ContainsFunc(tc.labels, func(l string) bool { return slices.Contains(labels, l) }) {
				gate = append(gate, p)
			}
		}
		slices.Sort(doc)
		slices.Sort(gate)
		if !slices.Equal(doc, gate) {
			t.Errorf("%s: the document has %q,\nthe gate lets the role call %q (scripts/gen.sh)", tc.file, doc, gate)
		}
	}
}
