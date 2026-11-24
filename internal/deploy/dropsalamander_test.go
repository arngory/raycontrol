package deploy

import (
	"os"
	"path/filepath"
	"testing"
)

// The hy2-obfs password files of before leave the disk once no unit of
// the plan copies them in; one a unit still copies in stays, and so does
// everything else in the rendered directory.
func TestDropUncopiedSalamander(t *testing.T) {
	root := t.TempDir()
	h := &Host{Root: root}
	rendered := "/var/lib/raycontrol/rendered"
	write := func(p string) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"ho/salamander", "front/ho.salamander", "kept/salamander", "front/ho.salamander.keys", "ho/key.pem"} {
		write(rendered + "/" + p)
	}
	plan := Plan{Files: []File{
		{Path: "/etc/systemd/system/niko-kept.service", Content: []byte("[Service]\nExecStartPre=+/usr/local/bin/rayd credential /var/lib raycontrol/rendered/kept/salamander rayd niko-kept /run/niko/kept/salamander\n")},
		{Path: "/etc/systemd/system/niko-front.service", Content: []byte("[Service]\n")},
	}}
	if err := h.DropUncopiedSalamander(plan, rendered); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{"ho/salamander": false, "front/ho.salamander": false, "kept/salamander": true, "front/ho.salamander.keys": true, "ho/key.pem": true} {
		_, err := os.Stat(filepath.Join(root, rendered, p))
		if got := err == nil; got != want {
			t.Errorf("%s: there %v, want %v", p, got, want)
		}
	}
}
