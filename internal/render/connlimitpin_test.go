package render

import (
	"bufio"
	"encoding/json"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/store"
)

// The niko-server render writes for is the one deploy/versions.env pins:
// the embedded copy reads the same tag as the file CI reads.
func TestNikoServerTagIsThePin(t *testing.T) {
	f, err := os.Open("../../deploy/versions.env")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tag := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "NIKO_SERVER_TAG="); ok {
			tag = strings.Trim(v, `"`)
		}
	}
	if tag == "" || nikoServerTag != tag {
		t.Fatalf("render writes for niko-server %q, versions.env pins %q", nikoServerTag, tag)
	}
}

func TestNikoServerAtLeast(t *testing.T) {
	was := nikoServerTag
	t.Cleanup(func() { nikoServerTag = was })
	for tag, want := range map[string]bool{"v0.17.0": true, "v0.17.1": true, "v0.18.0": true, "v1.0.0": true,
		"v0.17.0-rc1": true, "v0.16.1": false, "v0.9.9": false, "0.17.0": false, "v0.17": false, "vx.y.z": false, "": false} {
		nikoServerTag = tag
		if got := NikoServerAtLeast(NikoConnLimitFrom); got != want {
			t.Errorf("%q at least v0.17.0: %v", tag, got)
		}
	}
}

// The Hysteria2 backends get the switch of the connection limits
// (spec/conn-limit-v1.md §3.2, §8) only from niko-server v0.17.0: an older
// one refuses options.conn_limit_file, and with it the backend. The switch
// is a file of the rendered directory, read again without a restart.
func TestHysteriaConnLimitPin(t *testing.T) {
	was := nikoServerTag
	t.Cleanup(func() { nikoServerTag = was })
	p := DefaultPaths
	for _, kind := range []string{"hy2-masq", "hy2-obfs"} {
		s := Service{Service: store.Service{ID: 3, Kind: kind, Name: "h", Enabled: true, Settings: `{}`}}
		for _, tag := range []string{"v0.16.1", "v0.17.0"} {
			for off, content := range map[bool]string{false: "on\n", true: "off\n"} {
				nikoServerTag = tag
				files, err := hysteriaFiles(s, Model{ConnLimitOff: off}, p)
				if err != nil {
					t.Fatal(err)
				}
				var cfg struct {
					Options map[string]any `json:"options"`
				}
				var limit *File
				for i, f := range files {
					switch path.Base(f.Path) {
					case "backend.json":
						if err := json.Unmarshal(f.Content, &cfg); err != nil {
							t.Fatal(err)
						}
					case HysteriaConnLimit:
						limit = &files[i]
					}
				}
				want := "/var/lib/raycontrol/rendered/h/conn-limit"
				got, has := cfg.Options["conn_limit_file"]
				if _, ok := cfg.Options["conn_limit"]; ok {
					t.Errorf("%s %s: conn_limit written (a change of it restarts the backend)", kind, tag)
				}
				if tag == "v0.16.1" {
					if has || limit != nil {
						t.Errorf("%s %s: conn_limit_file %v, file %v", kind, tag, got, limit)
					}
					continue
				}
				if got != want || limit == nil || limit.Path != want || string(limit.Content) != content || !limit.Reload ||
					limit.Mode != 0o640 || limit.Group != "niko-h" || limit.Service != "h" {
					t.Errorf("%s %s off %v: conn_limit_file %v, file %+v", kind, tag, off, got, limit)
				}
			}
		}
	}
}
