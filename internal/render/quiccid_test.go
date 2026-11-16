package render_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/quiccid"
	"github.com/arngory/raycontrol/internal/quiccid/cidkey"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// Routable connection IDs (spec/quic-cid-route-v1.md): one secret for the
// node, made once; each QUIC service's label is its ID, and each label has
// its own key. rayd's naive-quic gets its label and its key in a file of
// its own whatever the front; the front (udp.cid_keys_file, the keys of its
// backends' labels; backends.*.cid_label) and the Hysteria2 backends
// (options.cid_key_file, their label's key; options.cid_label) only from
// niko-server v0.18.0, which reads them. A label's key is in its service's
// file and the front's, and nowhere else; the secret is in none. None of
// them is read at the start only: a new secret restarts every process of
// them.
func TestQUICCIDRender(t *testing.T) {
	ctx := context.Background()
	st := node(t)
	for _, s := range []store.Service{{Kind: "reality", Name: "r"}, {Kind: "naive", Name: "nv"}, {Kind: "doh", Name: "dh"},
		{Kind: "hy2-masq", Name: "hm"}, {Kind: "hy2-obfs", Name: "ho"}} {
		s.Enabled = true
		if _, err := provision.CreateService(ctx, st, s); err != nil {
			t.Fatal(err)
		}
	}
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{provision.SecretTLSChain: []byte("chain"), provision.SecretTLSKey: []byte("key")}})
	secret, err := st.QUICCIDKey(ctx)
	if err != nil || len(secret) != cidkey.SecretLen {
		t.Fatalf("the secret: %d bytes, %v", len(secret), err)
	}
	if again, _ := st.QUICCIDKey(ctx); !bytes.Equal(again, secret) {
		t.Fatal("a second secret")
	}
	ids := map[string]int{}
	for _, name := range []string{"nv", "dh", "hm", "ho"} {
		s, _ := st.ServiceByName(ctx, name)
		ids[name] = int(s.ID)
	}
	p := render.DefaultPaths
	h := hex.EncodeToString(secret)
	labelKey := func(name string) string {
		k, err := cidkey.LabelKey(secret, ids[name])
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(k)
	}
	// The front's file: the keys of its backends' labels, by label.
	frontKeys := path.Join(p.Rendered, "front", render.FrontQUICCIDKeys)
	byLabel := []string{"nv", "dh", "hm", "ho"}
	slices.SortFunc(byLabel, func(a, b string) int { return ids[a] - ids[b] })
	var lines strings.Builder
	for _, name := range byLabel {
		fmt.Fprintf(&lines, "%d %s\n", ids[name], labelKey(name))
	}
	hmFile, hoFile := path.Join(p.Rendered, "hm", render.QUICCIDKey), path.Join(p.Rendered, "ho", render.QUICCIDKey)
	keyFiles := map[string]string{ // path: content
		frontKeys: lines.String(),
		hmFile:    labelKey("hm") + "\n",
		hoFile:    labelKey("ho") + "\n",
	}
	naiveFile := path.Join(p.Rendered, "nv", render.NaiveQUICCID)
	// The files each label's key may be in; DoH3's rayd derives itself.
	homes := map[string][]string{labelKey("nv"): {naiveFile, frontKeys}, labelKey("hm"): {hmFile, frontKeys},
		labelKey("ho"): {hoFile, frontKeys}, labelKey("dh"): {frontKeys}}
	groups := map[string]string{"front": "niko-front", "hm": "niko-hm", "ho": "niko-ho", "nv": "niko-nv"}

	for _, tag := range []string{"v0.17.1", "v0.18.0"} {
		restore := render.UseNikoServer(tag)
		m, err := render.CollectForRender(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		files, _, err := render.Render(m, p)
		restore()
		if err != nil {
			t.Fatal(err)
		}
		on := tag == "v0.18.0"
		byPath := map[string]render.File{}
		for _, f := range files {
			byPath[f.Path] = f
			for k, allowed := range homes {
				if !slices.Contains(allowed, f.Path) && bytes.Contains(f.Content, []byte(k)) {
					t.Fatalf("%s: a key of %s is in %s", tag, allowed[0], f.Path)
				}
			}
			// The secret stays in the store and rayd: no process of the
			// data plane has it, the front's included.
			if bytes.Contains(f.Content, []byte(h)) || bytes.Contains(f.Content, secret) {
				t.Fatalf("%s: the secret is in %s", tag, f.Path)
			}
		}
		// naive-quic's: always, its label and its key; a change restarts it.
		nf := byPath[naiveFile]
		if string(nf.Content) != strconv.Itoa(ids["nv"])+" "+labelKey("nv")+"\n" || nf.Mode != 0o640 || nf.Group != "niko-nv" ||
			nf.Service != "nv" || nf.AtStart || nf.Reload || nf.Needed {
			t.Fatalf("%s: naive's file %+v", tag, nf)
		}
		if label, got, err := quiccid.ParseLabelled(nf.Content); err != nil || label != ids["nv"] || hex.EncodeToString(got) != labelKey("nv") {
			t.Fatalf("%s: naive's file does not read: %v", tag, err)
		}
		for file, content := range keyFiles {
			f, ok := byPath[file]
			if ok != on {
				t.Fatalf("%s: %s rendered %v", tag, file, ok)
			}
			if svc := path.Base(path.Dir(file)); ok && (string(f.Content) != content || f.Mode != 0o640 || f.Group != groups[svc] ||
				f.Service != svc || f.AtStart || f.Reload || f.Needed) {
				t.Fatalf("%s: %s: %+v", tag, file, f)
			}
		}
		var front struct {
			UDP struct {
				CIDKeysFile string `json:"cid_keys_file"`
			} `json:"udp"`
			Backends map[string]struct {
				CIDLabel int `json:"cid_label"`
			} `json:"backends"`
		}
		if err := json.Unmarshal(byPath[p.FrontConfig()].Content, &front); err != nil {
			t.Fatal(err)
		}
		want := map[string]int{"nv/quic": ids["nv"], "dh/quic": ids["dh"], "hm": ids["hm"], "ho": ids["ho"]}
		if !on {
			want = map[string]int{}
		}
		for name, b := range front.Backends {
			if b.CIDLabel != want[name] {
				t.Errorf("%s: backend %s label %d, want %d", tag, name, b.CIDLabel, want[name])
			}
		}
		if wantKey := map[bool]string{true: frontKeys}[on]; front.UDP.CIDKeysFile != wantKey {
			t.Errorf("%s: udp.cid_keys_file %q", tag, front.UDP.CIDKeysFile)
		}
		for _, hy := range []string{"hm", "ho"} {
			var backend struct {
				Options struct {
					CIDKeyFile string `json:"cid_key_file"`
					CIDLabel   int    `json:"cid_label"`
				} `json:"options"`
			}
			if err := json.Unmarshal(byPath[path.Join(p.Rendered, hy, "backend.json")].Content, &backend); err != nil {
				t.Fatal(err)
			}
			wantKey, wantLabel := "", 0
			if on {
				wantKey, wantLabel = path.Join(p.Rendered, hy, render.QUICCIDKey), ids[hy]
			}
			if backend.Options.CIDKeyFile != wantKey || backend.Options.CIDLabel != wantLabel {
				t.Errorf("%s: %s options %+v", tag, hy, backend.Options)
			}
		}
	}
}

// A label is a service's ID while it fits 16 bits.
func TestCIDLabel(t *testing.T) {
	for id, want := range map[int64]int{1: 1, 300: 300, quiccid.MaxLabel: quiccid.MaxLabel, quiccid.MaxLabel + 1: 0, 0: 0, -3: 0} {
		if got := render.CIDLabel(id); got != want {
			t.Errorf("service %d: label %d, want %d", id, got, want)
		}
	}
}
