package render_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"path"
	"strconv"
	"testing"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/quiccid"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// Routable connection IDs (spec/quic-cid-route-v1.md): one secret for the
// node, made once; each QUIC service's label is its ID. rayd's naive-quic
// gets its label and the secret in a file of its own whatever the front;
// the front (udp.cid_key_file, backends.*.cid_label) and the Hysteria2
// backends (options.cid_key_file, options.cid_label) only from
// niko-server v0.18.0, which reads them. The secret is in those files and
// nowhere else.
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
	if err != nil || len(secret) != quiccid.SecretLen {
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
	keyFiles := map[string]string{ // path: content
		path.Join(p.Rendered, "front", render.QUICCIDKey): h + "\n",
		path.Join(p.Rendered, "hm", render.QUICCIDKey):    h + "\n",
		path.Join(p.Rendered, "ho", render.QUICCIDKey):    h + "\n",
	}
	naiveFile := path.Join(p.Rendered, "nv", render.NaiveQUICCID)
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
			_, isKey := keyFiles[f.Path]
			if f.Path != naiveFile && !isKey && (bytes.Contains(f.Content, []byte(h)) || bytes.Contains(f.Content, secret)) {
				t.Fatalf("%s: the secret is in %s", tag, f.Path)
			}
		}
		// naive-quic's: always, its label and the secret, read at its start.
		nf := byPath[naiveFile]
		if string(nf.Content) != strconv.Itoa(ids["nv"])+" "+h+"\n" || nf.Mode != 0o640 || nf.Group != "niko-nv" || nf.Service != "nv" ||
			!nf.AtStart || nf.Reload || nf.Needed {
			t.Fatalf("%s: naive's file %+v", tag, nf)
		}
		if label, got, err := quiccid.ParseLabelled(nf.Content); err != nil || label != ids["nv"] || !bytes.Equal(got, secret) {
			t.Fatalf("%s: naive's file does not read: %v", tag, err)
		}
		for file, content := range keyFiles {
			f, ok := byPath[file]
			if ok != on {
				t.Fatalf("%s: %s rendered %v", tag, file, ok)
			}
			if svc := path.Base(path.Dir(file)); ok && (string(f.Content) != content || f.Mode != 0o640 || f.Group != groups[svc] ||
				f.Service != svc || !f.AtStart || f.Reload || f.Needed) {
				t.Fatalf("%s: %s: %+v", tag, file, f)
			}
		}
		var front struct {
			UDP struct {
				CIDKeyFile string `json:"cid_key_file"`
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
		if wantKey := map[bool]string{true: path.Join(p.Rendered, "front", render.QUICCIDKey)}[on]; front.UDP.CIDKeyFile != wantKey {
			t.Errorf("%s: udp.cid_key_file %q", tag, front.UDP.CIDKeyFile)
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

// A label is a service's ID while it fits 16 bits; render's bounds are
// quiccid's, which it does not import.
func TestCIDLabel(t *testing.T) {
	for id, want := range map[int64]int{1: 1, 300: 300, quiccid.MaxLabel: quiccid.MaxLabel, quiccid.MaxLabel + 1: 0, 0: 0, -3: 0} {
		if got := render.CIDLabel(id); got != want {
			t.Errorf("service %d: label %d, want %d", id, got, want)
		}
	}
	if render.CIDSecretLen != quiccid.SecretLen {
		t.Fatal("the secret's length")
	}
}
