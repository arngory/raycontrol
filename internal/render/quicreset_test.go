package render_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// A naive service has a key of QUIC stateless resets: made with the
// service, given at the next collect to one made before there was such a
// key, the same from then on (a new one at a restart would be no key at
// all), and rendered into one file, for the service's group and no one
// else.
func TestNaiveQUICResetKey(t *testing.T) {
	ctx := context.Background()
	st := node(t)
	for _, s := range []store.Service{{Kind: "reality", Name: "r"}, {Kind: "naive", Name: "nv"}} {
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
	nv, err := st.ServiceByName(ctx, "nv")
	if err != nil {
		t.Fatal(err)
	}
	key := func() []byte {
		t.Helper()
		secrets, err := st.ServiceSecrets(ctx, nv.ID)
		if err != nil {
			t.Fatal(err)
		}
		return secrets[provision.SecretQUICReset]
	}
	made := key()
	if len(made) != 32 {
		t.Fatalf("a new naive service's key: %d bytes", len(made))
	}
	rendered := func() render.File {
		t.Helper()
		m, err := render.CollectForRender(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		files, _, err := render.Render(m, render.DefaultPaths)
		if err != nil {
			t.Fatal(err)
		}
		k := []byte(hex.EncodeToString(key()))
		var file render.File
		for _, f := range files {
			switch {
			case f.Path == render.DefaultPaths.Rendered+"/nv/"+render.NaiveQUICReset:
				file = f
			case bytes.Contains(f.Content, k) || bytes.Contains(f.Content, key()):
				t.Fatalf("the key is in %s", f.Path)
			}
		}
		// Read at the start only, and no unit waits for it: its coming
		// restarts nothing (live.Applier).
		if !bytes.Equal(file.Content, append(k, '\n')) || file.Mode != 0o640 || file.Group != "niko-nv" || file.Service != "nv" ||
			!file.AtStart || file.Reload || file.Needed {
			t.Fatalf("the key's file: %d bytes, mode %o, group %q, service %q, %+v", len(file.Content), file.Mode, file.Group, file.Service, file)
		}
		return file
	}
	if got := rendered(); !bytes.Equal(key(), made) || !bytes.Contains(got.Content, []byte(hex.EncodeToString(made))) {
		t.Fatal("the key changed at a collect")
	}
	// A service from before the key: the next collect makes one, once.
	if err := st.UpdateService(ctx, nv.ID, store.ServiceUpdate{Delete: []string{provision.SecretQUICReset}}); err != nil {
		t.Fatal(err)
	}
	rendered()
	given := key()
	if len(given) != 32 || bytes.Equal(given, made) {
		t.Fatalf("an old service's key: %d bytes", len(given))
	}
	rendered()
	if !bytes.Equal(key(), given) {
		t.Fatal("the key changed at the next collect")
	}
	// Only naive has one.
	for _, name := range []string{"r", "site"} {
		s, _ := st.ServiceByName(ctx, name)
		if secrets, _ := st.ServiceSecrets(ctx, s.ID); secrets[provision.SecretQUICReset] != nil {
			t.Fatalf("%s has a QUIC reset key", name)
		}
	}
}
