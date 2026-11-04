package provision

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/testca"
)

func TestSetCertificate(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	good, err := testca.New([]string{"*.example.test"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := testca.New([]string{"*.example.org"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	expired, _ := testca.New([]string{"*.example.test"}, now.Add(-48*time.Hour), now.Add(-time.Hour))

	for _, c := range []struct {
		name, svc  string
		chain, key []byte
		want       string
	}{
		{"not a site", "reality", good.ChainPEM, good.KeyPEM, "belong to a site"},
		{"another key", "site", good.ChainPEM, other.KeyPEM, "private key does not match"},
		{"short chain", "site", good.ChainPEM[:strings.Index(string(good.ChainPEM), "-----END")+25], good.KeyPEM, "REALITY needs"},
		{"other names", "site", other.ChainPEM, other.KeyPEM, "does not cover"},
		{"expired", "site", expired.ChainPEM, expired.KeyPEM, "not now"},
	} {
		if _, err := SetCertificate(ctx, st, c.svc, c.chain, c.key, now); !errors.Is(err, store.ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	got, err := SetCertificate(ctx, st, "site", good.ChainPEM, good.KeyPEM, now)
	if err != nil {
		t.Fatal(err)
	}
	site, _ := st.ServiceByName(ctx, "site")
	if len(got.Names) == 0 || got.Names[0] != SiteName(site) || got.NotAfter.Before(now) {
		t.Fatalf("stored %+v", got)
	}
	secrets, _ := st.ServiceSecrets(ctx, site.ID)
	if string(secrets[SecretTLSChain]) != string(good.ChainPEM) || len(secrets[SecretTLSKey]) == 0 {
		t.Fatal("certificate not stored")
	}
}
