package store

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

// A service's settings and secrets, changed together by UpdateService,
// are read together by ServicesWithSecrets: a reader never sees the
// settings of one change with the secrets of another. ListServices and
// ServiceSecrets one after the other do: a subscription built across the
// import of the operator's certificate paired the settings of before (not
// marked imported) with the chain of after and published pins for it
// (spec/cert-pin-v1.md §7). The loop below is that interleaving, forced a
// few thousand times.
func TestServicesWithSecretsIsOneRead(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	svc, err := s.CreateService(ctx, Service{Kind: "site", Name: "site", Enabled: true, Settings: `{"n":"0"}`,
		Secrets: map[string][]byte{"chain": []byte("0"), "key": []byte("0")}})
	if err != nil {
		t.Fatal(err)
	}
	const rounds = 3000
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= rounds; i++ {
			n := strconv.Itoa(i)
			if err := s.UpdateService(ctx, svc.ID, ServiceUpdate{Settings: `{"n":"` + n + `"}`,
				Set: map[string][]byte{"chain": []byte(n), "key": []byte(n)}}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	check := func(settings string, secrets map[string][]byte) (string, bool) {
		var st struct {
			N string `json:"n"`
		}
		if err := json.Unmarshal([]byte(settings), &st); err != nil {
			t.Fatal(err)
		}
		return st.N, st.N == string(secrets["chain"]) && st.N == string(secrets["key"])
	}
	for last := ""; last != strconv.Itoa(rounds); {
		services, secrets, err := s.ServicesWithSecrets(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var ok bool
		if last, ok = check(services[len(services)-1].Settings, secrets[svc.ID]); !ok {
			t.Fatalf("settings of change %s with the secrets %q, %q", last, secrets[svc.ID]["chain"], secrets[svc.ID]["key"])
		}
		one, oneSecrets, err := s.ServiceWithSecrets(ctx, svc.ID)
		if err != nil {
			t.Fatal(err)
		}
		if n, ok := check(one.Settings, oneSecrets); !ok {
			t.Fatalf("ServiceWithSecrets: settings of change %s with the secrets %q", n, oneSecrets["chain"])
		}
	}
	wg.Wait()
	if _, _, err := s.ServiceWithSecrets(ctx, svc.ID+100); err == nil {
		t.Fatal("a service that is not there")
	}
}
