package provision

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// The seal key of a dnstt service (spec/dnsseal-v1.md §8) changes when the
// operator asks (rayctl service rotate): the new key is current at once and
// goes into subscriptions; the previous one stays accepted for the grace
// period of credentials (rayd -cred-grace), so that clients that have not
// fetched their subscription since keep working, then it goes. A switch at
// once drops it straight away (a key in the wrong hands): those clients get
// nothing until they fetch their subscription. Only one previous key is
// kept: a second switch within the grace drops the one before.

// DNSSealMode is a dnstt service's dnsseal-v1 mode: off, optional or
// required (spec/dnsseal-v1.md §5); off when unset.
func DNSSealMode(s store.Service) string {
	var st struct {
		Seal string `json:"seal"`
	}
	_ = json.Unmarshal([]byte(s.Settings), &st)
	if s.Kind != "dnstt" || st.Seal == "" {
		return "off"
	}
	return st.Seal
}

// DNSAuthMode is a dnstt service's dnsauth-v1 mode: off, optional or
// required (spec/dnsauth-v1.md §5).
func DNSAuthMode(s store.Service) string {
	var st struct {
		Auth string `json:"auth"`
	}
	_ = json.Unmarshal([]byte(s.Settings), &st)
	if s.Kind != "dnstt" || st.Auth == "" {
		return "off"
	}
	return st.Auth
}

// SealState is the rotation state in the settings of a dnstt service.
type SealState struct {
	RotatedAt int64 `json:"seal_rotated_at,omitempty"` // last switch; 0 before the first
	PrevUntil int64 `json:"seal_prev_until,omitempty"` // the previous key is accepted until then
}

// ParseSealState reads the seal key rotation state of a service.
func ParseSealState(svc store.Service) SealState {
	var s SealState
	_ = json.Unmarshal([]byte(svc.Settings), &s)
	return s
}

// SealKeys are the keys a dnstt service accepts, the current first: what
// the backend's seal key file holds. The previous key is in it until
// ExpireSealKeys drops it, as REALITY's previous set (PrevReality).
func SealKeys(svc store.Service, secrets map[string][]byte) [][]byte {
	keys := [][]byte{secrets[SecretSealKey]}
	if prev := secrets[PrevSecret(SecretSealKey)]; len(prev) == 32 && ParseSealState(svc).PrevUntil != 0 {
		keys = append(keys, prev)
	}
	return keys
}

// RotateSealKey gives a dnstt service a new seal key at now; the previous
// one is accepted for grace more, or not at all when immediately is set or
// grace is zero. It returns the new state.
func RotateSealKey(ctx context.Context, st *store.Store, name string, now time.Time, grace time.Duration, immediately bool) (SealState, error) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		return SealState{}, err
	}
	if svc.Kind != "dnstt" {
		return SealState{}, fmt.Errorf("%w: %s is a %s service: rotate takes REALITY and dnstt (its seal key)", store.ErrInvalid, name, svc.Kind)
	}
	secrets, err := st.ServiceSecrets(ctx, svc.ID)
	if err != nil {
		return SealState{}, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return SealState{}, err
	}
	state := SealState{RotatedAt: now.Unix()}
	u := store.ServiceUpdate{Set: map[string][]byte{SecretSealKey: key}}
	if old := secrets[SecretSealKey]; len(old) == 32 && !immediately && grace > 0 {
		u.Set[PrevSecret(SecretSealKey)] = old
		state.PrevUntil = now.Add(grace).Unix()
	} else {
		u.Delete = []string{PrevSecret(SecretSealKey)}
	}
	if u.Settings, err = setFields(svc.Settings, map[string]any{"seal_rotated_at": state.RotatedAt, "seal_prev_until": state.PrevUntil}); err != nil {
		return SealState{}, err
	}
	if err := st.UpdateService(ctx, svc.ID, u); err != nil {
		return SealState{}, err
	}
	// The node's own dnsauth key for its check (node-check in the keys of
	// every dnstt service) is renewed with it: it had no other way to
	// change (review 9). The check may warn once until the next render.
	return state, st.RenewDNSCheckKey(ctx)
}

// ExpireSealKeys drops the previous seal keys whose grace is over at now
// and returns how many services changed: their key files must be rendered
// again.
func ExpireSealKeys(ctx context.Context, st *store.Store, now time.Time, log *slog.Logger) (int, error) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	all, err := st.ListServices(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, svc := range all {
		if svc.Kind != "dnstt" {
			continue
		}
		if until := ParseSealState(svc).PrevUntil; until == 0 || now.Unix() < until {
			continue
		}
		settings, err := setFields(svc.Settings, map[string]any{"seal_prev_until": nil})
		if err != nil {
			return n, err
		}
		if err := st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: settings, Delete: []string{PrevSecret(SecretSealKey)}}); err != nil {
			return n, err
		}
		log.Info("previous seal key no longer accepted", "service", svc.Name)
		n++
	}
	return n, nil
}
