package provision

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// MasterDNSKeyState is the rotation state of a masterdns service's key
// (spec/masterdns-key-rotation.md §2), in its settings.
type MasterDNSKeyState struct {
	RotatedAt int64 `json:"key_rotated_at,omitempty"` // last switch; 0 before the first
	PrevUntil int64 `json:"key_prev_until,omitempty"` // the previous key is accepted until then
}

// ParseMasterDNSKeyState reads a masterdns service's key rotation state.
func ParseMasterDNSKeyState(svc store.Service) MasterDNSKeyState {
	var s MasterDNSKeyState
	_ = json.Unmarshal([]byte(svc.Settings), &s)
	return s
}

// MasterDNSKeys are the keys a masterdns service takes, the current first:
// what its backend's key file holds (§3). The previous key is in it until
// ExpireSealKeys drops it.
func MasterDNSKeys(svc store.Service, secrets map[string][]byte) [][]byte {
	keys := [][]byte{secrets[SecretMasterDNSKey]}
	if prev := secrets[PrevSecret(SecretMasterDNSKey)]; len(prev) > 0 && ParseMasterDNSKeyState(svc).PrevUntil != 0 {
		keys = append(keys, prev)
	}
	return keys
}

// newMasterDNSKey is a masterdns key: 16 random bytes as 32 hex characters,
// as MasterDnsVPN takes them for method 5.
func newMasterDNSKey() ([]byte, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(raw)), nil
}

// RotateMasterDNSKey gives a masterdns service a new key at now (§2): it goes
// out with subscriptions from then on, and the previous one is taken for
// grace more, or not at all when immediately is set or grace is zero (its
// sessions then close at once). A second switch with a grace within the
// grace is store.ErrPrecondition: it would drop the key before the previous
// one with no grace; force does it anyway (checkGrace).
func RotateMasterDNSKey(ctx context.Context, st *store.Store, name string, now time.Time, grace time.Duration, immediately, force bool) (MasterDNSKeyState, error) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		return MasterDNSKeyState{}, err
	}
	if svc.Kind != "masterdns" {
		return MasterDNSKeyState{}, fmt.Errorf("%w: %s is a %s service, not masterdns", store.ErrInvalid, name, svc.Kind)
	}
	secrets, err := st.ServiceSecrets(ctx, svc.ID)
	if err != nil {
		return MasterDNSKeyState{}, err
	}
	if err := checkGrace(name, "service", len(secrets[PrevSecret(SecretMasterDNSKey)]) > 0, ParseMasterDNSKeyState(svc).PrevUntil, now, grace, immediately, force); err != nil {
		return MasterDNSKeyState{}, err
	}
	key, err := newMasterDNSKey()
	if err != nil {
		return MasterDNSKeyState{}, err
	}
	state := MasterDNSKeyState{RotatedAt: now.Unix()}
	u := store.ServiceUpdate{Set: map[string][]byte{SecretMasterDNSKey: key}}
	if old := secrets[SecretMasterDNSKey]; len(old) > 0 && !immediately && grace > 0 {
		u.Set[PrevSecret(SecretMasterDNSKey)] = old
		state.PrevUntil = now.Add(grace).Unix()
	} else {
		u.Delete = []string{PrevSecret(SecretMasterDNSKey)}
	}
	if u.Settings, err = setFields(svc.Settings, map[string]any{"key_rotated_at": state.RotatedAt, "key_prev_until": state.PrevUntil}); err != nil {
		return MasterDNSKeyState{}, err
	}
	return state, st.UpdateService(ctx, svc.ID, u)
}
