package provision

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// The secret S of a hy2-obfs service (SecretObfsPassword) changes when the
// operator asks (rayctl service rotate; spec/salamander-device-v1.md §3),
// with the overlap of R4: the next S is made and published at once, its
// switch a lead away, and the devices' passwords from it go into
// subscriptions as profiles[].next and into the front's list from then;
// at the switch it becomes current, and the one before stays accepted for
// the grace. A switch at once keeps nothing of the old one: devices that
// have not fetched their subscription since lose hy2-obfs until they do.
// The devices' passwords are of S (store.SalamanderDevicePassword), so a
// new S gives every device a new one; the SPA key, the other half, changes
// only with the device. Only with a niko-server whose front takes
// salamander off itself (render.NikoSalamanderDeviceFrom): before, S was
// every client's one password, and the front and the backend take one.

// ObfsState is the rotation state in the settings of a hy2-obfs service.
type ObfsState struct {
	RotatedAt int64 `json:"obfs_rotated_at,omitempty"` // last switch; 0 before the first
	NextFrom  int64 `json:"obfs_next_from,omitempty"`  // the next S is published, its switch then
	PrevUntil int64 `json:"obfs_prev_until,omitempty"` // the previous S is accepted until then
}

// ParseObfsState reads the S rotation state of a service.
func ParseObfsState(svc store.Service) ObfsState {
	var s ObfsState
	_ = json.Unmarshal([]byte(svc.Settings), &s)
	return s
}

// ObfsSecrets are the S a hy2-obfs service accepts at now, the current
// first: the current one, the next once published, the previous while in
// its grace. By the times, so the list is right before rayd's loop has
// made the switch or dropped the previous one (AdvanceObfs).
func ObfsSecrets(svc store.Service, secrets map[string][]byte, now time.Time) [][]byte {
	st := ParseObfsState(svc)
	out := [][]byte{secrets[SecretObfsPassword]}
	if next := secrets[NextSecret(SecretObfsPassword)]; len(next) > 0 && st.NextFrom != 0 {
		out = append(out, next)
	}
	if prev := secrets[PrevSecret(SecretObfsPassword)]; len(prev) > 0 && now.Unix() < st.PrevUntil {
		out = append(out, prev)
	}
	return out
}

// ObfsNext is the published next S and its switch; ok is false when there
// is none.
func ObfsNext(svc store.Service, secrets map[string][]byte) (next []byte, from time.Time, ok bool) {
	st := ParseObfsState(svc)
	next = secrets[NextSecret(SecretObfsPassword)]
	if len(next) == 0 || st.NextFrom == 0 {
		return nil, time.Time{}, false
	}
	return next, time.Unix(st.NextFrom, 0), true
}

// newObfsPassword is a new S, as CreateService makes the first.
func newObfsPassword() ([]byte, error) {
	pw := make([]byte, 24)
	if _, err := rand.Read(pw); err != nil {
		return nil, err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(pw)), nil
}

// RotateObfsPassword asks for a new S of a hy2-obfs service at now: the
// next one published at once with its switch a lead away, or with
// immediately the new one current at once, the next and the previous
// dropped. A next already published stays as it is, its switch too: the
// devices may have it already. It returns the new state.
func RotateObfsPassword(ctx context.Context, st *store.Store, name string, now time.Time, lead time.Duration, immediately bool) (ObfsState, error) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		return ObfsState{}, err
	}
	if svc.Kind != "hy2-obfs" {
		return ObfsState{}, fmt.Errorf("%w: %s is a %s service, not hy2-obfs", store.ErrInvalid, name, svc.Kind)
	}
	state := ParseObfsState(svc)
	if !immediately && state.NextFrom != 0 {
		return state, nil
	}
	pw, err := newObfsPassword()
	if err != nil {
		return ObfsState{}, err
	}
	u := store.ServiceUpdate{Set: map[string][]byte{}}
	if immediately {
		state = ObfsState{RotatedAt: now.Unix()}
		u.Set[SecretObfsPassword] = pw
		u.Delete = []string{NextSecret(SecretObfsPassword), PrevSecret(SecretObfsPassword)}
	} else {
		state.NextFrom = now.Add(lead).Unix()
		u.Set[NextSecret(SecretObfsPassword)] = pw
	}
	if u.Settings, err = setFields(svc.Settings, map[string]any{"obfs_rotated_at": state.RotatedAt,
		"obfs_next_from": state.NextFrom, "obfs_prev_until": state.PrevUntil}); err != nil {
		return ObfsState{}, err
	}
	return state, st.UpdateService(ctx, svc.ID, u)
}

// AdvanceObfs makes the switches of the hy2-obfs services' S that are due
// at now, the previous one accepted for grace more, and drops a previous
// one past its grace. It returns how many services changed: their front
// lists and subscriptions are rendered again.
func AdvanceObfs(ctx context.Context, st *store.Store, now time.Time, grace time.Duration, log *slog.Logger) (int, error) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	if log == nil {
		log = slog.Default()
	}
	all, err := st.ListServices(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, svc := range all {
		if svc.Kind != "hy2-obfs" {
			continue
		}
		state := ParseObfsState(svc)
		var u store.ServiceUpdate
		switch {
		case state.NextFrom != 0 && now.Unix() >= state.NextFrom:
			secrets, err := st.ServiceSecrets(ctx, svc.ID)
			if err != nil {
				return n, err
			}
			next := secrets[NextSecret(SecretObfsPassword)]
			if len(next) == 0 {
				// Lost (a restored backup?): nothing to switch to.
				log.Warn("hy2-obfs next password missing, no switch", "service", svc.Name)
				state.NextFrom = 0
			} else {
				u.Set = map[string][]byte{SecretObfsPassword: next, PrevSecret(SecretObfsPassword): secrets[SecretObfsPassword]}
				u.Delete = []string{NextSecret(SecretObfsPassword)}
				state = ObfsState{RotatedAt: state.NextFrom, PrevUntil: state.NextFrom + int64(grace/time.Second)}
				if grace <= 0 {
					delete(u.Set, PrevSecret(SecretObfsPassword))
					u.Delete = append(u.Delete, PrevSecret(SecretObfsPassword))
					state.PrevUntil = 0
				}
				log.Info("hy2-obfs password switched", "service", svc.Name)
			}
		case state.PrevUntil != 0 && now.Unix() >= state.PrevUntil:
			u.Delete = []string{PrevSecret(SecretObfsPassword)}
			state.PrevUntil = 0
			log.Info("hy2-obfs previous password no longer accepted", "service", svc.Name)
		default:
			continue
		}
		if u.Settings, err = setFields(svc.Settings, map[string]any{"obfs_rotated_at": state.RotatedAt,
			"obfs_next_from": state.NextFrom, "obfs_prev_until": state.PrevUntil}); err != nil {
			return n, err
		}
		if err := st.UpdateService(ctx, svc.ID, u); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
