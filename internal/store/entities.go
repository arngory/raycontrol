package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/arngory/raycontrol/internal/spa"
)

// ServiceKinds lists the services a node can run (docs/03-protocols.md).
var ServiceKinds = []string{
	"reality", "hy2-masq", "hy2-obfs", "naive", "doh", "yggdrasil",
	"dnstt", "masterdns", "olcrtc", "openflux", "inner", "site",
	"subscription", "api", "ssh",
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrInvalid wraps validation failures.
var ErrInvalid = errors.New("store: invalid")

func checkName(kind, name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("%w %s name %q: use 1-64 of a-z 0-9 . _ - starting with a letter or digit", ErrInvalid, kind, name)
	}
	return nil
}

// User is a person who may connect through the node.
type User struct {
	ID           int64
	Name         string
	Enabled      bool
	ExpiresAt    *time.Time
	TrafficLimit *int64 // bytes
	Note         string
	CreatedAt    time.Time
	Services     []int64 // allowed service IDs
}

// CreateUser inserts u and returns it with its ID.
func (s *Store) CreateUser(ctx context.Context, u User) (User, error) {
	if err := checkName("user", u.Name); err != nil {
		return u, err
	}
	u.CreatedAt = s.now().Truncate(time.Second)
	res, err := s.db.ExecContext(ctx, `INSERT INTO users (name, enabled, expires_at, traffic_limit_bytes, note, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.Name, u.Enabled, nullTime(u.ExpiresAt), u.TrafficLimit, u.Note, u.CreatedAt.Unix())
	if err != nil {
		return u, err
	}
	u.ID, err = res.LastInsertId()
	return u, err
}

const userCols = `id, name, enabled, expires_at, traffic_limit_bytes, note, created_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var exp, limit sql.NullInt64
	var created int64
	if err := row.Scan(&u.ID, &u.Name, &u.Enabled, &exp, &limit, &u.Note, &created); err != nil {
		return u, err
	}
	u.ExpiresAt = timePtr(exp)
	if limit.Valid {
		u.TrafficLimit = &limit.Int64
	}
	u.CreatedAt = time.Unix(created, 0)
	return u, nil
}

// UserByName returns a user with its allowed services.
func (s *Store) UserByName(ctx context.Context, name string) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return u, fmt.Errorf("user %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return u, err
	}
	u.Services, err = s.userServices(ctx, u.ID)
	return u, err
}

// ListUsers returns all users ordered by name.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Services, err = s.userServices(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) userServices(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT service_id FROM user_services WHERE user_id = ? ORDER BY service_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SetUserEnabled enables or disables a user.
func (s *Store) SetUserEnabled(ctx context.Context, name string, enabled bool) error {
	return s.affectOne(ctx, "user", name, `UPDATE users SET enabled = ? WHERE name = ?`, enabled, name)
}

// DeleteUser removes a user and, by cascade, its devices.
func (s *Store) DeleteUser(ctx context.Context, name string) error {
	return s.affectOne(ctx, "user", name, `DELETE FROM users WHERE name = ?`, name)
}

// SetUserServices replaces the services a user may reach.
func (s *Store) SetUserServices(ctx context.Context, name string, serviceIDs []int64) error {
	u, err := s.UserByName(ctx, name)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_services WHERE user_id = ?`, u.ID); err != nil {
			return err
		}
		for _, id := range serviceIDs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO user_services (user_id, service_id) VALUES (?, ?)`, u.ID, id); err != nil {
				return fmt.Errorf("service %d: %w", id, err)
			}
		}
		return nil
	})
}

// Service is one data-plane service of the node.
type Service struct {
	ID        int64 // also the SPA scope ID
	Kind      string
	Name      string
	Enabled   bool
	Settings  string // JSON
	UID       int    // system user of its process, 0 if it has none
	CreatedAt time.Time
	// Secrets are stored with a new service; they are not loaded back by
	// ListServices (use ServiceSecrets).
	Secrets map[string][]byte
}

// processNameRE keeps "niko-<name>" a valid system user name (32 chars).
var processNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,26}$`)

// CreateService inserts svc. IDs are never reused: clients refer to them
// in SPA scopes, so a deleted ID must not start meaning another service.
func (s *Store) CreateService(ctx context.Context, svc Service) (Service, error) {
	if !slices.Contains(ServiceKinds, svc.Kind) {
		return svc, fmt.Errorf("%w service kind %q", ErrInvalid, svc.Kind)
	}
	if err := checkName("service", svc.Name); err != nil {
		return svc, err
	}
	if svc.Settings == "" {
		svc.Settings = "{}"
	}
	if _, err := svc.Ports(); err != nil {
		return svc, err
	}
	if HasProcess(svc.Kind) && !processNameRE.MatchString(svc.Name) {
		return svc, fmt.Errorf("%w service name %q: services with a process need 1-27 of a-z 0-9 -", ErrInvalid, svc.Name)
	}
	// A process's runtime directories are <name>, <name>-in (what the front
	// passes) and <name>-api (Xray's API), its user niko-<name>: "x-in"
	// would take x's, "front" the front's.
	if HasProcess(svc.Kind) && (svc.Name == "front" || strings.HasSuffix(svc.Name, "-in") || strings.HasSuffix(svc.Name, "-api")) {
		return svc, fmt.Errorf("%w service name %q: front and names ending in -in or -api are taken", ErrInvalid, svc.Name)
	}
	svc.CreatedAt = s.now().Truncate(time.Second)
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var uid any
		if HasProcess(svc.Kind) {
			if err := tx.QueryRowContext(ctx, `
				WITH RECURSIVE r(u) AS (SELECT ? UNION ALL SELECT u + 1 FROM r WHERE u < ?)
				SELECT min(u) FROM r WHERE u NOT IN (SELECT uid FROM services WHERE uid IS NOT NULL)`,
				FirstServiceUID, LastServiceUID).Scan(&uid); err != nil {
				return err
			}
			if uid == nil {
				return fmt.Errorf("%w: no free service UID in %d-%d", ErrInvalid, FirstServiceUID, LastServiceUID)
			}
			svc.UID = int(uid.(int64))
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO services (kind, name, enabled, settings_json, uid, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			svc.Kind, svc.Name, svc.Enabled, svc.Settings, uid, svc.CreatedAt.Unix())
		if err != nil {
			return err
		}
		if svc.ID, err = res.LastInsertId(); err != nil {
			return err
		}
		for name, value := range svc.Secrets {
			if _, err := tx.ExecContext(ctx, `INSERT INTO service_secrets (service_id, name, value) VALUES (?, ?, ?)`, svc.ID, name, value); err != nil {
				return err
			}
		}
		return nil
	})
	svc.Secrets = nil
	return svc, err
}

// ServiceSecrets returns the secrets of a service.
func (s *Store) ServiceSecrets(ctx context.Context, serviceID int64) (map[string][]byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, value FROM service_secrets WHERE service_id = ?`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]byte{}
	for rows.Next() {
		var name string
		var value []byte
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		out[name] = value
	}
	return out, rows.Err()
}

// InitServiceSecret stores value unless the service has that secret, and
// returns the one stored: of two callers making it at once, both get the
// first.
func (s *Store) InitServiceSecret(ctx context.Context, serviceID int64, name string, value []byte) ([]byte, error) {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO service_secrets (service_id, name, value) VALUES (?, ?, ?)
		ON CONFLICT(service_id, name) DO NOTHING`, serviceID, name, value); err != nil {
		return nil, err
	}
	var v []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM service_secrets WHERE service_id = ? AND name = ?`, serviceID, name).Scan(&v)
	return v, err
}

// SetServiceSecret stores or replaces one secret of a service.
func (s *Store) SetServiceSecret(ctx context.Context, serviceID int64, name string, value []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO service_secrets (service_id, name, value) VALUES (?, ?, ?)
		ON CONFLICT(service_id, name) DO UPDATE SET value = excluded.value`, serviceID, name, value)
	return err
}

// ServiceUpdate changes a service in one transaction: its settings (unless
// empty) and secrets, set and deleted, so that a key and what goes with it
// (a certificate and its chain, a set of REALITY keys) never mix.
type ServiceUpdate struct {
	Settings string
	Set      map[string][]byte
	Delete   []string
}

// UpdateService applies u to the service with this ID.
func (s *Store) UpdateService(ctx context.Context, id int64, u ServiceUpdate) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if u.Settings != "" {
			var kind string
			if err := tx.QueryRowContext(ctx, `SELECT kind FROM services WHERE id = ?`, id).Scan(&kind); errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("service %d: %w", id, ErrNotFound)
			} else if err != nil {
				return err
			}
			if _, err := (Service{Kind: kind, Settings: u.Settings}).Ports(); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE services SET settings_json = ? WHERE id = ?`, u.Settings, id); err != nil {
				return err
			}
		}
		for _, name := range slices.Sorted(maps.Keys(u.Set)) {
			if _, err := tx.ExecContext(ctx, `INSERT INTO service_secrets (service_id, name, value) VALUES (?, ?, ?)
				ON CONFLICT(service_id, name) DO UPDATE SET value = excluded.value`, id, name, u.Set[name]); err != nil {
				return err
			}
		}
		for _, name := range u.Delete {
			if _, err := tx.ExecContext(ctx, `DELETE FROM service_secrets WHERE service_id = ? AND name = ?`, id, name); err != nil {
				return err
			}
		}
		return nil
	})
}

// Credentials returns the credential of every user for a service, creating
// missing ones with gen for the given users. Credentials of users not in
// userIDs are returned as they are.
func (s *Store) Credentials(ctx context.Context, serviceID int64, userIDs []int64, gen func() (string, error)) (map[int64]string, error) {
	out := map[int64]string{}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT user_id, secret FROM credentials WHERE service_id = ?`, serviceID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var secret string
			if err := rows.Scan(&id, &secret); err != nil {
				rows.Close()
				return err
			}
			out[id] = secret
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range userIDs {
			if _, ok := out[id]; ok {
				continue
			}
			secret, err := gen()
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO credentials (user_id, service_id, secret, created_at, rotated_at) VALUES (?, ?, ?, ?, ?)`,
				id, serviceID, secret, s.now().Unix(), s.now().Unix()); err != nil {
				return err
			}
			out[id] = secret
		}
		return nil
	})
	return out, err
}

// Credential is a user's secret for a service with its rotation state: the
// next secret is accepted from when it is published and becomes current at
// NextFrom; the previous one is accepted until PrevUntil.
type Credential struct {
	Current   string
	Next      string
	NextFrom  time.Time
	Prev      string
	PrevUntil time.Time
}

// Accepted returns the secrets a server takes now, current first.
func (c Credential) Accepted(now time.Time) []string {
	out := []string{c.Current}
	if c.Next != "" {
		out = append(out, c.Next)
	}
	if c.Prev != "" && now.Before(c.PrevUntil) {
		out = append(out, c.Prev)
	}
	return out
}

// CredentialSets is Credentials with the rotation state.
func (s *Store) CredentialSets(ctx context.Context, serviceID int64, userIDs []int64, gen func() (string, error)) (map[int64]Credential, error) {
	if _, err := s.Credentials(ctx, serviceID, userIDs, gen); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, secret, coalesce(next_secret, ''), coalesce(next_from, 0),
		coalesce(prev_secret, ''), coalesce(prev_until, 0) FROM credentials WHERE service_id = ?`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]Credential{}
	for rows.Next() {
		var id, nextFrom, prevUntil int64
		var c Credential
		if err := rows.Scan(&id, &c.Current, &c.Next, &nextFrom, &c.Prev, &prevUntil); err != nil {
			return nil, err
		}
		if nextFrom != 0 {
			c.NextFrom = time.Unix(nextFrom, 0)
		}
		if prevUntil != 0 {
			c.PrevUntil = time.Unix(prevUntil, 0)
		}
		out[id] = c
	}
	return out, rows.Err()
}

// Rotation is the schedule of credential rotation.
type Rotation struct {
	Period time.Duration // a secret is current this long
	Lead   time.Duration // the next one is published this long before the switch
	Grace  time.Duration // the previous one is accepted this long after it
}

// RotateCredentials advances every credential's rotation at now: publishes
// next secrets that are due, switches to them at their time and drops
// previous secrets past their grace. It returns how many rows changed.
func (s *Store) RotateCredentials(ctx context.Context, now time.Time, r Rotation, gen func() (string, error)) (int, error) {
	changed := 0
	err := s.tx(ctx, func(tx *sql.Tx) error {
		t := now.Unix()
		res, err := tx.ExecContext(ctx, `UPDATE credentials SET prev_secret = secret, prev_until = ?,
			secret = next_secret, next_secret = NULL, next_from = NULL, rotated_at = next_from
			WHERE next_secret IS NOT NULL AND next_from <= ?`, now.Add(r.Grace).Unix(), t)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		changed += int(n)
		res, err = tx.ExecContext(ctx, `UPDATE credentials SET prev_secret = NULL, prev_until = NULL
			WHERE prev_secret IS NOT NULL AND prev_until <= ?`, t)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		changed += int(n)

		rows, err := tx.QueryContext(ctx, `SELECT user_id, service_id, coalesce(rotated_at, created_at) FROM credentials
			WHERE next_secret IS NULL AND coalesce(rotated_at, created_at) + ? <= ?`,
			int64((r.Period-r.Lead)/time.Second), t)
		if err != nil {
			return err
		}
		type due struct{ user, service, rotated int64 }
		var dues []due
		for rows.Next() {
			var d due
			if err := rows.Scan(&d.user, &d.service, &d.rotated); err != nil {
				rows.Close()
				return err
			}
			dues = append(dues, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, d := range dues {
			secret, err := gen()
			if err != nil {
				return err
			}
			// The switch is a full lead away at least, so clients see the
			// next secret in time even after a long pause of the node.
			from := max(d.rotated+int64(r.Period/time.Second), t+int64(r.Lead/time.Second))
			if _, err := tx.ExecContext(ctx, `UPDATE credentials SET next_secret = ?, next_from = ? WHERE user_id = ? AND service_id = ?`,
				secret, from, d.user, d.service); err != nil {
				return err
			}
			changed++
		}
		return nil
	})
	return changed, err
}

// ListServices returns all services ordered by ID.
func (s *Store) ListServices(ctx context.Context) ([]Service, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, name, enabled, settings_json, coalesce(uid, 0), created_at FROM services ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		var svc Service
		var created int64
		if err := rows.Scan(&svc.ID, &svc.Kind, &svc.Name, &svc.Enabled, &svc.Settings, &svc.UID, &created); err != nil {
			return nil, err
		}
		svc.CreatedAt = time.Unix(created, 0)
		out = append(out, svc)
	}
	return out, rows.Err()
}

// ServiceByName looks a service up by name.
func (s *Store) ServiceByName(ctx context.Context, name string) (Service, error) {
	all, err := s.ListServices(ctx)
	if err != nil {
		return Service{}, err
	}
	for _, svc := range all {
		if svc.Name == name {
			return svc, nil
		}
	}
	return Service{}, fmt.Errorf("service %q: %w", name, ErrNotFound)
}

// SetServiceEnabled enables or disables a service.
func (s *Store) SetServiceEnabled(ctx context.Context, name string, enabled bool) error {
	return s.affectOne(ctx, "service", name, `UPDATE services SET enabled = ? WHERE name = ?`, enabled, name)
}

// DeleteService removes a service.
func (s *Store) DeleteService(ctx context.Context, name string) error {
	return s.affectOne(ctx, "service", name, `DELETE FROM services WHERE name = ?`, name)
}

// Device is an enrolled client device. Its SPA key is returned only once, by
// CreateDevice.
type Device struct {
	ID        string
	UserName  string
	Name      string
	Role      string // user | admin
	CreatedAt time.Time
	RevokedAt *time.Time
	CertPin   string // TLS client key of a device registered through the API
}

// CreateDevice enrolls a device for a user and returns its fresh SPA key.
func (s *Store) CreateDevice(ctx context.Context, userName, name, role string) (Device, [spa.KeySize]byte, error) {
	var key [spa.KeySize]byte
	if err := checkName("device", name); err != nil {
		return Device{}, key, err
	}
	if role != "user" && role != "admin" {
		return Device{}, key, fmt.Errorf("%w role %q: use user or admin", ErrInvalid, role)
	}
	u, err := s.UserByName(ctx, userName)
	if err != nil {
		return Device{}, key, err
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Device{}, key, err
	}
	if _, err := rand.Read(key[:]); err != nil {
		return Device{}, key, err
	}
	d := Device{ID: hex.EncodeToString(id[:]), UserName: u.Name, Name: name, Role: role, CreatedAt: s.now().Truncate(time.Second)}
	_, err = s.db.ExecContext(ctx, `INSERT INTO devices (id, user_id, name, role, spa_key, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		d.ID, u.ID, d.Name, d.Role, key[:], d.CreatedAt.Unix())
	return d, key, err
}

// ListDevices returns devices, optionally of one user.
func (s *Store) ListDevices(ctx context.Context, userName string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.id, u.name, d.name, d.role, d.created_at, d.revoked_at, coalesce(d.cert_pin, '')
		FROM devices d JOIN users u ON u.id = d.user_id
		WHERE ? = '' OR u.name = ? ORDER BY u.name, d.name`, userName, userName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var created int64
		var revoked sql.NullInt64
		if err := rows.Scan(&d.ID, &d.UserName, &d.Name, &d.Role, &created, &revoked, &d.CertPin); err != nil {
			return nil, err
		}
		d.CreatedAt, d.RevokedAt = time.Unix(created, 0), timePtr(revoked)
		out = append(out, d)
	}
	return out, rows.Err()
}

// ActiveDevice returns a device and its SPA key if the device may connect
// now: not revoked, with an enabled and unexpired user.
func (s *Store) ActiveDevice(ctx context.Context, id string) (Device, [spa.KeySize]byte, error) {
	var d Device
	var key [spa.KeySize]byte
	var raw []byte
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT d.id, u.name, d.name, d.role, d.spa_key, d.created_at
		FROM devices d JOIN users u ON u.id = d.user_id
		WHERE d.id = ? AND d.revoked_at IS NULL AND u.enabled = 1 AND (u.expires_at IS NULL OR u.expires_at > ?)`,
		id, s.now().Unix()).Scan(&d.ID, &d.UserName, &d.Name, &d.Role, &raw, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return d, key, fmt.Errorf("device %q: %w", id, ErrNotFound)
	}
	if err != nil {
		return d, key, err
	}
	copy(key[:], raw)
	d.CreatedAt = time.Unix(created, 0)
	return d, key, nil
}

// RevokeDevice marks a device revoked. Revocation is permanent.
func (s *Store) RevokeDevice(ctx context.Context, id string) error {
	return s.affectOne(ctx, "device", id, `UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, s.now().Unix(), id)
}

// SPADevices returns the devices that may currently pass SPA: not revoked,
// owned by an enabled and unexpired user, with that user's enabled services
// plus the subscription service, which every device may reach, and the API
// for admin devices registered through it (they have a client certificate).
// Active invites pass too, to the API only (R3-3).
func (s *Store) SPADevices(ctx context.Context) ([]spa.Device, error) {
	now := s.now().Unix()
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, d.spa_key, sv.id
		FROM devices d
		JOIN users u ON u.id = d.user_id
		JOIN services sv ON sv.enabled = 1 AND (sv.kind = 'subscription'
			OR (sv.kind = 'api' AND d.role = 'admin' AND d.cert_pin IS NOT NULL)
			OR sv.id IN (SELECT service_id FROM user_services WHERE user_id = u.id))
		WHERE d.revoked_at IS NULL AND u.enabled = 1
		  AND (u.expires_at IS NULL OR u.expires_at > ?)
		UNION ALL
		SELECT i.id, i.spa_key, sv.id
		FROM invites i
		JOIN users u ON u.id = i.user_id
		JOIN services sv ON sv.enabled = 1 AND sv.kind = 'api'
		WHERE i.used_at IS NULL AND i.expires_at > ? AND u.enabled = 1
		  AND (u.expires_at IS NULL OR u.expires_at > ?)
		ORDER BY 1, 3`, now, now, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []spa.Device
	for rows.Next() {
		var id string
		var key []byte
		var svc uint16
		if err := rows.Scan(&id, &key, &svc); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].ID != id {
			d := spa.Device{ID: id}
			copy(d.Key[:], key)
			out = append(out, d)
		}
		last := &out[len(out)-1]
		last.Allowed = append(last.Allowed, svc)
	}
	return out, rows.Err()
}

func (s *Store) affectOne(ctx context.Context, kind, ref, query string, args ...any) error {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%s %q: %w", kind, ref, ErrNotFound)
	}
	return nil
}
