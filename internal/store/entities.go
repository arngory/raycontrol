package store

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arngory/raycontrol/internal/spa"
)

// ServiceKinds lists the services a node can run (docs/03-protocols.md).
var ServiceKinds = []string{
	"reality", "hy2-masq", "hy2-obfs", "naive", "doh", "yggdrasil",
	"dnstt", "masterdns", "slipstream", "olcrtc", "openflux", "inner", "site",
	"subscription", "api", "ssh",
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrInvalid wraps validation failures.
var ErrInvalid = errors.New("store: invalid")

// ErrPrecondition wraps a change refused in the current state, which the
// caller may wait out or force.
var ErrPrecondition = errors.New("not now")

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
	// The limit's period (traffic-limit-v1 §3.4): PeriodMonthly from
	// TrafficResetDay, or PeriodNone; kept whether or not there is a limit.
	TrafficPeriod   string
	TrafficResetDay int
	// The current period's count as rayd last wrote it, with a limit only:
	// its start (zero without a limit) and its bytes at the destinations'
	// side. Used and the methods beside it read them at a moment.
	TrafficStart           time.Time
	TrafficUp, TrafficDown int64
	// TrafficCountedFrom is when the limit was set: rayd counts the bytes
	// of the processes it read after that, not before.
	TrafficCountedFrom time.Time
	// LAN: the administrator lets the user's devices see each other over
	// Yggdrasil (lan-v1 §1.1); each device decides for itself too
	// (Device.LAN).
	LAN bool
}

// CreateUser inserts u with its services (u.Services, IDs), all or
// nothing, and returns it with its ID. A limit counts from now.
func (s *Store) CreateUser(ctx context.Context, u User) (User, error) {
	if err := checkName("user", u.Name); err != nil {
		return u, err
	}
	u.TrafficPeriod = cmp.Or(u.TrafficPeriod, PeriodMonthly)
	u.TrafficResetDay = cmp.Or(u.TrafficResetDay, 1)
	if err := CheckTrafficPeriod(u.TrafficPeriod, u.TrafficResetDay); err != nil {
		return u, err
	}
	if u.TrafficLimit != nil && *u.TrafficLimit <= 0 {
		return u, fmt.Errorf("%w traffic limit %d: more than 0 bytes, or none", ErrInvalid, *u.TrafficLimit)
	}
	u.CreatedAt = s.now().Truncate(time.Second)
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO users (name, enabled, expires_at, traffic_limit_bytes, note, created_at, traffic_period, traffic_reset_day)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			u.Name, u.Enabled, nullTime(u.ExpiresAt), u.TrafficLimit, u.Note, u.CreatedAt.Unix(), u.TrafficPeriod, u.TrafficResetDay)
		if err != nil {
			return err
		}
		if u.ID, err = res.LastInsertId(); err != nil {
			return err
		}
		for _, id := range u.Services {
			if _, err := tx.ExecContext(ctx, `INSERT INTO user_services (user_id, service_id) VALUES (?, ?)`, u.ID, id); err != nil {
				return fmt.Errorf("service %d: %w", id, err)
			}
		}
		if u.TrafficLimit != nil {
			u.TrafficStart, u.TrafficCountedFrom = u.CreatedAt, u.CreatedAt
			_, err = tx.ExecContext(ctx, `INSERT INTO user_traffic (user_id, period_start, counted_from) VALUES (?, ?, ?)`,
				u.ID, u.CreatedAt.Unix(), u.CreatedAt.Unix())
		}
		return err
	})
	return u, err
}

// userSelect reads users with their count, in scanUser's order.
const userSelect = `SELECT u.id, u.name, u.enabled, u.expires_at, u.traffic_limit_bytes, u.note, u.created_at,
	u.traffic_period, u.traffic_reset_day, t.period_start, t.counted_from, coalesce(t.up, 0), coalesce(t.down, 0), u.lan
	FROM users u LEFT JOIN user_traffic t ON t.user_id = u.id`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var exp, limit, start, from sql.NullInt64
	var created int64
	if err := row.Scan(&u.ID, &u.Name, &u.Enabled, &exp, &limit, &u.Note, &created,
		&u.TrafficPeriod, &u.TrafficResetDay, &start, &from, &u.TrafficUp, &u.TrafficDown, &u.LAN); err != nil {
		return u, err
	}
	u.ExpiresAt = timePtr(exp)
	switch {
	case !limit.Valid:
		u.TrafficUp, u.TrafficDown = 0, 0
	case start.Valid:
		u.TrafficLimit = &limit.Int64
		u.TrafficStart, u.TrafficCountedFrom = time.Unix(start.Int64, 0), time.Unix(from.Int64, 0)
	default:
		u.TrafficLimit = &limit.Int64
	}
	u.CreatedAt = time.Unix(created, 0)
	return u, nil
}

// UserByName returns a user with its allowed services.
func (s *Store) UserByName(ctx context.Context, name string) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE u.name = ?`, name))
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
	rows, err := s.db.QueryContext(ctx, userSelect+` ORDER BY u.name`)
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
	// Every user's services in one query, not one a user: rayd lists the
	// users at every apply and every traffic round.
	byID := make(map[int64]int, len(out))
	for i := range out {
		byID[out[i].ID] = i
	}
	rows, err = s.db.QueryContext(ctx, `SELECT user_id, service_id FROM user_services ORDER BY user_id, service_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var user, svc int64
		if err := rows.Scan(&user, &svc); err != nil {
			return nil, err
		}
		if i, ok := byID[user]; ok {
			out[i].Services = append(out[i].Services, svc)
		}
	}
	return out, rows.Err()
}

// HasTrafficLimits reports whether some user has a traffic limit: the
// traffic loop reads nothing otherwise.
func (s *Store) HasTrafficLimits(ctx context.Context) (bool, error) {
	var any bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE traffic_limit_bytes IS NOT NULL)`).Scan(&any)
	return any, err
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

// CheckServiceName checks the name of a service as CreateService does.
func CheckServiceName(name string) error { return checkName("service", name) }

// CheckProcessName checks the name of a service with a process of its own
// (HasProcess) as CreateService does. The name goes into its user, its
// unit and its runtime directories: rayctl apply checks the services rayd
// reports with it too (spec/apply-plan-v1.md).
func CheckProcessName(name string) error {
	if !processNameRE.MatchString(name) {
		return fmt.Errorf("%w service name %q: services with a process need 1-27 of a-z 0-9 -", ErrInvalid, name)
	}
	// A process's runtime directories are <name>, <name>-in (what the front
	// passes) and <name>-api (Xray's API), its user niko-<name>: "x-in"
	// would take x's, "front" the front's.
	if name == "front" || strings.HasSuffix(name, "-in") || strings.HasSuffix(name, "-api") {
		return fmt.Errorf("%w service name %q: front and names ending in -in or -api are taken", ErrInvalid, name)
	}
	return nil
}

// CreateService inserts svc. IDs are never reused: clients refer to them
// in SPA scopes, so a deleted ID must not start meaning another service.
func (s *Store) CreateService(ctx context.Context, svc Service) (Service, error) {
	if !slices.Contains(ServiceKinds, svc.Kind) {
		return svc, fmt.Errorf("%w service kind %q", ErrInvalid, svc.Kind)
	}
	if err := CheckServiceName(svc.Name); err != nil {
		return svc, err
	}
	if svc.Settings == "" {
		svc.Settings = "{}"
	}
	if _, err := svc.Ports(); err != nil {
		return svc, err
	}
	if HasProcess(svc.Kind) {
		if err := CheckProcessName(svc.Name); err != nil {
			return svc, err
		}
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

// credentialPrint is the bytes of a credential's fingerprint in its name.
const credentialPrint = 8

// CredentialName is the name a credential goes by in the data plane: the
// email of an Xray user (inner, REALITY), the name in the users files of
// Hysteria2 and naive. The processes count bytes by it (traffic-limit-v1
// §1), and Xray and niko-server cut the connections of a name that goes
// or changes its secret. It is the user's u<id>, a dash and a fingerprint
// of the secret: 16 hex digits of a SHA-256 under a label of its own, so
// it tells nothing of the secret. The secret is the credential for its
// whole life, current, next and previous alike, so its name stays when
// the roles move at a switch, and nothing is cut (rayd before v0.23.0
// named them by the role, u5, u5-n and u5-p, and every switch renamed
// two). A different secret of the user never gets the name, unless 64
// bits of SHA-256 collide; another user's name has another u<id>. Nothing
// is stored: rollback and the store need no new column.
func CredentialName(userID int64, secret string) string {
	sum := sha256.Sum256([]byte("raycontrol credential name\x00" + secret))
	return "u" + strconv.FormatInt(userID, 10) + "-" + hex.EncodeToString(sum[:credentialPrint])
}

// isCredentialPrint reports whether s is a fingerprint as CredentialName
// writes it: 16 lowercase hex digits.
func isCredentialPrint(s string) bool {
	return len(s) == 2*credentialPrint && strings.Trim(s, "0123456789abcdef") == ""
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
	// LAN: the device shows itself to the user's other devices, as its
	// X-Raycontrol-LAN header last said (lan-v1 §1.1).
	LAN bool
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

// DeviceSecret is a device and its SPA key, which only it and the node
// hold.
type DeviceSecret struct {
	ID  string
	Key [spa.KeySize]byte
	// LAN: the device shows itself (Device.LAN).
	LAN bool
}

// ActiveDeviceSecrets maps user ID to the user's devices not revoked, in
// order.
func (s *Store) ActiveDeviceSecrets(ctx context.Context) (map[int64][]DeviceSecret, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, id, spa_key, lan FROM devices WHERE revoked_at IS NULL ORDER BY user_id, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]DeviceSecret{}
	for rows.Next() {
		var user int64
		var d DeviceSecret
		var key []byte
		if err := rows.Scan(&user, &d.ID, &key, &d.LAN); err != nil {
			return nil, err
		}
		copy(d.Key[:], key)
		out[user] = append(out[user], d)
	}
	return out, rows.Err()
}

// ListDevices returns devices, optionally of one user.
func (s *Store) ListDevices(ctx context.Context, userName string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.id, u.name, d.name, d.role, d.created_at, d.revoked_at, coalesce(d.cert_pin, ''), d.lan
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
		if err := rows.Scan(&d.ID, &d.UserName, &d.Name, &d.Role, &created, &revoked, &d.CertPin, &d.LAN); err != nil {
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

// RevokeDevice marks a device revoked. Revocation is permanent. The user's
// LAN key, when there is one, is new with it (lan-v1 §3): the multicast
// password the device knew is no longer the user's, both at once. A device
// revoked already is no error and changes nothing; an unknown one is
// ErrNotFound.
func (s *Store) RevokeDevice(ctx context.Context, id string) error {
	key, err := newLANKey()
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, s.now().Unix(), id)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			// Revoked already (a retry): done, nothing changes.
			var known int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM devices WHERE id = ?`, id).Scan(&known); err != nil || known > 0 {
				return err
			}
			return fmt.Errorf("device %q: %w", id, ErrNotFound)
		}
		_, err = tx.ExecContext(ctx, `UPDATE users SET lan_key = ? WHERE lan_key IS NOT NULL
			AND id = (SELECT user_id FROM devices WHERE id = ?)`, key, id)
		return err
	})
}

// SPADevices returns the devices that may currently pass SPA: not revoked,
// owned by an enabled and unexpired user (User.Live), with the
// subscription service, which every device may reach, the API for admin
// devices registered through it (they have a client certificate), and the
// user's enabled services while the user is Active: one over the traffic
// limit keeps the subscription and the API, no data service
// (traffic-limit-v1 §3.1). Active invites pass too, to the API only (R3-3),
// and so do invites used less than InviteReplayWindow ago while their
// device is not revoked: a client that lost Register's answer asks again
// with the invite (api-v1 §4.1).
func (s *Store) SPADevices(ctx context.Context) ([]spa.Device, error) {
	now := s.now()
	users, err := s.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}
	services, err := s.ListServices(ctx) // by ID
	if err != nil {
		return nil, err
	}
	// allowed is a device's scope, sorted.
	allowed := func(u User, admin, invite bool) []uint16 {
		var ids []uint16
		for _, svc := range services {
			switch {
			case !svc.Enabled:
			case invite:
				if svc.Kind == "api" {
					ids = append(ids, uint16(svc.ID)) //nolint:gosec // G115: service IDs fit (CHECK)
				}
			case svc.Kind == "subscription", svc.Kind == "api" && admin,
				u.Active(now) && slices.Contains(u.Services, svc.ID):
				ids = append(ids, uint16(svc.ID)) //nolint:gosec // G115: service IDs fit (CHECK)
			}
		}
		return ids
	}
	type row struct {
		id     string
		key    []byte
		user   int64
		admin  bool
		invite bool
	}
	var list []row
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, d.spa_key, d.user_id, d.role = 'admin' AND d.cert_pin IS NOT NULL, 0
		FROM devices d WHERE d.revoked_at IS NULL
		UNION ALL
		SELECT i.id, i.spa_key, i.user_id, 0, 1
		FROM invites i WHERE (i.used_at IS NULL AND i.expires_at > ?)
			OR (i.used_at > ? AND EXISTS (SELECT 1 FROM devices d WHERE d.id = i.device_id AND d.revoked_at IS NULL))
		ORDER BY 1`, now.Unix(), now.Add(-InviteReplayWindow).Unix())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.key, &r.user, &r.admin, &r.invite); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []spa.Device
	for _, r := range list {
		u, ok := byID[r.user]
		if !ok || !u.Live(now) {
			continue
		}
		ids := allowed(u, r.admin, r.invite)
		if len(ids) == 0 {
			continue
		}
		d := spa.Device{ID: r.id, Allowed: ids}
		copy(d.Key[:], r.key)
		out = append(out, d)
	}
	return out, nil
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
