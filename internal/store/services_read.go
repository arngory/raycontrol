package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ServicesWithSecrets returns every service and its secrets (by service
// ID) as one read. UpdateService changes a service's settings and secrets
// together; ListServices followed by ServiceSecrets may read across such a
// change and pair the settings of before with the secrets of after. Here
// both come from one transaction, and the store has one connection: no
// change lands between them.
func (s *Store) ServicesWithSecrets(ctx context.Context) ([]Service, map[int64]map[string][]byte, error) {
	var services []Service
	secrets := map[int64]map[string][]byte{}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, kind, name, enabled, settings_json, coalesce(uid, 0), created_at FROM services ORDER BY id`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var svc Service
			var created int64
			if err := rows.Scan(&svc.ID, &svc.Kind, &svc.Name, &svc.Enabled, &svc.Settings, &svc.UID, &created); err != nil {
				rows.Close()
				return err
			}
			svc.CreatedAt = time.Unix(created, 0)
			services = append(services, svc)
			secrets[svc.ID] = map[string][]byte{}
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows, err = tx.QueryContext(ctx, `SELECT service_id, name, value FROM service_secrets`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			var name string
			var value []byte
			if err := rows.Scan(&id, &name, &value); err != nil {
				return err
			}
			if secrets[id] != nil {
				secrets[id][name] = value
			}
		}
		return rows.Err()
	})
	return services, secrets, err
}

// ServiceWithSecrets is one service and its secrets as one read
// (ServicesWithSecrets).
func (s *Store) ServiceWithSecrets(ctx context.Context, id int64) (Service, map[string][]byte, error) {
	services, secrets, err := s.ServicesWithSecrets(ctx)
	if err != nil {
		return Service{}, nil, err
	}
	for _, svc := range services {
		if svc.ID == id {
			return svc, secrets[id], nil
		}
	}
	return Service{}, nil, fmt.Errorf("service %d: %w", id, ErrNotFound)
}
