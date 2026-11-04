package store

import (
	"context"
	"database/sql"
)

// SummaryCount is one counter of the client summaries (R4-21).
type SummaryCount struct {
	Day    int64 // UTC day number (Unix seconds / 86400)
	ASN    uint32
	Svc    int64 // 0: the reports themselves
	Field  string
	Bucket string
	N      int64
}

// AddSummary adds counts in one transaction and remembers what the lookup
// said about the AS.
func (s *Store) AddSummary(ctx context.Context, counts []SummaryCount, asName, country string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, c := range counts {
			if _, err := tx.ExecContext(ctx, `INSERT INTO summary_counts (day, asn, svc, field, bucket, n) VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (day, asn, svc, field, bucket) DO UPDATE SET n = n + excluded.n`,
				c.Day, c.ASN, c.Svc, c.Field, c.Bucket, c.N); err != nil {
				return err
			}
		}
		if len(counts) > 0 && asName != "" {
			if _, err := tx.ExecContext(ctx, `INSERT INTO summary_as (asn, name, country) VALUES (?, ?, ?)
				ON CONFLICT (asn) DO UPDATE SET name = excluded.name, country = excluded.country`,
				counts[0].ASN, asName, country); err != nil {
				return err
			}
		}
		return nil
	})
}

// SummaryCounts returns the counters from day on, of one AS, or of all
// when all is set.
func (s *Store) SummaryCounts(ctx context.Context, fromDay int64, asn uint32, all bool) ([]SummaryCount, error) {
	q := `SELECT day, asn, svc, field, bucket, n FROM summary_counts WHERE day >= ? AND (? OR asn = ?) ORDER BY asn, svc, field, bucket, day`
	rows, err := s.db.QueryContext(ctx, q, fromDay, all, asn)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SummaryCount
	for rows.Next() {
		var c SummaryCount
		if err := rows.Scan(&c.Day, &c.ASN, &c.Svc, &c.Field, &c.Bucket, &c.N); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SummaryAS returns what is known of the systems: name and country.
func (s *Store) SummaryAS(ctx context.Context) (map[uint32][2]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT asn, name, country FROM summary_as`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint32][2]string{}
	for rows.Next() {
		var asn uint32
		var name, country string
		if err := rows.Scan(&asn, &name, &country); err != nil {
			return nil, err
		}
		out[asn] = [2]string{name, country}
	}
	return out, rows.Err()
}

// PruneSummary drops the counters before day, and the systems nothing
// counts any more.
func (s *Store) PruneSummary(ctx context.Context, beforeDay int64) (int64, error) {
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM summary_counts WHERE day < ?`, beforeDay)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		_, err = tx.ExecContext(ctx, `DELETE FROM summary_as WHERE asn NOT IN (SELECT DISTINCT asn FROM summary_counts)`)
		return err
	})
	return n, err
}
