package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"
)

// OpenReadOnly opens the database at path for reading only: no file is
// made, no migration runs, nothing is written; a rayd may run on it
// meanwhile (rayd init -check-ports beside the node's rayd). A database
// migrated by a newer raycontrol is refused (ErrNewerSchema); one this
// build would migrate is read as it is.
func OpenReadOnly(ctx context.Context, path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	v, err := Schema(ctx, path)
	if err != nil {
		return nil, err
	}
	if v > KnownSchema() {
		return nil, ErrNewerSchema
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, errors.Join(errors.New("store: opening read-only"), err)
	}
	return &Store{db: db, now: time.Now, path: path}, nil
}
