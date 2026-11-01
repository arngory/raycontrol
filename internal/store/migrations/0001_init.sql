-- Initial schema. Later migrations add credentials, rotations, grants and
-- traffic as the stages that use them land (docs/01-architecture.md).

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE users (
    id                  INTEGER PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    enabled             INTEGER NOT NULL DEFAULT 1,
    expires_at          INTEGER,            -- unix seconds, NULL = never
    traffic_limit_bytes INTEGER,            -- NULL = unlimited
    note                TEXT NOT NULL DEFAULT '',
    created_at          INTEGER NOT NULL
);

-- Service IDs double as SPA scope identifiers: they must fit in uint16 and
-- are never reused (AUTOINCREMENT).
CREATE TABLE services (
    id            INTEGER PRIMARY KEY AUTOINCREMENT CHECK (id BETWEEN 1 AND 65535),
    kind          TEXT NOT NULL,
    name          TEXT NOT NULL UNIQUE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    settings_json TEXT NOT NULL DEFAULT '{}',
    created_at    INTEGER NOT NULL
);

CREATE TABLE devices (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    spa_key    BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    UNIQUE (user_id, name)
);

-- Services a user may reach; SPA grants are limited to these.
CREATE TABLE user_services (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, service_id)
);

CREATE TABLE audit_log (
    id     INTEGER PRIMARY KEY,
    ts     INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL
);

CREATE INDEX audit_log_ts ON audit_log(ts);
