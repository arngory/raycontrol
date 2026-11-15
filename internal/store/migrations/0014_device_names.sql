-- A revoked device's name is free again (docs/08-decisions.md, R4-36): a
-- new device of the user may take it. The name is unique among the user's
-- devices not revoked, a partial index, where 0001 had UNIQUE (user_id,
-- name) over all of them. SQLite cannot drop a table's constraint: the
-- table is made again with the same columns and rows. Nothing refers to
-- devices by a foreign key (invites.device_id is plain text).
CREATE TABLE devices_new (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    spa_key    BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    cert_pin   TEXT,
    lan        INTEGER NOT NULL DEFAULT 0,
    lan_at     INTEGER
);
INSERT INTO devices_new (id, user_id, name, role, spa_key, created_at, revoked_at, cert_pin, lan, lan_at)
    SELECT id, user_id, name, role, spa_key, created_at, revoked_at, cert_pin, lan, lan_at FROM devices;
DROP TABLE devices;
ALTER TABLE devices_new RENAME TO devices;
CREATE UNIQUE INDEX devices_cert_pin ON devices (cert_pin) WHERE cert_pin IS NOT NULL;
CREATE UNIQUE INDEX devices_name ON devices (user_id, name) WHERE revoked_at IS NULL;
