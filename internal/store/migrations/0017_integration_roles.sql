-- integrations-v1 §2.1: devices and invites of the roles billing and
-- support, besides user and admin. SQLite cannot change a table's CHECK
-- in place: both tables are made again with the same columns, rows and
-- indexes, as 0014 did. Nothing refers to them by a foreign key.
-- by_integration: the invite an integration made, and the device it
-- became (§2.2): never past a regular user's data services.
CREATE TABLE devices_new (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('user', 'admin', 'billing', 'support')),
    spa_key    BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    cert_pin   TEXT,
    lan        INTEGER NOT NULL DEFAULT 0,
    lan_at     INTEGER,
    client     TEXT,
    client_at  INTEGER,
    by_integration INTEGER NOT NULL DEFAULT 0
);
INSERT INTO devices_new (id, user_id, name, role, spa_key, created_at, revoked_at, cert_pin, lan, lan_at, client, client_at)
    SELECT id, user_id, name, role, spa_key, created_at, revoked_at, cert_pin, lan, lan_at, client, client_at FROM devices;
DROP TABLE devices;
ALTER TABLE devices_new RENAME TO devices;
CREATE UNIQUE INDEX devices_cert_pin ON devices (cert_pin) WHERE cert_pin IS NOT NULL;
CREATE UNIQUE INDEX devices_name ON devices (user_id, name) WHERE revoked_at IS NULL;

CREATE TABLE invites_new (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('user', 'admin', 'billing', 'support')),
    spa_key    BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    device_id  TEXT,
    pin_proof  BLOB,
    pin_tries  INTEGER NOT NULL DEFAULT 0,
    by_integration INTEGER NOT NULL DEFAULT 0
);
INSERT INTO invites_new (id, user_id, name, role, spa_key, created_at, expires_at, used_at, device_id, pin_proof, pin_tries)
    SELECT id, user_id, name, role, spa_key, created_at, expires_at, used_at, device_id, pin_proof, pin_tries FROM invites;
DROP TABLE invites;
ALTER TABLE invites_new RENAME TO invites;
