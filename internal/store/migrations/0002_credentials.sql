-- R1: system users of data-plane processes, per-user credentials and
-- per-service secrets.

-- Fixed UID of the service's process (docs/08-decisions.md, R1-6); NULL for
-- kinds without a process of their own (ssh, subscription, api).
ALTER TABLE services ADD COLUMN uid INTEGER;
CREATE UNIQUE INDEX services_uid ON services(uid) WHERE uid IS NOT NULL;

-- One credential per user and service (e.g. the inner VLESS UUID).
-- Rotation (current/next) arrives in R4.
CREATE TABLE credentials (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    secret     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, service_id)
);

-- Secrets of a service itself: tunnel keys, VLESS encryption seed, TLS keys.
CREATE TABLE service_secrets (
    service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    value      BLOB NOT NULL,
    PRIMARY KEY (service_id, name)
);
