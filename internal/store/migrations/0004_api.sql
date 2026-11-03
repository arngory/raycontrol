-- R3: the remote API (docs/08-decisions.md, R3-3). A device registered
-- through the API is known by the key of its TLS client certificate:
-- base64url SHA-256 of the SubjectPublicKeyInfo, as the client pins the
-- node's certificates.
ALTER TABLE devices ADD COLUMN cert_pin TEXT;
CREATE UNIQUE INDEX devices_cert_pin ON devices (cert_pin) WHERE cert_pin IS NOT NULL;

-- One-time invites: their SPA key opens the API port only, for Register.
CREATE TABLE invites (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    spa_key    BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    device_id  TEXT
);
