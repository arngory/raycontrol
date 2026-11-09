-- traffic-limit-v1 §2.5: a user's limit is enforced. Each user's period
-- (monthly from a reset day, 00:00 UTC, or none: the user's whole time),
-- the count of the current period for users with a limit only, and what
-- rayd last read from each process that counts (no history: counters by
-- name, never destinations).
ALTER TABLE users ADD COLUMN traffic_period TEXT NOT NULL DEFAULT 'monthly'; -- 'monthly' | 'none'
ALTER TABLE users ADD COLUMN traffic_reset_day INTEGER NOT NULL DEFAULT 1;   -- 1..28

-- period_start: the current period's start (the last reset, or when the
-- limit was set); counted_from: when the limit was set, counting starts
-- there (rayd baselines the counters of a user set later than a
-- process's last poll).
CREATE TABLE user_traffic (
    user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    period_start INTEGER NOT NULL,
    counted_from INTEGER NOT NULL,
    up           INTEGER NOT NULL DEFAULT 0,
    down         INTEGER NOT NULL DEFAULT 0
);

-- A process that counts ("xray:inner", "hy2:<service>", "naive:<service>"):
-- its start as it gives it, and when rayd's count was taken from it.
CREATE TABLE traffic_sources (
    source    TEXT PRIMARY KEY,
    boot      TEXT NOT NULL,
    polled_at INTEGER NOT NULL
);

-- The counters of the names of users with a limit at that poll: by name,
-- not by user (users.id is reused; a process keeps a deleted user's
-- counter until it restarts).
CREATE TABLE traffic_marks (
    source TEXT NOT NULL REFERENCES traffic_sources(source) ON DELETE CASCADE,
    name   TEXT NOT NULL,
    up     INTEGER NOT NULL,
    down   INTEGER NOT NULL,
    PRIMARY KEY (source, name)
) WITHOUT ROWID;

-- A limit recorded before this version ("recorded, not enforced") holds
-- from now, counted from zero (owner's decision 2).
UPDATE users SET traffic_limit_bytes = NULL WHERE traffic_limit_bytes <= 0;
INSERT INTO user_traffic (user_id, period_start, counted_from)
  SELECT id, CAST(strftime('%s', 'now') AS INTEGER), CAST(strftime('%s', 'now') AS INTEGER)
  FROM users WHERE traffic_limit_bytes IS NOT NULL;
