-- lan-v1 §1.1, §3: a user's devices see each other over Yggdrasil (LAN),
-- off by default. It takes both consents: the administrator's, per user
-- (rayctl user lan NAME on|off), and each device's own, the
-- X-Raycontrol-LAN header of its last subscription request.
ALTER TABLE users ADD COLUMN lan INTEGER NOT NULL DEFAULT 0;
-- The key of the user's multicast password (lan-v1 §3): 32 random bytes,
-- new at every user lan on and at every revocation of one of the user's
-- devices; NULL while LAN is off.
ALTER TABLE users ADD COLUMN lan_key BLOB;

-- The device's consent as its header last said (1: it shows itself), and
-- when that last changed (unix seconds; NULL: never): a device shows
-- itself again at most once a minute (lan-v1 §4.4).
ALTER TABLE devices ADD COLUMN lan INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN lan_at INTEGER;
