-- relay-v1 §3.1: the addresses that reach the relay host's SSH without SPA,
-- its own list, never the exit's (JSON array of prefixes; NULL: none).
ALTER TABLE relays ADD COLUMN admin_json TEXT;
