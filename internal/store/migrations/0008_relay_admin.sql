-- relay-v1 §3.1: the addresses that reach the relay host's SSH without SPA,
-- its own list, never the exit's (JSON array of prefixes; NULL: none).
-- No release has had 0006 to 0008 before v0.10.1; a test database a branch
-- build made with this column in 0007 is made anew, not migrated.
ALTER TABLE relays ADD COLUMN admin_json TEXT;
