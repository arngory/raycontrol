-- relay-v1 §4.1 (v0.36.0): the users a relay is for, a JSON list of user
-- IDs, sorted; NULL: every user. Their profiles go through it, the relay is
-- in their subscription and knows their devices; no one else's.
ALTER TABLE relays ADD COLUMN users_json TEXT;
