-- R4: credentials rotate with an overlap (docs/08-decisions.md, R4-1). The
-- current secret, the next one with the moment clients switch to it, and
-- the previous one, still accepted for a grace period after the switch.
ALTER TABLE credentials ADD COLUMN rotated_at INTEGER;
ALTER TABLE credentials ADD COLUMN next_secret TEXT;
ALTER TABLE credentials ADD COLUMN next_from INTEGER;
ALTER TABLE credentials ADD COLUMN prev_secret TEXT;
ALTER TABLE credentials ADD COLUMN prev_until INTEGER;
UPDATE credentials SET rotated_at = created_at;
