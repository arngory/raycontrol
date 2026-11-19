-- integrations-v1 §3.2: an integration's device in the mode of addresses
-- calls from these prefixes without a knock ("198.51.100.7/32,2001:db8::/64",
-- canonical, sorted; NULL: it knocks). An invite's go to the device it
-- becomes. last_call: the device's last call through the remote API, unix
-- seconds, written at most once an hour (§3.4: a list with no calls for 30
-- days is pointed out).
ALTER TABLE devices ADD COLUMN allow TEXT;
ALTER TABLE devices ADD COLUMN last_call INTEGER;
ALTER TABLE invites ADD COLUMN allow TEXT;
-- Every remote call reads the lists (AllowLists): only the rows that have one.
CREATE INDEX devices_allow ON devices (id) WHERE allow IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX invites_allow ON invites (id) WHERE allow IS NOT NULL AND used_at IS NULL;
