-- relay-v1 (R6-a): relays in front of this node. A relay is one address
-- that reaches the service ports without SPA; devices knock at the relay.
CREATE TABLE relays (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    address    TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);
