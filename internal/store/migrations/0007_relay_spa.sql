-- relay-v1 §3 (R6-a): a relay's own SPA parameters, made by the exit when
-- the relay is added or first asked for (JSON of node.SPAParams), and the
-- port of the relay host's SSH, which the admin addresses reach there.
ALTER TABLE relays ADD COLUMN spa_json TEXT;
ALTER TABLE relays ADD COLUMN ssh_port INTEGER NOT NULL DEFAULT 22;
-- The pin of the client certificate the exit made for the relay: with it
-- the relay takes its perimeter from the exit's API (RelayService).
ALTER TABLE relays ADD COLUMN cert_pin TEXT;
CREATE UNIQUE INDEX relays_cert_pin ON relays (cert_pin) WHERE cert_pin IS NOT NULL;
-- The addresses that reach the relay host's SSH without SPA: its own list,
-- not the exit's (JSON array of prefixes; NULL: none).
ALTER TABLE relays ADD COLUMN admin_json TEXT;
