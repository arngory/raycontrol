-- relay-v1 §9.1 (R6-c): the relay's probe-v1 endpoint, made with its bundle:
-- its port (TCP and UDP on one number) and the pin of its certificate.
-- NULL: a bundle from before v0.11, which has no probe endpoint.
ALTER TABLE relays ADD COLUMN probe_port INTEGER;
ALTER TABLE relays ADD COLUMN probe_pin TEXT;
