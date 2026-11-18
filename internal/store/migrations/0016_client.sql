-- client-min-v1 §5: the last X-Raycontrol-Client of the device's
-- subscription requests, product and version only ("niko/1.59.0"; NULL:
-- none yet), and when the node last saw it (unix seconds). Written after
-- the request's Authorization is checked, not logged.
ALTER TABLE devices ADD COLUMN client TEXT;
ALTER TABLE devices ADD COLUMN client_at INTEGER;
