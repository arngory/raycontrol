-- egress-policy-v1 §1, §9: the node's egress policy moves from Xray's
-- routing into the kernel. A node with Xray services (inner, reality)
-- blocked BitTorrent there until now, and keeps it blocked, now on every
-- profile; any other node, and a new one, starts with nothing blocked.
INSERT INTO settings (key, value)
  SELECT 'egress_bittorrent', CAST('on' AS BLOB)
  WHERE EXISTS (SELECT 1 FROM services WHERE kind IN ('inner', 'reality'))
  ON CONFLICT(key) DO NOTHING;
