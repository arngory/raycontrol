-- api-v1 §3: an invite may need a PIN told by another channel. The node
-- keeps the proof it expects, not the PIN, and the wrong PINs still
-- allowed; the last one withdraws the invite (the row goes, as a revoked
-- invite's does).
ALTER TABLE invites ADD COLUMN pin_proof BLOB;
ALTER TABLE invites ADD COLUMN pin_tries INTEGER NOT NULL DEFAULT 0;
