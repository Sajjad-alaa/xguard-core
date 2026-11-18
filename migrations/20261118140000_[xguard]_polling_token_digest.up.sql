-- XGuard config sync: store polling tokens as SHA-256 digests (hex) instead of plaintext.
-- Existing tokens keep working: clients present the same secret, Core hashes it before lookup.
UPDATE pollingtoken SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex')
    WHERE token !~ '^[0-9a-f]{64}$';
CREATE UNIQUE INDEX IF NOT EXISTS pollingtoken_token_key ON pollingtoken (token);
CREATE INDEX IF NOT EXISTS pollingtoken_device_id_idx ON pollingtoken (device_id);
