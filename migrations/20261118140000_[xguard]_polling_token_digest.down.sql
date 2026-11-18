-- Digests cannot be turned back into tokens; clients re-enroll after a downgrade.
DROP INDEX IF EXISTS pollingtoken_device_id_idx;
DROP INDEX IF EXISTS pollingtoken_token_key;
