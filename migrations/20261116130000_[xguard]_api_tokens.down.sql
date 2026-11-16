DROP INDEX api_token_user_id_idx;

ALTER TABLE api_token
    DROP CONSTRAINT api_token_name_length,
    DROP COLUMN read_only,
    DROP COLUMN last_used_ip,
    DROP COLUMN last_used_at,
    DROP COLUMN expires_at,
    DROP COLUMN hint;
