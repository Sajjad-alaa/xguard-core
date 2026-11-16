-- XGuard API tokens (xgt_ prefix, SHA-256 stored). Tokens from the Defguard enterprise
-- feature used another format; they are revoked and must be created again.
DELETE FROM api_token;

ALTER TABLE api_token
    ADD COLUMN hint text NOT NULL,
    ADD COLUMN expires_at timestamp without time zone,
    ADD COLUMN last_used_at timestamp without time zone,
    ADD COLUMN last_used_ip inet,
    ADD COLUMN read_only boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT api_token_name_length CHECK (char_length(name) BETWEEN 1 AND 64);

CREATE INDEX api_token_user_id_idx ON api_token (user_id);
