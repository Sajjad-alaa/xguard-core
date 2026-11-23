-- RADIUS MFA settings and server-side Access-Challenge state.
-- Dedicated tables keep existing SQLx offline queries on "user" and settings untouched.

ALTER TYPE mfa_method ADD VALUE IF NOT EXISTS 'radius';
ALTER TYPE vpn_client_mfa_method ADD VALUE IF NOT EXISTS 'radius';

CREATE TABLE IF NOT EXISTS radius_settings (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    web_login_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    vpn_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    primary_host TEXT NOT NULL DEFAULT '',
    primary_port INTEGER NOT NULL DEFAULT 1812 CHECK (primary_port BETWEEN 1 AND 65535),
    primary_secret TEXT NOT NULL DEFAULT '',
    secondary_host TEXT,
    secondary_port INTEGER NOT NULL DEFAULT 1812 CHECK (secondary_port BETWEEN 1 AND 65535),
    secondary_secret TEXT,
    timeout_secs INTEGER NOT NULL DEFAULT 3 CHECK (timeout_secs BETWEEN 1 AND 30),
    retries SMALLINT NOT NULL DEFAULT 3 CHECK (retries BETWEEN 1 AND 10),
    nas_identifier TEXT NOT NULL DEFAULT 'xguard',
    nas_ip_address TEXT,
    username_format TEXT NOT NULL DEFAULT 'username' CHECK (username_format IN ('username', 'email')),
    push_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    push_poll_interval_secs INTEGER NOT NULL DEFAULT 2 CHECK (push_poll_interval_secs BETWEEN 1 AND 15),
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO radius_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS web_radius_challenge (
    session_id TEXT PRIMARY KEY REFERENCES session(id) ON DELETE CASCADE,
    state BYTEA NOT NULL,
    reply_message TEXT,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_web_radius_challenge_expires_at
    ON web_radius_challenge (expires_at);

CREATE TABLE IF NOT EXISTS vpn_mfa_radius_challenge (
    session_id BIGINT PRIMARY KEY REFERENCES vpn_client_mfa_session(id) ON DELETE CASCADE,
    step_attempt_id TEXT NOT NULL,
    state BYTEA NOT NULL,
    reply_message TEXT,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
