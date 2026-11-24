-- High-impact B-tree indexes for hot authentication, WireGuard polling,
-- authorization, ACL firewall, and session expiry paths.

CREATE INDEX IF NOT EXISTS idx_device_wireguard_pubkey
    ON device (wireguard_pubkey);

CREATE INDEX IF NOT EXISTS idx_pollingtoken_token
    ON pollingtoken (token);

CREATE INDEX IF NOT EXISTS idx_pollingtoken_device_id
    ON pollingtoken (device_id);

CREATE INDEX IF NOT EXISTS idx_group_user_user_id
    ON group_user (user_id);

CREATE INDEX IF NOT EXISTS idx_session_user_id
    ON session (user_id);

CREATE INDEX IF NOT EXISTS idx_session_expires
    ON session (expires);

CREATE INDEX IF NOT EXISTS idx_webauthn_user_id
    ON webauthn (user_id);

CREATE INDEX IF NOT EXISTS idx_biometric_auth_pub_key
    ON biometric_auth (pub_key);

CREATE INDEX IF NOT EXISTS idx_gateway_location_id
    ON gateway (location_id);

CREATE INDEX IF NOT EXISTS idx_device_posture_location_location_id
    ON device_posture_location (location_id);

CREATE INDEX IF NOT EXISTS idx_token_user_id
    ON token (user_id);

CREATE INDEX IF NOT EXISTS idx_token_device_id
    ON token (device_id);

CREATE INDEX IF NOT EXISTS idx_firewall_rule_user_user_id
    ON firewall_rule_user (user_id);

CREATE INDEX IF NOT EXISTS idx_firewall_rule_group_group_id
    ON firewall_rule_group (group_id);

CREATE INDEX IF NOT EXISTS idx_firewall_rule_device_device_id
    ON firewall_rule_device (device_id);

CREATE INDEX IF NOT EXISTS idx_api_token_user_id
    ON api_token (user_id);

CREATE INDEX IF NOT EXISTS idx_device_login_event_user_id
    ON device_login_event (user_id);
