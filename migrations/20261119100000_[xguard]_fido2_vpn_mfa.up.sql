-- XGuard FIDO2 VPN MFA: which WebAuthn credentials may answer a VPN MFA step.
-- Kept in its own table so the `webauthn` row shape (and the queries over it) stays unchanged.
CREATE TABLE webauthn_vpn_mfa (
    webauthn_id bigint PRIMARY KEY REFERENCES webauthn(id) ON DELETE CASCADE,
    enabled_at timestamp without time zone NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'),
    last_used_at timestamp without time zone NULL
);

-- Security keys registered through the desktop client were registered for VPN MFA.
INSERT INTO webauthn_vpn_mfa (webauthn_id)
    SELECT id FROM webauthn WHERE registration_source = 'desktop';
