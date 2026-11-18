-- XGuard device posture policies.
--
-- Versions become dotted numeric strings ("14.5", "10.0.22631", "6.8") so policies can
-- require a minor release or a Windows build, not only a major number. Existing Windows
-- values were product names (10, 11) and map to their first build.
ALTER TABLE device_posture_os_rule
    ALTER COLUMN min_os_version TYPE text USING (
        CASE
            WHEN min_os_version IS NULL THEN NULL
            WHEN os_type = 'windows' AND min_os_version >= 11 THEN '10.0.22000'
            WHEN os_type = 'windows' THEN '10.0.10240'
            ELSE min_os_version::text
        END
    ),
    ALTER COLUMN min_kernel_version TYPE text USING min_kernel_version::text,
    ADD COLUMN firewall_required boolean,
    ADD COLUMN screen_lock_required boolean,
    ADD CONSTRAINT device_posture_os_rule_min_os_version_format
        CHECK (min_os_version ~ '^[0-9]{1,5}(\.[0-9]{1,5}){0,3}$'),
    ADD CONSTRAINT device_posture_os_rule_min_kernel_version_format
        CHECK (min_kernel_version ~ '^[0-9]{1,5}(\.[0-9]{1,5}){0,3}$'),
    ADD CONSTRAINT device_posture_os_rule_max_age_range
        CHECK (windows_security_update_max_age BETWEEN 1 AND 3650
            AND android_security_patch_level_max_age BETWEEN 1 AND 3650);

UPDATE device_posture SET name = left(btrim(name), 64) WHERE char_length(btrim(name)) > 64;
UPDATE device_posture SET name = 'Posture policy ' || id WHERE btrim(name) = '';
UPDATE device_posture SET description = left(description, 512) WHERE char_length(description) > 512;

ALTER TABLE device_posture
    ADD CONSTRAINT device_posture_name_length CHECK (char_length(name) BETWEEN 1 AND 64),
    ADD CONSTRAINT device_posture_description_length CHECK (char_length(description) <= 512);

CREATE INDEX device_posture_location_location_id_idx ON device_posture_location (location_id);

-- The last posture facts a device reported, for admins. One row per device, replaced on
-- every report; the facts are validated and size-limited before they are stored.
CREATE TABLE device_posture_snapshot (
    device_id     bigint PRIMARY KEY REFERENCES device(id) ON DELETE CASCADE,
    facts         jsonb NOT NULL CHECK (octet_length(facts::text) <= 4096),
    reported_at   timestamp without time zone NOT NULL,
    location_id   bigint REFERENCES wireguard_network(id) ON DELETE SET NULL,
    compliant     boolean NOT NULL,
    failed_checks text[] NOT NULL DEFAULT '{}'
);
