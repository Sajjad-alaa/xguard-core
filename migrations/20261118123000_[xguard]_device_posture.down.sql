DROP TABLE device_posture_snapshot;
DROP INDEX device_posture_location_location_id_idx;

ALTER TABLE device_posture
    DROP CONSTRAINT device_posture_name_length,
    DROP CONSTRAINT device_posture_description_length;

ALTER TABLE device_posture_os_rule
    DROP CONSTRAINT device_posture_os_rule_min_os_version_format,
    DROP CONSTRAINT device_posture_os_rule_min_kernel_version_format,
    DROP CONSTRAINT device_posture_os_rule_max_age_range,
    DROP COLUMN firewall_required,
    DROP COLUMN screen_lock_required,
    ALTER COLUMN min_os_version TYPE integer USING (
        CASE
            WHEN min_os_version IS NULL THEN NULL
            WHEN os_type = 'windows' AND min_os_version LIKE '10.0.%'
                AND split_part(min_os_version, '.', 3)::integer >= 22000 THEN 11
            WHEN os_type = 'windows' AND min_os_version LIKE '10.0.%' THEN 10
            ELSE split_part(min_os_version, '.', 1)::integer
        END
    ),
    ALTER COLUMN min_kernel_version TYPE integer
        USING split_part(min_kernel_version, '.', 1)::integer;
