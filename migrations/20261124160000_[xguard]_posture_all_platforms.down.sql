-- Older versions evaluate every stored column on every platform but cannot edit the new
-- per-platform checks, so they are cleared to keep the old behaviour.
UPDATE device_posture_os_rule SET security_update_max_age = NULL WHERE os_type <> 'windows';
UPDATE device_posture_os_rule
    SET antivirus_required = NULL, ad_domain_joined_required = NULL
    WHERE os_type IN ('macos', 'linux');
UPDATE device_posture_os_rule
    SET disk_encryption_required = NULL, screen_lock_required = NULL
    WHERE os_type IN ('ios', 'android');

ALTER TABLE device_posture_os_rule
    RENAME COLUMN security_update_max_age TO windows_security_update_max_age;
