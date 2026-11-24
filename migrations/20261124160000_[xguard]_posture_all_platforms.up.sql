-- XGuard device posture on every platform.
--
-- The security update age is no longer Windows only: macOS and Linux report it as well, so
-- the column gets a neutral name. The existing antivirus, directory, screen lock and disk
-- encryption columns are reused for the platforms that can now report them (macOS and Linux
-- antivirus and directory membership; iOS and Android screen lock and disk encryption).
ALTER TABLE device_posture_os_rule
    RENAME COLUMN windows_security_update_max_age TO security_update_max_age;
