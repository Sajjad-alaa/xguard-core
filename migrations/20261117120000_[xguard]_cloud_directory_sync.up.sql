-- XGuard cloud directory sync: remember which accounts the sync disabled, so it re-enables
-- only those when the directory activates them again (never accounts an admin disabled).
ALTER TABLE user_directory_identity
    ADD COLUMN sync_disabled boolean NOT NULL DEFAULT false;
