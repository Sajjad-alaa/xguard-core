-- Where users download the XGuard clients from (Settings -> Client downloads).
-- A missing row means the built-in defaults (the XGuard GitHub releases).
CREATE TABLE client_download_settings (
    id smallint PRIMARY KEY CHECK (id = 1),
    base_url text NOT NULL CHECK (length(base_url) BETWEEN 1 AND 2048),
    releases_url text NOT NULL CHECK (length(releases_url) BETWEEN 1 AND 2048),
    android_url text CHECK (android_url IS NULL OR length(android_url) BETWEEN 1 AND 2048),
    ios_url text CHECK (ios_url IS NULL OR length(ios_url) BETWEEN 1 AND 2048),
    macos_installer boolean NOT NULL DEFAULT false,
    allow_http boolean NOT NULL DEFAULT false
);
