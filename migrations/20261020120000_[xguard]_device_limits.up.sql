CREATE TABLE device_limit_settings (
    id smallint PRIMARY KEY CHECK (id = 1),
    max_devices_per_user integer NOT NULL DEFAULT 0 CHECK (max_devices_per_user >= 0),
    max_connections_per_user integer NOT NULL DEFAULT 0 CHECK (max_connections_per_user >= 0)
);

INSERT INTO device_limit_settings (id, max_devices_per_user, max_connections_per_user)
VALUES (1, 0, 0)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE group_device_limit (
    group_id bigint PRIMARY KEY REFERENCES "group"(id) ON DELETE CASCADE,
    max_devices integer CHECK (max_devices IS NULL OR max_devices >= 0),
    max_connections integer CHECK (max_connections IS NULL OR max_connections >= 0)
);

CREATE TABLE user_device_limit (
    user_id bigint PRIMARY KEY REFERENCES "user"(id) ON DELETE CASCADE,
    max_devices integer CHECK (max_devices IS NULL OR max_devices >= 0),
    max_connections integer CHECK (max_connections IS NULL OR max_connections >= 0)
);
