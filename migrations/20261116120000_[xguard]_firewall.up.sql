-- XGuard firewall rules (replaces the removed Defguard enterprise ACL; the old acl* tables are
-- left untouched).
CREATE TYPE firewall_action AS ENUM ('allow', 'deny', 'reject');

CREATE TABLE firewall_rule (
    id bigserial PRIMARY KEY,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    description text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT true,
    -- Evaluation order within a location: lower first, ties broken by id. First match wins.
    priority integer NOT NULL DEFAULT 1000,
    action firewall_action NOT NULL,
    all_locations boolean NOT NULL DEFAULT false,
    -- Sources: either any VPN address, or the union of the selections below.
    any_source boolean NOT NULL DEFAULT false,
    all_users boolean NOT NULL DEFAULT false,
    all_network_devices boolean NOT NULL DEFAULT false,
    -- Destinations: either anywhere, or these addresses (IP, CIDR or "start-end", canonical).
    any_destination boolean NOT NULL DEFAULT false,
    destinations text[] NOT NULL DEFAULT '{}',
    -- IANA protocol numbers; empty means any.
    protocols smallint[] NOT NULL DEFAULT '{}',
    -- Destination ports as "80" or "8000-8080"; empty means any.
    ports text[] NOT NULL DEFAULT '{}',
    expires_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone NOT NULL DEFAULT now()
);
CREATE INDEX firewall_rule_order_idx ON firewall_rule (priority, id) WHERE enabled;

CREATE TABLE firewall_rule_location (
    rule_id bigint NOT NULL REFERENCES firewall_rule(id) ON DELETE CASCADE,
    location_id bigint NOT NULL REFERENCES wireguard_network(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, location_id)
);
CREATE INDEX firewall_rule_location_location_idx ON firewall_rule_location (location_id);

CREATE TABLE firewall_rule_user (
    rule_id bigint NOT NULL REFERENCES firewall_rule(id) ON DELETE CASCADE,
    user_id bigint NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, user_id)
);

CREATE TABLE firewall_rule_group (
    rule_id bigint NOT NULL REFERENCES firewall_rule(id) ON DELETE CASCADE,
    group_id bigint NOT NULL REFERENCES "group"(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, group_id)
);

CREATE TABLE firewall_rule_device (
    rule_id bigint NOT NULL REFERENCES firewall_rule(id) ON DELETE CASCADE,
    device_id bigint NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, device_id)
);
