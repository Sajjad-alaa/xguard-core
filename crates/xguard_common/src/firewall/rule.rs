//! Firewall rules: storage, validation of admin input, and loading for the compiler.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection, PgExecutor, Postgres, Transaction, Type};

use super::address::{parse_destination, parse_ports};
use crate::db::Id;

/// Upper bounds on one rule, so a single request cannot produce an unbounded policy.
pub const MAX_DESTINATIONS: usize = 1000;
pub const MAX_PORTS: usize = 256;
pub const MAX_MEMBERS: usize = 10_000;

const TCP: i16 = 6;
const UDP: i16 = 17;
const SCTP: i16 = 132;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "firewall_action", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum FirewallRuleAction {
    Allow,
    Deny,
    Reject,
}

fn yes() -> bool {
    true
}

fn default_priority() -> i32 {
    1000
}

/// A rule as an admin submits it.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FirewallRuleInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Lower runs first; ties are broken by rule ID.
    #[serde(default = "default_priority")]
    pub priority: i32,
    pub action: FirewallRuleAction,
    #[serde(default)]
    pub all_locations: bool,
    #[serde(default)]
    pub locations: Vec<Id>,
    /// Match traffic from any VPN address, ignoring the selections below.
    #[serde(default)]
    pub any_source: bool,
    #[serde(default)]
    pub all_users: bool,
    #[serde(default)]
    pub all_network_devices: bool,
    #[serde(default)]
    pub users: Vec<Id>,
    #[serde(default)]
    pub groups: Vec<Id>,
    #[serde(default)]
    pub devices: Vec<Id>,
    /// Match any destination, ignoring `destinations`.
    #[serde(default)]
    pub any_destination: bool,
    /// IP addresses, CIDR networks or `start-end` ranges.
    #[serde(default)]
    pub destinations: Vec<String>,
    /// IANA protocol numbers (6 TCP, 17 UDP, 1 ICMP, ...); empty means any.
    #[serde(default)]
    pub protocols: Vec<i16>,
    /// Destination ports, `443` or `8000-8080`; empty means any. Need TCP, UDP or SCTP.
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<NaiveDateTime>,
}

/// A stored rule with its selections.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FirewallRule {
    pub id: Id,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: i32,
    pub action: FirewallRuleAction,
    pub all_locations: bool,
    pub locations: Vec<Id>,
    pub any_source: bool,
    pub all_users: bool,
    pub all_network_devices: bool,
    pub users: Vec<Id>,
    pub groups: Vec<Id>,
    pub devices: Vec<Id>,
    pub any_destination: bool,
    pub destinations: Vec<String>,
    pub protocols: Vec<i16>,
    pub ports: Vec<String>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, thiserror::Error)]
pub enum FirewallRuleError {
    #[error("{0}")]
    Invalid(String),
    #[error("firewall rule not found")]
    NotFound,
    #[error("a selected location, user, group or device does not exist")]
    UnknownReference,
    #[error(transparent)]
    Database(sqlx::Error),
}

impl From<sqlx::Error> for FirewallRuleError {
    fn from(err: sqlx::Error) -> Self {
        // Foreign-key violation: a referenced row is missing (or was deleted meanwhile).
        if let sqlx::Error::Database(db) = &err
            && db.code().as_deref() == Some("23503")
        {
            return Self::UnknownReference;
        }
        Self::Database(err)
    }
}

fn invalid(message: impl Into<String>) -> FirewallRuleError {
    FirewallRuleError::Invalid(message.into())
}

fn sorted_unique<T: Ord>(mut values: Vec<T>) -> Vec<T> {
    values.sort_unstable();
    values.dedup();
    values
}

impl FirewallRuleInput {
    /// Checks the input and puts it in canonical form (trimmed name, canonical addresses and
    /// ports, sorted unique lists).
    pub fn validate(mut self) -> Result<Self, FirewallRuleError> {
        self.name = self.name.trim().to_string();
        if self.name.is_empty() || self.name.chars().count() > 255 {
            return Err(invalid("Name must be between 1 and 255 characters."));
        }
        if self.description.chars().count() > 4096 {
            return Err(invalid("Description must be at most 4096 characters."));
        }
        if self.destinations.len() > MAX_DESTINATIONS {
            return Err(invalid(format!(
                "At most {MAX_DESTINATIONS} destinations per rule."
            )));
        }
        if self.ports.len() > MAX_PORTS {
            return Err(invalid(format!(
                "At most {MAX_PORTS} port entries per rule."
            )));
        }
        for members in [&self.locations, &self.users, &self.groups, &self.devices] {
            if members.len() > MAX_MEMBERS {
                return Err(invalid(format!(
                    "At most {MAX_MEMBERS} selections per list."
                )));
            }
        }

        if !self.all_locations && self.locations.is_empty() {
            return Err(invalid(
                "Choose the locations this rule applies to, or all locations.",
            ));
        }
        let selects_sources = self.all_users
            || self.all_network_devices
            || !self.users.is_empty()
            || !self.groups.is_empty()
            || !self.devices.is_empty();
        if !self.any_source && !selects_sources {
            return Err(invalid("Choose who this rule applies to, or any source."));
        }

        let mut destinations = Vec::with_capacity(self.destinations.len());
        for destination in &self.destinations {
            let (canonical, _) =
                parse_destination(destination).map_err(|err| invalid(err.to_string()))?;
            destinations.push(canonical);
        }
        self.destinations = sorted_unique(destinations);
        if !self.any_destination && self.destinations.is_empty() {
            return Err(invalid(
                "Add at least one destination, or allow any destination.",
            ));
        }

        if let Some(bad) = self.protocols.iter().find(|p| !(0..=255).contains(*p)) {
            return Err(invalid(format!("{bad} is not a protocol number (0-255).")));
        }
        self.protocols = sorted_unique(std::mem::take(&mut self.protocols));

        let mut ports = Vec::with_capacity(self.ports.len());
        for entry in &self.ports {
            let (canonical, _) = parse_ports(entry).map_err(|err| invalid(err.to_string()))?;
            ports.push(canonical);
        }
        self.ports = sorted_unique(ports);
        if !self.ports.is_empty()
            && let Some(other) = self
                .protocols
                .iter()
                .find(|p| ![TCP, UDP, SCTP].contains(p))
        {
            return Err(invalid(format!(
                "Ports only apply to TCP, UDP and SCTP, not protocol {other}."
            )));
        }

        self.locations = sorted_unique(std::mem::take(&mut self.locations));
        self.users = sorted_unique(std::mem::take(&mut self.users));
        self.groups = sorted_unique(std::mem::take(&mut self.groups));
        self.devices = sorted_unique(std::mem::take(&mut self.devices));
        Ok(self)
    }
}

#[derive(FromRow)]
struct RuleRow {
    id: Id,
    name: String,
    description: String,
    enabled: bool,
    priority: i32,
    action: FirewallRuleAction,
    all_locations: bool,
    any_source: bool,
    all_users: bool,
    all_network_devices: bool,
    any_destination: bool,
    destinations: Vec<String>,
    protocols: Vec<i16>,
    ports: Vec<String>,
    expires_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
    locations: Vec<Id>,
    users: Vec<Id>,
    groups: Vec<Id>,
    devices: Vec<Id>,
}

impl From<RuleRow> for FirewallRule {
    fn from(row: RuleRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            description: row.description,
            enabled: row.enabled,
            priority: row.priority,
            action: row.action,
            all_locations: row.all_locations,
            locations: row.locations,
            any_source: row.any_source,
            all_users: row.all_users,
            all_network_devices: row.all_network_devices,
            users: row.users,
            groups: row.groups,
            devices: row.devices,
            any_destination: row.any_destination,
            destinations: row.destinations,
            protocols: row.protocols,
            ports: row.ports,
            expires_at: row.expires_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// The rule columns plus its selections; a macro so queries can extend it with `concat!` and
/// stay static strings.
macro_rules! select_rules {
    () => {
        "SELECT r.id, r.name, r.description, r.enabled, r.priority, r.action, \
    r.all_locations, r.any_source, r.all_users, r.all_network_devices, r.any_destination, \
    r.destinations, r.protocols, r.ports, r.expires_at, r.created_at, r.updated_at, \
    ARRAY(SELECT location_id FROM firewall_rule_location WHERE rule_id = r.id ORDER BY 1) locations, \
    ARRAY(SELECT user_id FROM firewall_rule_user WHERE rule_id = r.id ORDER BY 1) users, \
    ARRAY(SELECT group_id FROM firewall_rule_group WHERE rule_id = r.id ORDER BY 1) groups, \
    ARRAY(SELECT device_id FROM firewall_rule_device WHERE rule_id = r.id ORDER BY 1) devices \
    FROM firewall_rule r"
    };
}

impl FirewallRule {
    /// All rules in evaluation order.
    pub async fn all<'e, E: PgExecutor<'e>>(executor: E) -> Result<Vec<Self>, sqlx::Error> {
        let rows: Vec<RuleRow> =
            sqlx::query_as(concat!(select_rules!(), " ORDER BY r.priority, r.id"))
                .fetch_all(executor)
                .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn find_by_id<'e, E: PgExecutor<'e>>(
        executor: E,
        id: Id,
    ) -> Result<Option<Self>, sqlx::Error> {
        let row: Option<RuleRow> = sqlx::query_as(concat!(select_rules!(), " WHERE r.id = $1"))
            .bind(id)
            .fetch_optional(executor)
            .await?;
        Ok(row.map(Into::into))
    }

    /// Stores a new rule. `input` must come from [`FirewallRuleInput::validate`].
    pub async fn create(
        transaction: &mut Transaction<'_, Postgres>,
        input: &FirewallRuleInput,
    ) -> Result<Id, FirewallRuleError> {
        let id: Id = sqlx::query_scalar(
            "INSERT INTO firewall_rule (name, description, enabled, priority, action, \
            all_locations, any_source, all_users, all_network_devices, any_destination, \
            destinations, protocols, ports, expires_at) \
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id",
        )
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.enabled)
        .bind(input.priority)
        .bind(input.action)
        .bind(input.all_locations)
        .bind(input.any_source)
        .bind(input.all_users)
        .bind(input.all_network_devices)
        .bind(input.any_destination)
        .bind(&input.destinations)
        .bind(&input.protocols)
        .bind(&input.ports)
        .bind(input.expires_at)
        .fetch_one(&mut **transaction)
        .await?;
        insert_members(transaction, id, input).await?;
        Ok(id)
    }

    /// Replaces rule `id` with `input`, which must come from [`FirewallRuleInput::validate`].
    pub async fn update(
        transaction: &mut Transaction<'_, Postgres>,
        id: Id,
        input: &FirewallRuleInput,
    ) -> Result<(), FirewallRuleError> {
        let updated = sqlx::query(
            "UPDATE firewall_rule SET name = $2, description = $3, enabled = $4, priority = $5, \
            action = $6, all_locations = $7, any_source = $8, all_users = $9, \
            all_network_devices = $10, any_destination = $11, destinations = $12, \
            protocols = $13, ports = $14, expires_at = $15, updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.enabled)
        .bind(input.priority)
        .bind(input.action)
        .bind(input.all_locations)
        .bind(input.any_source)
        .bind(input.all_users)
        .bind(input.all_network_devices)
        .bind(input.any_destination)
        .bind(&input.destinations)
        .bind(&input.protocols)
        .bind(&input.ports)
        .bind(input.expires_at)
        .execute(&mut **transaction)
        .await?;
        if updated.rows_affected() == 0 {
            return Err(FirewallRuleError::NotFound);
        }
        for statement in [
            "DELETE FROM firewall_rule_location WHERE rule_id = $1",
            "DELETE FROM firewall_rule_user WHERE rule_id = $1",
            "DELETE FROM firewall_rule_group WHERE rule_id = $1",
            "DELETE FROM firewall_rule_device WHERE rule_id = $1",
        ] {
            sqlx::query(statement)
                .bind(id)
                .execute(&mut **transaction)
                .await?;
        }
        insert_members(transaction, id, input).await
    }

    pub async fn delete<'e, E: PgExecutor<'e>>(
        executor: E,
        id: Id,
    ) -> Result<(), FirewallRuleError> {
        let deleted = sqlx::query("DELETE FROM firewall_rule WHERE id = $1")
            .bind(id)
            .execute(executor)
            .await?;
        if deleted.rows_affected() == 0 {
            return Err(FirewallRuleError::NotFound);
        }
        Ok(())
    }

    /// Enabled, unexpired rules that apply to `location_id`, in evaluation order.
    pub async fn active_for_location(
        conn: &mut PgConnection,
        location_id: Id,
        now: NaiveDateTime,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let rows: Vec<RuleRow> = sqlx::query_as(concat!(
            select_rules!(),
            " WHERE r.enabled AND (r.expires_at IS NULL OR r.expires_at > $2) \
            AND (r.all_locations OR EXISTS (SELECT 1 FROM firewall_rule_location l \
            WHERE l.rule_id = r.id AND l.location_id = $1)) ORDER BY r.priority, r.id"
        ))
        .bind(location_id)
        .bind(now)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

async fn insert_members(
    transaction: &mut Transaction<'_, Postgres>,
    id: Id,
    input: &FirewallRuleInput,
) -> Result<(), FirewallRuleError> {
    let lists = [
        (
            "INSERT INTO firewall_rule_location (rule_id, location_id) \
            SELECT $1, unnest($2::bigint[])",
            &input.locations,
        ),
        (
            "INSERT INTO firewall_rule_user (rule_id, user_id) SELECT $1, unnest($2::bigint[])",
            &input.users,
        ),
        (
            "INSERT INTO firewall_rule_group (rule_id, group_id) SELECT $1, unnest($2::bigint[])",
            &input.groups,
        ),
        (
            "INSERT INTO firewall_rule_device (rule_id, device_id) \
            SELECT $1, unnest($2::bigint[])",
            &input.devices,
        ),
    ];
    for (statement, members) in lists {
        if members.is_empty() {
            continue;
        }
        sqlx::query(statement)
            .bind(id)
            .bind(members)
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}
