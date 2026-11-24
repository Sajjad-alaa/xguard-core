//! XGuard device posture policies and the last posture snapshot of each device.
//!
//! - A policy ([`DevicePosture`]) is a named rule set: minimum client versions plus one
//!   [`DevicePostureOsRule`] per allowed operating system. An operating system without a rule is
//!   not allowed by the policy; a policy without any rule allows every operating system.
//! - Policies are attached to locations through `device_posture_location`. A device must pass
//!   every policy of a location to connect.
//! - [`PostureSnapshot`] keeps the last facts a device reported (one row per device), so admins
//!   can see them and policies can be re-evaluated when they change.
//!
//! All queries are static strings and load whole sets in one query per table (no N+1).

use std::collections::HashMap;

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection, PgExecutor, Type, query, query_as, query_scalar};

use crate::db::{Id, NoId};

/// Operating system family, stored as the `os_type` database enum.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Type,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "os_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    Windows,
    Macos,
    #[default]
    Linux,
    Ios,
    Android,
}

impl OsType {
    pub const ALL: [Self; 5] = [
        Self::Windows,
        Self::Macos,
        Self::Linux,
        Self::Ios,
        Self::Android,
    ];

    #[must_use]
    pub const fn is_mobile(self) -> bool {
        matches!(self, Self::Ios | Self::Android)
    }

    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::Macos => "macOS",
            Self::Linux => "Linux",
            Self::Ios => "iOS",
            Self::Android => "Android",
        }
    }
}

/// A posture policy.
#[derive(Clone, Debug, Deserialize, FromRow, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DevicePosture<I = NoId> {
    #[cfg_attr(feature = "openapi", schema(value_type = i64))]
    pub id: I,
    pub name: String,
    pub description: Option<String>,
    /// Minimum XGuard desktop client version (semver), if any.
    pub min_desktop_client_version: Option<String>,
    /// Minimum XGuard mobile client version (semver), if any.
    pub min_mobile_client_version: Option<String>,
    /// Whether pre-release client builds (e.g. `2.3.0-beta1`) are accepted.
    pub allow_prerelease_client: bool,
}

/// The requirements of a policy for one operating system. `None` and `Some(false)` both mean
/// "not required".
#[derive(Clone, Debug, Default, Deserialize, FromRow, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DevicePostureOsRule {
    pub posture_id: Id,
    pub os_type: OsType,
    /// Dotted numeric minimum OS version.
    pub min_os_version: Option<String>,
    /// Dotted numeric minimum kernel version (Linux).
    pub min_kernel_version: Option<String>,
    pub disk_encryption_required: Option<bool>,
    pub firewall_required: Option<bool>,
    pub screen_lock_required: Option<bool>,
    pub antivirus_required: Option<bool>,
    pub ad_domain_joined_required: Option<bool>,
    pub device_integrity_required: Option<bool>,
    /// Maximum age in days of the last OS security update (Windows, macOS, Linux).
    pub security_update_max_age: Option<i32>,
    /// Maximum age in days of the Android security patch level.
    pub android_security_patch_level_max_age: Option<i32>,
}

/// A policy together with its rules and the locations it is attached to.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DevicePostureWithRules {
    pub posture: DevicePosture<Id>,
    pub os_rules: Vec<DevicePostureOsRule>,
    pub locations: Vec<Id>,
}

/// Columns of `device_posture_os_rule`, shared by the select queries below.
macro_rules! os_rule_columns {
    () => {
        "posture_id, os_type, min_os_version, min_kernel_version, disk_encryption_required, \
         firewall_required, screen_lock_required, antivirus_required, \
         ad_domain_joined_required, device_integrity_required, \
         security_update_max_age, android_security_patch_level_max_age"
    };
}

impl DevicePosture<Id> {
    /// Every policy with its rules and locations, ordered by name: three queries in total.
    pub async fn list_with_rules(
        conn: &mut PgConnection,
    ) -> sqlx::Result<Vec<DevicePostureWithRules>> {
        let postures: Vec<DevicePosture<Id>> = query_as(
            "SELECT id, name, description, min_desktop_client_version, \
             min_mobile_client_version, allow_prerelease_client \
             FROM device_posture ORDER BY lower(name), id",
        )
        .fetch_all(&mut *conn)
        .await?;
        let ids: Vec<Id> = postures.iter().map(|p| p.id).collect();
        Self::attach(conn, postures, &ids).await
    }

    /// One policy with its rules and locations.
    pub async fn find_with_rules(
        conn: &mut PgConnection,
        id: Id,
    ) -> sqlx::Result<Option<DevicePostureWithRules>> {
        let Some(posture) = Self::find_by_id(&mut *conn, id).await? else {
            return Ok(None);
        };
        Ok(Self::attach(conn, vec![posture], &[id]).await?.pop())
    }

    pub async fn find_by_id<'e, E: PgExecutor<'e>>(
        executor: E,
        id: Id,
    ) -> sqlx::Result<Option<Self>> {
        query_as(
            "SELECT id, name, description, min_desktop_client_version, \
             min_mobile_client_version, allow_prerelease_client \
             FROM device_posture WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// The policies attached to a location, with their rules (two queries).
    pub async fn find_for_location(
        conn: &mut PgConnection,
        location_id: Id,
    ) -> sqlx::Result<Vec<DevicePostureWithRules>> {
        let postures: Vec<DevicePosture<Id>> = query_as(
            "SELECT p.id, p.name, p.description, p.min_desktop_client_version, \
             p.min_mobile_client_version, p.allow_prerelease_client \
             FROM device_posture p JOIN device_posture_location l ON l.posture_id = p.id \
             WHERE l.location_id = $1 ORDER BY p.id",
        )
        .bind(location_id)
        .fetch_all(&mut *conn)
        .await?;
        let ids: Vec<Id> = postures.iter().map(|p| p.id).collect();
        Self::attach(conn, postures, &ids).await
    }

    async fn attach(
        conn: &mut PgConnection,
        postures: Vec<DevicePosture<Id>>,
        ids: &[Id],
    ) -> sqlx::Result<Vec<DevicePostureWithRules>> {
        if postures.is_empty() {
            return Ok(Vec::new());
        }
        let rules: Vec<DevicePostureOsRule> = query_as(concat!(
            "SELECT ",
            os_rule_columns!(),
            " FROM device_posture_os_rule WHERE posture_id = ANY($1) ORDER BY posture_id, os_type"
        ))
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?;
        let links: Vec<(Id, Id)> = query_as(
            "SELECT posture_id, location_id FROM device_posture_location \
             WHERE posture_id = ANY($1) ORDER BY location_id",
        )
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?;

        let mut by_id: HashMap<Id, (Vec<DevicePostureOsRule>, Vec<Id>)> = HashMap::new();
        for rule in rules {
            by_id.entry(rule.posture_id).or_default().0.push(rule);
        }
        for (posture_id, location_id) in links {
            by_id.entry(posture_id).or_default().1.push(location_id);
        }
        Ok(postures
            .into_iter()
            .map(|posture| {
                let (os_rules, locations) = by_id.remove(&posture.id).unwrap_or_default();
                DevicePostureWithRules {
                    posture,
                    os_rules,
                    locations,
                }
            })
            .collect())
    }

    /// Replaces the rules of this policy.
    pub async fn replace_rules(
        &self,
        conn: &mut PgConnection,
        rules: &[DevicePostureOsRule],
    ) -> sqlx::Result<()> {
        query("DELETE FROM device_posture_os_rule WHERE posture_id = $1")
            .bind(self.id)
            .execute(&mut *conn)
            .await?;
        for rule in rules {
            query(
                "INSERT INTO device_posture_os_rule (posture_id, os_type, min_os_version, \
                 min_kernel_version, disk_encryption_required, firewall_required, \
                 screen_lock_required, antivirus_required, ad_domain_joined_required, \
                 device_integrity_required, security_update_max_age, \
                 android_security_patch_level_max_age) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            )
            .bind(self.id)
            .bind(rule.os_type)
            .bind(&rule.min_os_version)
            .bind(&rule.min_kernel_version)
            .bind(rule.disk_encryption_required)
            .bind(rule.firewall_required)
            .bind(rule.screen_lock_required)
            .bind(rule.antivirus_required)
            .bind(rule.ad_domain_joined_required)
            .bind(rule.device_integrity_required)
            .bind(rule.security_update_max_age)
            .bind(rule.android_security_patch_level_max_age)
            .execute(&mut *conn)
            .await?;
        }
        Ok(())
    }

    pub async fn update(&self, conn: &mut PgConnection) -> sqlx::Result<()> {
        query(
            "UPDATE device_posture SET name = $2, description = $3, \
             min_desktop_client_version = $4, min_mobile_client_version = $5, \
             allow_prerelease_client = $6 WHERE id = $1",
        )
        .bind(self.id)
        .bind(&self.name)
        .bind(&self.description)
        .bind(&self.min_desktop_client_version)
        .bind(&self.min_mobile_client_version)
        .bind(self.allow_prerelease_client)
        .execute(conn)
        .await?;
        Ok(())
    }

    /// Deletes the policy and returns the locations it was attached to.
    pub async fn delete(&self, conn: &mut PgConnection) -> sqlx::Result<Vec<Id>> {
        let locations = self.location_ids(&mut *conn).await?;
        query("DELETE FROM device_posture WHERE id = $1")
            .bind(self.id)
            .execute(conn)
            .await?;
        Ok(locations)
    }

    pub async fn location_ids<'e, E: PgExecutor<'e>>(&self, executor: E) -> sqlx::Result<Vec<Id>> {
        query_scalar(
            "SELECT location_id FROM device_posture_location WHERE posture_id = $1 \
             ORDER BY location_id",
        )
        .bind(self.id)
        .fetch_all(executor)
        .await
    }

    /// Sets the locations of this policy.
    pub async fn set_locations(
        &self,
        conn: &mut PgConnection,
        locations: &[Id],
    ) -> sqlx::Result<()> {
        query("DELETE FROM device_posture_location WHERE posture_id = $1")
            .bind(self.id)
            .execute(&mut *conn)
            .await?;
        query(
            "INSERT INTO device_posture_location (posture_id, location_id) \
             SELECT $1, unnest($2::bigint[]) ON CONFLICT DO NOTHING",
        )
        .bind(self.id)
        .bind(locations)
        .execute(conn)
        .await?;
        Ok(())
    }
}

impl DevicePosture<NoId> {
    pub async fn save(self, conn: &mut PgConnection) -> sqlx::Result<DevicePosture<Id>> {
        let id: Id = query_scalar(
            "INSERT INTO device_posture (name, description, min_desktop_client_version, \
             min_mobile_client_version, allow_prerelease_client) \
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(&self.name)
        .bind(&self.description)
        .bind(&self.min_desktop_client_version)
        .bind(&self.min_mobile_client_version)
        .bind(self.allow_prerelease_client)
        .fetch_one(conn)
        .await?;
        Ok(DevicePosture {
            id,
            name: self.name,
            description: self.description,
            min_desktop_client_version: self.min_desktop_client_version,
            min_mobile_client_version: self.min_mobile_client_version,
            allow_prerelease_client: self.allow_prerelease_client,
        })
    }
}

/// Posture assignments seen from a location.
pub struct LocationPostures;

impl LocationPostures {
    pub async fn find<'e, E: PgExecutor<'e>>(
        executor: E,
        location_id: Id,
    ) -> sqlx::Result<Vec<Id>> {
        query_scalar(
            "SELECT posture_id FROM device_posture_location WHERE location_id = $1 \
             ORDER BY posture_id",
        )
        .bind(location_id)
        .fetch_all(executor)
        .await
    }

    /// Policy IDs of every location, in one query.
    pub async fn all_by_location<'e, E: PgExecutor<'e>>(
        executor: E,
    ) -> sqlx::Result<HashMap<Id, Vec<Id>>> {
        let rows: Vec<(Id, Id)> = query_as(
            "SELECT location_id, posture_id FROM device_posture_location \
             ORDER BY location_id, posture_id",
        )
        .fetch_all(executor)
        .await?;
        let mut map: HashMap<Id, Vec<Id>> = HashMap::new();
        for (location_id, posture_id) in rows {
            map.entry(location_id).or_default().push(posture_id);
        }
        Ok(map)
    }

    /// Which of `locations` have at least one policy.
    pub async fn with_postures<'e, E: PgExecutor<'e>>(
        executor: E,
        locations: &[Id],
    ) -> sqlx::Result<Vec<Id>> {
        query_scalar(
            "SELECT DISTINCT location_id FROM device_posture_location \
             WHERE location_id = ANY($1) ORDER BY location_id",
        )
        .bind(locations)
        .fetch_all(executor)
        .await
    }

    /// How many of `ids` exist, to validate assignments.
    pub async fn count_existing<'e, E: PgExecutor<'e>>(
        executor: E,
        ids: &[Id],
    ) -> sqlx::Result<i64> {
        query_scalar("SELECT count(*) FROM device_posture WHERE id = ANY($1)")
            .bind(ids)
            .fetch_one(executor)
            .await
    }

    /// Sets the policies of a location.
    pub async fn set(
        conn: &mut PgConnection,
        location_id: Id,
        postures: &[Id],
    ) -> sqlx::Result<()> {
        query("DELETE FROM device_posture_location WHERE location_id = $1")
            .bind(location_id)
            .execute(&mut *conn)
            .await?;
        query(
            "INSERT INTO device_posture_location (posture_id, location_id) \
             SELECT unnest($2::bigint[]), $1 ON CONFLICT DO NOTHING",
        )
        .bind(location_id)
        .bind(postures)
        .execute(conn)
        .await?;
        Ok(())
    }
}

/// The last posture facts a device reported and the result of their evaluation.
#[derive(Clone, Debug, Deserialize, FromRow, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PostureSnapshot {
    pub device_id: Id,
    /// Validated, size-limited facts as reported by the client.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub facts: serde_json::Value,
    pub reported_at: NaiveDateTime,
    /// The location the device was connecting to.
    pub location_id: Option<Id>,
    pub compliant: bool,
    pub failed_checks: Vec<String>,
}

impl PostureSnapshot {
    /// Stores the snapshot, replacing the device's previous one.
    pub async fn upsert<'e, E: PgExecutor<'e>>(&self, executor: E) -> sqlx::Result<()> {
        query(
            "INSERT INTO device_posture_snapshot \
             (device_id, facts, reported_at, location_id, compliant, failed_checks) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (device_id) DO UPDATE SET facts = EXCLUDED.facts, \
             reported_at = EXCLUDED.reported_at, location_id = EXCLUDED.location_id, \
             compliant = EXCLUDED.compliant, failed_checks = EXCLUDED.failed_checks",
        )
        .bind(self.device_id)
        .bind(&self.facts)
        .bind(self.reported_at)
        .bind(self.location_id)
        .bind(self.compliant)
        .bind(&self.failed_checks)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Records a new evaluation result for a stored snapshot without changing its facts.
    pub async fn set_result<'e, E: PgExecutor<'e>>(
        executor: E,
        device_id: Id,
        compliant: bool,
        failed_checks: &[String],
    ) -> sqlx::Result<()> {
        query(
            "UPDATE device_posture_snapshot SET compliant = $2, failed_checks = $3 \
             WHERE device_id = $1",
        )
        .bind(device_id)
        .bind(compliant)
        .bind(failed_checks)
        .execute(executor)
        .await?;
        Ok(())
    }

    pub async fn find<'e, E: PgExecutor<'e>>(
        executor: E,
        device_id: Id,
    ) -> sqlx::Result<Option<Self>> {
        query_as(
            "SELECT device_id, facts, reported_at, location_id, compliant, failed_checks \
             FROM device_posture_snapshot WHERE device_id = $1",
        )
        .bind(device_id)
        .fetch_optional(executor)
        .await
    }

    /// Snapshots of all devices of a user.
    pub async fn find_for_user<'e, E: PgExecutor<'e>>(
        executor: E,
        user_id: Id,
    ) -> sqlx::Result<Vec<Self>> {
        query_as(
            "SELECT s.device_id, s.facts, s.reported_at, s.location_id, s.compliant, \
             s.failed_checks FROM device_posture_snapshot s JOIN device d ON d.id = s.device_id \
             WHERE d.user_id = $1 ORDER BY s.device_id",
        )
        .bind(user_id)
        .fetch_all(executor)
        .await
    }
}

/// An active VPN session in a posture-checked location, with the device's snapshot if any.
#[derive(Clone, Debug, FromRow)]
pub struct ActiveSessionPosture {
    pub session_id: Id,
    pub device_id: Id,
    pub facts: Option<serde_json::Value>,
}

impl ActiveSessionPosture {
    /// All active sessions of a location, joined with their device's snapshot (one query).
    pub async fn for_location<'e, E: PgExecutor<'e>>(
        executor: E,
        location_id: Id,
    ) -> sqlx::Result<Vec<Self>> {
        query_as(
            "SELECT vs.id session_id, vs.device_id, s.facts \
             FROM vpn_client_session vs \
             LEFT JOIN device_posture_snapshot s ON s.device_id = vs.device_id \
             WHERE vs.location_id = $1 AND vs.state IN ('new', 'connected') \
             ORDER BY vs.id",
        )
        .bind(location_id)
        .fetch_all(executor)
        .await
    }
}
