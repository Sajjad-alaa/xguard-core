//! Registered device limits and simultaneous MFA VPN connection limits.
//!
//! Limits follow a three-tier precedence:
//! 1. Per-user override (`user_device_limit`), when set (non-null).
//! 2. Per-group override (`group_device_limit`): if a user belongs to multiple groups with
//!    overrides, the **most permissive** value applies (`0` = unlimited beats any finite limit;
//!    otherwise the highest finite value).
//! 3. Global default (`device_limit_settings`, default `0` = unlimited).
//!
//! `0` always means unlimited. Both enforcement functions lock the `"user"` row with
//! `FOR UPDATE` inside the caller's transaction so parallel requests cannot exceed the limit.

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection, PgExecutor};
use thiserror::Error;

use crate::db::Id;

/// Upper bound to reject absurd limit inputs.
pub const MAX_CONFIGURABLE_LIMIT: i32 = 10_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, FromRow)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeviceLimitSettings {
    /// Global default maximum registered user devices per user (`0` = unlimited).
    pub max_devices_per_user: i32,
    /// Global default maximum simultaneous MFA VPN connections per user per location
    /// (`0` = unlimited). Applies only to MFA-protected locations.
    pub max_connections_per_user: i32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, FromRow)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeviceLimitOverride {
    /// `None` inherits; `Some(0)` is explicitly unlimited; `Some(n)` limits to `n`.
    pub max_devices: Option<i32>,
    /// `None` inherits; `Some(0)` is explicitly unlimited; `Some(n)` limits to `n`.
    pub max_connections: Option<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, FromRow)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GroupDeviceLimit {
    pub group_id: Id,
    pub max_devices: Option<i32>,
    pub max_connections: Option<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserDeviceLimitInfo {
    pub user_id: Id,
    pub device_count: i64,
    pub effective_max_devices: i32,
    pub effective_max_connections: i32,
    pub override_max_devices: Option<i32>,
    pub override_max_connections: Option<i32>,
}

#[derive(Debug, Error)]
pub enum DeviceLimitError {
    #[error("device_limit_reached: Maximum number of registered devices ({limit}) reached.")]
    DeviceLimitReached { limit: i32, current: i64 },
    #[error(
        "connection_limit_reached: Maximum number of simultaneous VPN connections ({limit}) reached."
    )]
    ConnectionLimitReached { limit: i32, current: i64 },
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub fn validate_limit_value(value: i32, field: &str) -> Result<(), DeviceLimitError> {
    if !(0..=MAX_CONFIGURABLE_LIMIT).contains(&value) {
        return Err(DeviceLimitError::Invalid(format!(
            "{field} must be between 0 and {MAX_CONFIGURABLE_LIMIT}"
        )));
    }
    Ok(())
}

/// Resolves effective limit from global default, group overrides (most permissive wins,
/// `0` = unlimited beats any finite limit), and optional user override (always wins).
#[must_use]
pub fn resolve_limit(global: i32, group_overrides: &[i32], user_override: Option<i32>) -> i32 {
    if let Some(limit) = user_override {
        return limit.max(0);
    }
    if !group_overrides.is_empty() {
        if group_overrides.contains(&0) {
            return 0;
        }
        if let Some(&max_group) = group_overrides.iter().max() {
            return max_group.max(0);
        }
    }
    global.max(0)
}

impl DeviceLimitSettings {
    pub async fn load<'e, E: PgExecutor<'e>>(executor: E) -> Result<Self, sqlx::Error> {
        let row: Option<Self> = sqlx::query_as(
            "SELECT max_devices_per_user, max_connections_per_user \
             FROM device_limit_settings WHERE id = 1",
        )
        .fetch_optional(executor)
        .await?;
        Ok(row.unwrap_or_default())
    }

    pub async fn save(&self, conn: &mut PgConnection) -> Result<Self, DeviceLimitError> {
        validate_limit_value(self.max_devices_per_user, "max_devices_per_user")?;
        validate_limit_value(self.max_connections_per_user, "max_connections_per_user")?;
        let row: Self = sqlx::query_as(
            "INSERT INTO device_limit_settings (id, max_devices_per_user, max_connections_per_user) \
             VALUES (1, $1, $2) \
             ON CONFLICT (id) DO UPDATE SET \
                max_devices_per_user = EXCLUDED.max_devices_per_user, \
                max_connections_per_user = EXCLUDED.max_connections_per_user \
             RETURNING max_devices_per_user, max_connections_per_user",
        )
        .bind(self.max_devices_per_user)
        .bind(self.max_connections_per_user)
        .fetch_one(conn)
        .await?;
        Ok(row)
    }
}

pub async fn list_group_limits<'e, E: PgExecutor<'e>>(
    executor: E,
) -> Result<Vec<GroupDeviceLimit>, sqlx::Error> {
    sqlx::query_as(
        "SELECT group_id, max_devices, max_connections \
         FROM group_device_limit ORDER BY group_id",
    )
    .fetch_all(executor)
    .await
}

pub async fn get_group_limit<'e, E: PgExecutor<'e>>(
    executor: E,
    group_id: Id,
) -> Result<DeviceLimitOverride, sqlx::Error> {
    let row: Option<DeviceLimitOverride> = sqlx::query_as(
        "SELECT max_devices, max_connections FROM group_device_limit WHERE group_id = $1",
    )
    .bind(group_id)
    .fetch_optional(executor)
    .await?;
    Ok(row.unwrap_or_default())
}

pub async fn set_group_limit(
    conn: &mut PgConnection,
    group_id: Id,
    override_val: DeviceLimitOverride,
) -> Result<DeviceLimitOverride, DeviceLimitError> {
    if let Some(v) = override_val.max_devices {
        validate_limit_value(v, "max_devices")?;
    }
    if let Some(v) = override_val.max_connections {
        validate_limit_value(v, "max_connections")?;
    }
    if override_val.max_devices.is_none() && override_val.max_connections.is_none() {
        sqlx::query("DELETE FROM group_device_limit WHERE group_id = $1")
            .bind(group_id)
            .execute(conn)
            .await?;
        return Ok(DeviceLimitOverride::default());
    }
    let row: DeviceLimitOverride = sqlx::query_as(
        "INSERT INTO group_device_limit (group_id, max_devices, max_connections) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (group_id) DO UPDATE SET \
            max_devices = EXCLUDED.max_devices, \
            max_connections = EXCLUDED.max_connections \
         RETURNING max_devices, max_connections",
    )
    .bind(group_id)
    .bind(override_val.max_devices)
    .bind(override_val.max_connections)
    .fetch_one(conn)
    .await?;
    Ok(row)
}

pub async fn get_user_override<'e, E: PgExecutor<'e>>(
    executor: E,
    user_id: Id,
) -> Result<DeviceLimitOverride, sqlx::Error> {
    let row: Option<DeviceLimitOverride> = sqlx::query_as(
        "SELECT max_devices, max_connections FROM user_device_limit WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(executor)
    .await?;
    Ok(row.unwrap_or_default())
}

pub async fn set_user_override(
    conn: &mut PgConnection,
    user_id: Id,
    override_val: DeviceLimitOverride,
) -> Result<DeviceLimitOverride, DeviceLimitError> {
    if let Some(v) = override_val.max_devices {
        validate_limit_value(v, "max_devices")?;
    }
    if let Some(v) = override_val.max_connections {
        validate_limit_value(v, "max_connections")?;
    }
    if override_val.max_devices.is_none() && override_val.max_connections.is_none() {
        sqlx::query("DELETE FROM user_device_limit WHERE user_id = $1")
            .bind(user_id)
            .execute(conn)
            .await?;
        return Ok(DeviceLimitOverride::default());
    }
    let row: DeviceLimitOverride = sqlx::query_as(
        "INSERT INTO user_device_limit (user_id, max_devices, max_connections) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (user_id) DO UPDATE SET \
            max_devices = EXCLUDED.max_devices, \
            max_connections = EXCLUDED.max_connections \
         RETURNING max_devices, max_connections",
    )
    .bind(user_id)
    .bind(override_val.max_devices)
    .bind(override_val.max_connections)
    .fetch_one(conn)
    .await?;
    Ok(row)
}

/// Computes the effective `(max_devices, max_connections)` for `user_id` on `conn`.
pub async fn effective_limits_for_user(
    conn: &mut PgConnection,
    user_id: Id,
) -> Result<(i32, i32, DeviceLimitOverride), sqlx::Error> {
    let global = DeviceLimitSettings::load(&mut *conn).await?;
    let user_override = get_user_override(&mut *conn, user_id).await?;
    let group_rows: Vec<DeviceLimitOverride> = sqlx::query_as(
        "SELECT gdl.max_devices, gdl.max_connections \
         FROM group_device_limit gdl \
         JOIN group_user gu ON gu.group_id = gdl.group_id \
         WHERE gu.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;

    let group_devices: Vec<i32> = group_rows.iter().filter_map(|r| r.max_devices).collect();
    let group_conns: Vec<i32> = group_rows
        .iter()
        .filter_map(|r| r.max_connections)
        .collect();

    let max_devices = resolve_limit(
        global.max_devices_per_user,
        &group_devices,
        user_override.max_devices,
    );
    let max_connections = resolve_limit(
        global.max_connections_per_user,
        &group_conns,
        user_override.max_connections,
    );
    Ok((max_devices, max_connections, user_override))
}

pub async fn get_user_limit_info(
    conn: &mut PgConnection,
    user_id: Id,
) -> Result<UserDeviceLimitInfo, sqlx::Error> {
    let (effective_max_devices, effective_max_connections, user_override) =
        effective_limits_for_user(&mut *conn, user_id).await?;
    let device_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM device WHERE user_id = $1 AND device_type = 'user'",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(UserDeviceLimitInfo {
        user_id,
        device_count,
        effective_max_devices,
        effective_max_connections,
        override_max_devices: user_override.max_devices,
        override_max_connections: user_override.max_connections,
    })
}

/// Atomically checks whether `user_id` may register another user device.
/// Locks the `"user"` row `FOR UPDATE` inside the caller's transaction so concurrent requests
/// cannot exceed the configured limit.
pub async fn enforce_registered_device_limit(
    conn: &mut PgConnection,
    user_id: Id,
) -> Result<(), DeviceLimitError> {
    sqlx::query("SELECT id FROM \"user\" WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    let (max_devices, _, _) = effective_limits_for_user(&mut *conn, user_id).await?;
    if max_devices == 0 {
        return Ok(());
    }
    let current: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM device WHERE user_id = $1 AND device_type = 'user'",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?;
    if current >= i64::from(max_devices) {
        return Err(DeviceLimitError::DeviceLimitReached {
            limit: max_devices,
            current,
        });
    }
    Ok(())
}

/// Atomically checks whether `user_id` may open another simultaneous MFA VPN session in
/// `location_id` for `device_id`. Locks the `"user"` row `FOR UPDATE` inside the caller's
/// transaction. Reconnecting the same `device_id` does not count against its own slot.
pub async fn enforce_connection_limit(
    conn: &mut PgConnection,
    user_id: Id,
    location_id: Id,
    device_id: Id,
) -> Result<(), DeviceLimitError> {
    sqlx::query("SELECT id FROM \"user\" WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    let (_, max_connections, _) = effective_limits_for_user(&mut *conn, user_id).await?;
    if max_connections == 0 {
        return Ok(());
    }
    let current: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT device_id) FROM vpn_client_session \
         WHERE user_id = $1 AND location_id = $2 AND device_id <> $3 \
         AND is_mfa_session = true AND state IN ('new', 'connected')",
    )
    .bind(user_id)
    .bind(location_id)
    .bind(device_id)
    .fetch_one(&mut *conn)
    .await?;
    if current >= i64::from(max_connections) {
        return Err(DeviceLimitError::ConnectionLimitReached {
            limit: max_connections,
            current,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use super::*;
    use crate::db::{
        models::{
            Device, DeviceType, User, WireguardNetwork, group::Group,
            vpn_client_session::VpnClientSession,
        },
        setup_pool,
    };

    #[test]
    fn precedence_user_beats_most_permissive_group_beats_global() {
        // Global only
        assert_eq!(resolve_limit(3, &[], None), 3);
        assert_eq!(resolve_limit(0, &[], None), 0);
        // Multiple groups: most permissive finite wins
        assert_eq!(resolve_limit(2, &[1, 5, 3], None), 5);
        // Any group with 0 (unlimited) is most permissive
        assert_eq!(resolve_limit(2, &[1, 0, 5], None), 0);
        // User override always wins (even if stricter than group/global)
        assert_eq!(resolve_limit(0, &[0, 10], Some(1)), 1);
        assert_eq!(resolve_limit(2, &[1], Some(0)), 0);
    }

    #[sqlx::test]
    async fn test_registered_device_limit_and_overrides(
        _: PgPoolOptions,
        options: PgConnectOptions,
    ) {
        let pool = setup_pool(options).await;
        let user = User::new("alice", Some("pass"), "A", "B", "alice@example.com", None)
            .save(&pool)
            .await
            .unwrap();

        let mut tx = pool.begin().await.unwrap();
        DeviceLimitSettings {
            max_devices_per_user: 1,
            max_connections_per_user: 0,
        }
        .save(&mut tx)
        .await
        .unwrap();
        enforce_registered_device_limit(&mut tx, user.id)
            .await
            .unwrap();
        Device::new(
            "dev1".into(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            user.id,
            DeviceType::User,
            None,
            true,
        )
        .save(&mut *tx)
        .await
        .unwrap();
        // Second user device hits limit = 1
        assert!(matches!(
            enforce_registered_device_limit(&mut tx, user.id).await,
            Err(DeviceLimitError::DeviceLimitReached {
                limit: 1,
                current: 1
            })
        ));
        // Network devices do not count against user device limit
        Device::new(
            "netdev".into(),
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".into(),
            user.id,
            DeviceType::Network,
            None,
            true,
        )
        .save(&mut *tx)
        .await
        .unwrap();
        let info = get_user_limit_info(&mut tx, user.id).await.unwrap();
        assert_eq!(info.device_count, 1);
        assert_eq!(info.effective_max_devices, 1);

        // Group override of 2 allows a second device
        let group = Group::new("eng").save(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO group_user (group_id, user_id) VALUES ($1, $2)")
            .bind(group.id)
            .bind(user.id)
            .execute(&mut *tx)
            .await
            .unwrap();
        set_group_limit(
            &mut tx,
            group.id,
            DeviceLimitOverride {
                max_devices: Some(2),
                max_connections: None,
            },
        )
        .await
        .unwrap();
        enforce_registered_device_limit(&mut tx, user.id)
            .await
            .unwrap();

        // User override of 1 wins over group override of 2
        set_user_override(
            &mut tx,
            user.id,
            DeviceLimitOverride {
                max_devices: Some(1),
                max_connections: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            enforce_registered_device_limit(&mut tx, user.id).await,
            Err(DeviceLimitError::DeviceLimitReached {
                limit: 1,
                current: 1
            })
        ));
        tx.commit().await.unwrap();
    }

    #[sqlx::test]
    async fn test_simultaneous_connection_limit(_: PgPoolOptions, options: PgConnectOptions) {
        let pool = setup_pool(options).await;
        let user = User::new("bob", Some("pass"), "B", "C", "bob@example.com", None)
            .save(&pool)
            .await
            .unwrap();
        let dev1 = Device::new(
            "d1".into(),
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".into(),
            user.id,
            DeviceType::User,
            None,
            true,
        )
        .save(&pool)
        .await
        .unwrap();
        let dev2 = Device::new(
            "d2".into(),
            "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=".into(),
            user.id,
            DeviceType::User,
            None,
            true,
        )
        .save(&pool)
        .await
        .unwrap();
        let mut network = WireguardNetwork::default();
        network.name = "hq".into();
        let network = network.save(&pool).await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        DeviceLimitSettings {
            max_devices_per_user: 0,
            max_connections_per_user: 1,
        }
        .save(&mut tx)
        .await
        .unwrap();

        // First device connects
        enforce_connection_limit(&mut tx, user.id, network.id, dev1.id)
            .await
            .unwrap();
        VpnClientSession::new(network.id, user.id, dev1.id, None, true)
            .save(&mut *tx)
            .await
            .unwrap();

        // Same device reconnecting is still allowed
        enforce_connection_limit(&mut tx, user.id, network.id, dev1.id)
            .await
            .unwrap();

        // Second device in same location is refused
        assert!(matches!(
            enforce_connection_limit(&mut tx, user.id, network.id, dev2.id).await,
            Err(DeviceLimitError::ConnectionLimitReached {
                limit: 1,
                current: 1
            })
        ));
        tx.commit().await.unwrap();
    }
}
