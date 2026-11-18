//! Instance-wide client settings: who may manage devices, how devices may be added, and how the
//! XGuard clients may route traffic.
//!
//! - The settings live in the single-row `enterprisesettings` table, so values saved by an older
//!   release are kept. They are cached in memory like [`crate::db::models::Settings`]; every write
//!   goes through [`ClientSettings::save`] and [`ClientSettings::set_cached`].
//! - Groups can override the instance-wide client traffic policy. Resolution is deterministic and
//!   does not depend on group order, see [`ClientTrafficPolicy::resolve`].

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection, PgExecutor, Type};

use crate::{db::Id, global_value};

/// The most group assignments one request may carry. Far above any real deployment, it only bounds
/// the work a single request can cause.
pub const MAX_GROUP_POLICY_ASSIGNMENTS: usize = 10_000;

/// How XGuard clients may route traffic through a location.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "client_traffic_policy", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ClientTrafficPolicy {
    /// The user chooses between the location's allowed IPs and all traffic.
    #[default]
    None,
    /// Only the location's allowed IPs are routed; "all traffic" cannot be chosen.
    DisableAllTraffic,
    /// All traffic is routed through the location; the user cannot turn it off.
    ForceAllTraffic,
}

impl ClientTrafficPolicy {
    /// Rank used when a user's groups disagree: the higher rank wins.
    ///
    /// Disabling all traffic ranks highest. It is the setting admins use to keep user internet
    /// traffic off the VPN, and the one a client can always honour (the location's own routes
    /// still work), while forcing all traffic can break access when a gateway has no egress.
    const fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::ForceAllTraffic => 1,
            Self::DisableAllTraffic => 2,
        }
    }

    /// The policy that applies to a user.
    ///
    /// - Without group overrides, the instance default applies.
    /// - With group overrides, the instance default is ignored and the highest-ranked group
    ///   policy wins: `disable_all_traffic` over `force_all_traffic` over `none`. An explicit
    ///   `none` on a group therefore exempts its members from a restrictive instance default,
    ///   unless another of their groups is restricted.
    #[must_use]
    pub fn resolve(instance_default: Self, group_policies: impl IntoIterator<Item = Self>) -> Self {
        group_policies
            .into_iter()
            .max_by_key(|policy| policy.rank())
            .unwrap_or(instance_default)
    }
}

/// Instance-wide settings for devices and XGuard clients.
#[derive(Clone, Debug, Deserialize, Eq, FromRow, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ClientSettings {
    /// Only admins may add, edit or delete devices and start desktop activations.
    pub admin_device_management: bool,
    /// Devices may only be added through an XGuard client (no manual WireGuard configuration and
    /// no config downloads for non-admins).
    pub only_client_activation: bool,
    /// Default client traffic policy; groups can override it.
    pub client_traffic_policy: ClientTrafficPolicy,
    /// XGuard clients hide, block and disconnect bare WireGuard tunnels.
    pub disable_tunnels: bool,
    /// Edge shows the client download step during enrollment.
    pub display_download_step: bool,
    /// Edge offers password reset (also needs SMTP).
    pub display_password_reset: bool,
}

impl Default for ClientSettings {
    // The open defaults: users manage their own devices and choose their routing.
    fn default() -> Self {
        Self {
            admin_device_management: false,
            only_client_activation: false,
            client_traffic_policy: ClientTrafficPolicy::None,
            disable_tunnels: false,
            display_download_step: true,
            display_password_reset: true,
        }
    }
}

global_value!(
    CLIENT_SETTINGS,
    Option<ClientSettings>,
    None,
    set_client_settings,
    get_client_settings
);

/// Loads the client settings into the cache at program start.
pub async fn initialize_client_settings<'e, E: PgExecutor<'e>>(executor: E) -> sqlx::Result<()> {
    set_client_settings(Some(ClientSettings::load(executor).await?));
    Ok(())
}

impl ClientSettings {
    /// Reads the settings from the database, bypassing the cache. A missing row means defaults.
    pub async fn load<'e, E: PgExecutor<'e>>(executor: E) -> sqlx::Result<Self> {
        let settings: Option<Self> = sqlx::query_as(
            "SELECT admin_device_management, only_client_activation, client_traffic_policy, \
            disable_tunnels, display_download_step, display_password_reset \
            FROM enterprisesettings ORDER BY id LIMIT 1",
        )
        .fetch_optional(executor)
        .await?;
        Ok(settings.unwrap_or_default())
    }

    /// The cached settings. Before [`initialize_client_settings`] has run (in tests, for example)
    /// this reads the database every time, so separate databases never share a cached value.
    pub async fn current<'e, E: PgExecutor<'e>>(executor: E) -> sqlx::Result<Self> {
        if let Some(settings) = get_client_settings().clone() {
            return Ok(settings);
        }
        Self::load(executor).await
    }

    /// Writes the settings. Call [`Self::set_cached`] once the transaction has committed.
    pub async fn save<'e, E: PgExecutor<'e>>(&self, executor: E) -> sqlx::Result<()> {
        // The table has a single row; older databases may have lost it, so upsert.
        sqlx::query(
            "INSERT INTO enterprisesettings (id, admin_device_management, only_client_activation, \
            client_traffic_policy, disable_tunnels, display_download_step, display_password_reset) \
            VALUES (1, $1, $2, $3, $4, $5, $6) \
            ON CONFLICT (id) DO UPDATE SET \
            admin_device_management = EXCLUDED.admin_device_management, \
            only_client_activation = EXCLUDED.only_client_activation, \
            client_traffic_policy = EXCLUDED.client_traffic_policy, \
            disable_tunnels = EXCLUDED.disable_tunnels, \
            display_download_step = EXCLUDED.display_download_step, \
            display_password_reset = EXCLUDED.display_password_reset",
        )
        .bind(self.admin_device_management)
        .bind(self.only_client_activation)
        .bind(self.client_traffic_policy)
        .bind(self.disable_tunnels)
        .bind(self.display_download_step)
        .bind(self.display_password_reset)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Replaces the cached settings, if the cache is in use.
    pub fn set_cached(self) {
        let mut cache = CLIENT_SETTINGS
            .write()
            .expect("Failed to acquire RwLock for write");
        if cache.is_some() {
            *cache = Some(self);
        }
    }

    /// Whether `is_admin` may add, edit or delete devices of their own.
    #[must_use]
    pub fn may_manage_devices(&self, is_admin: bool) -> bool {
        is_admin || !self.admin_device_management
    }

    /// Whether `is_admin` may set up devices manually (WireGuard keys, config downloads).
    #[must_use]
    pub fn may_configure_manually(&self, is_admin: bool) -> bool {
        is_admin || !self.only_client_activation
    }
}

/// Group overrides of the client traffic policy, grouped by policy. The API shape.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct GroupClientTrafficPolicies {
    pub none: Vec<Id>,
    pub disable_all_traffic: Vec<Id>,
    pub force_all_traffic: Vec<Id>,
}

/// Client settings with the group overrides: the API and audit shape.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ClientSettingsInfo {
    #[serde(flatten)]
    pub settings: ClientSettings,
    pub group_client_traffic_policies: GroupClientTrafficPolicies,
}

/// Why group overrides were rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GroupPolicyError {
    #[error("group {0} is assigned to more than one client traffic policy")]
    Duplicate(Id),
    #[error(
        "too many group client traffic policy assignments (at most {MAX_GROUP_POLICY_ASSIGNMENTS})"
    )]
    TooMany,
    #[error("unknown group in client traffic policies")]
    UnknownGroup,
}

impl GroupClientTrafficPolicies {
    fn assignments(&self) -> impl Iterator<Item = (Id, ClientTrafficPolicy)> + '_ {
        fn tag(
            ids: &[Id],
            policy: ClientTrafficPolicy,
        ) -> impl Iterator<Item = (Id, ClientTrafficPolicy)> + '_ {
            ids.iter().map(move |id| (*id, policy))
        }
        tag(&self.none, ClientTrafficPolicy::None)
            .chain(tag(
                &self.disable_all_traffic,
                ClientTrafficPolicy::DisableAllTraffic,
            ))
            .chain(tag(
                &self.force_all_traffic,
                ClientTrafficPolicy::ForceAllTraffic,
            ))
    }

    /// Sorts the lists and checks that each group appears once.
    pub fn canonicalize(&mut self) -> Result<(), GroupPolicyError> {
        let total = self.none.len() + self.disable_all_traffic.len() + self.force_all_traffic.len();
        if total > MAX_GROUP_POLICY_ASSIGNMENTS {
            return Err(GroupPolicyError::TooMany);
        }
        let mut seen = HashSet::with_capacity(total);
        for (id, _) in self.assignments() {
            if !seen.insert(id) {
                return Err(GroupPolicyError::Duplicate(id));
            }
        }
        self.none.sort_unstable();
        self.disable_all_traffic.sort_unstable();
        self.force_all_traffic.sort_unstable();
        Ok(())
    }

    /// All group overrides, in one query.
    pub async fn load<'e, E: PgExecutor<'e>>(executor: E) -> sqlx::Result<Self> {
        let rows: Vec<(Id, ClientTrafficPolicy)> = sqlx::query_as(
            "SELECT group_id, client_traffic_policy FROM group_client_traffic_policy \
            ORDER BY group_id",
        )
        .fetch_all(executor)
        .await?;
        let mut policies = Self::default();
        for (group_id, policy) in rows {
            match policy {
                ClientTrafficPolicy::None => policies.none.push(group_id),
                ClientTrafficPolicy::DisableAllTraffic => {
                    policies.disable_all_traffic.push(group_id);
                }
                ClientTrafficPolicy::ForceAllTraffic => policies.force_all_traffic.push(group_id),
            }
        }
        Ok(policies)
    }

    /// Replaces every group override. Call [`Self::canonicalize`] first. Unknown groups are
    /// rejected before anything is written.
    pub async fn replace_all(
        &self,
        conn: &mut PgConnection,
    ) -> Result<(), ReplaceGroupPoliciesError> {
        let ids: Vec<Id> = self.assignments().map(|(id, _)| id).collect();
        if !ids.is_empty() {
            let known: i64 =
                sqlx::query_scalar(r#"SELECT count(*) FROM "group" WHERE id = ANY($1)"#)
                    .bind(&ids)
                    .fetch_one(&mut *conn)
                    .await?;
            if usize::try_from(known).ok() != Some(ids.len()) {
                return Err(GroupPolicyError::UnknownGroup.into());
            }
        }
        sqlx::query("DELETE FROM group_client_traffic_policy")
            .execute(&mut *conn)
            .await?;
        for (ids, policy) in [
            (&self.none, ClientTrafficPolicy::None),
            (
                &self.disable_all_traffic,
                ClientTrafficPolicy::DisableAllTraffic,
            ),
            (
                &self.force_all_traffic,
                ClientTrafficPolicy::ForceAllTraffic,
            ),
        ] {
            if ids.is_empty() {
                continue;
            }
            sqlx::query(
                "INSERT INTO group_client_traffic_policy (group_id, client_traffic_policy) \
                SELECT unnest($1::bigint[]), $2",
            )
            .bind(ids)
            .bind(policy)
            .execute(&mut *conn)
            .await?;
        }
        Ok(())
    }
}

/// Errors of [`GroupClientTrafficPolicies::replace_all`].
#[derive(Debug, thiserror::Error)]
pub enum ReplaceGroupPoliciesError {
    #[error(transparent)]
    Invalid(#[from] GroupPolicyError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// The client traffic policy for one user: the instance default resolved against the policies of
/// the user's groups (one query).
pub async fn effective_client_traffic_policy<'e, E: PgExecutor<'e>>(
    executor: E,
    instance_default: ClientTrafficPolicy,
    user_id: Id,
) -> sqlx::Result<ClientTrafficPolicy> {
    let group_policies: Vec<ClientTrafficPolicy> = sqlx::query_scalar(
        "SELECT DISTINCT gctp.client_traffic_policy FROM group_client_traffic_policy gctp \
        JOIN group_user gu ON gu.group_id = gctp.group_id WHERE gu.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(executor)
    .await?;
    Ok(ClientTrafficPolicy::resolve(
        instance_default,
        group_policies,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ClientTrafficPolicy::{DisableAllTraffic, ForceAllTraffic, None as NoPolicy};

    #[test]
    fn instance_default_applies_without_groups() {
        for policy in [NoPolicy, DisableAllTraffic, ForceAllTraffic] {
            assert_eq!(ClientTrafficPolicy::resolve(policy, []), policy);
        }
    }

    #[test]
    fn group_override_replaces_instance_default() {
        assert_eq!(
            ClientTrafficPolicy::resolve(DisableAllTraffic, [ForceAllTraffic]),
            ForceAllTraffic
        );
        assert_eq!(
            ClientTrafficPolicy::resolve(ForceAllTraffic, [NoPolicy]),
            NoPolicy
        );
    }

    #[test]
    fn highest_ranked_group_policy_wins_in_any_order() {
        let groups = [NoPolicy, ForceAllTraffic, DisableAllTraffic];
        // Every permutation gives the same answer.
        for rotation in 0..groups.len() {
            let mut ordered = groups;
            ordered.rotate_left(rotation);
            assert_eq!(
                ClientTrafficPolicy::resolve(NoPolicy, ordered),
                DisableAllTraffic
            );
            ordered.reverse();
            assert_eq!(
                ClientTrafficPolicy::resolve(ForceAllTraffic, ordered),
                DisableAllTraffic
            );
        }
        assert_eq!(
            ClientTrafficPolicy::resolve(DisableAllTraffic, [NoPolicy, ForceAllTraffic]),
            ForceAllTraffic
        );
    }

    #[test]
    fn defaults_are_open() {
        let settings = ClientSettings::default();
        assert!(settings.may_manage_devices(false));
        assert!(settings.may_configure_manually(false));
        assert_eq!(settings.client_traffic_policy, NoPolicy);
        assert!(settings.display_download_step && settings.display_password_reset);
        assert!(!settings.disable_tunnels);
    }

    #[test]
    fn admins_are_never_restricted() {
        let settings = ClientSettings {
            admin_device_management: true,
            only_client_activation: true,
            ..ClientSettings::default()
        };
        assert!(settings.may_manage_devices(true));
        assert!(settings.may_configure_manually(true));
        assert!(!settings.may_manage_devices(false));
        assert!(!settings.may_configure_manually(false));
    }

    #[test]
    fn canonicalize_sorts_and_rejects_duplicates() {
        let mut policies = GroupClientTrafficPolicies {
            none: vec![3, 1],
            disable_all_traffic: vec![7],
            force_all_traffic: vec![5, 4],
        };
        policies.canonicalize().unwrap();
        assert_eq!(policies.none, [1, 3]);
        assert_eq!(policies.force_all_traffic, [4, 5]);

        let mut duplicate = GroupClientTrafficPolicies {
            none: vec![1],
            disable_all_traffic: vec![1],
            force_all_traffic: vec![],
        };
        assert_eq!(
            duplicate.canonicalize(),
            Err(GroupPolicyError::Duplicate(1))
        );

        let mut same_list = GroupClientTrafficPolicies {
            force_all_traffic: vec![2, 2],
            ..GroupClientTrafficPolicies::default()
        };
        assert_eq!(
            same_list.canonicalize(),
            Err(GroupPolicyError::Duplicate(2))
        );

        let mut too_many = GroupClientTrafficPolicies {
            none: (0..=MAX_GROUP_POLICY_ASSIGNMENTS as Id).collect(),
            ..GroupClientTrafficPolicies::default()
        };
        assert_eq!(too_many.canonicalize(), Err(GroupPolicyError::TooMany));
    }

    #[test]
    fn cache_is_used_once_initialized() {
        // Before initialization, updates do not populate the cache.
        ClientSettings::default().set_cached();
        assert_eq!(*get_client_settings(), None);

        set_client_settings(Some(ClientSettings::default()));
        let changed = ClientSettings {
            disable_tunnels: true,
            ..ClientSettings::default()
        };
        changed.clone().set_cached();
        assert_eq!(get_client_settings().clone(), Some(changed));
        set_client_settings(None);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let result: Result<GroupClientTrafficPolicies, _> = serde_json::from_str(
            r#"{"none": [], "disable_all_traffic": [], "force_all_traffic": [], "x": []}"#,
        );
        assert!(result.is_err());
    }
}
