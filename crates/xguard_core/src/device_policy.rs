//! Server-side enforcement of the client settings ([`ClientSettings`]).
//!
//! The web UI hides actions the settings forbid, but every rule is checked here, on the server,
//! for the web API and for enrollment through Edge:
//!
//! - `admin_device_management`: only admins add, edit or delete devices, and start desktop
//!   activations. Through Edge, a device may be created only when the user is an admin or the
//!   enrollment token was issued by another user who is still an admin.
//! - `only_client_activation`: non-admins cannot add devices with their own WireGuard key, change a
//!   device's key, or download WireGuard configs; devices come from an XGuard client.
//!
//! Admins are never restricted.

use sqlx::PgExecutor;
use xguard_common::db::{
    Id,
    models::{ClientSettings, User},
};

use crate::{auth::SessionInfo, error::WebError};

/// Error returned to non-admins when device management is limited to admins.
pub const ADMIN_DEVICE_MANAGEMENT_MSG: &str = "Only administrators can manage devices";
/// Error returned to non-admins when devices must be added through an XGuard client.
pub const ONLY_CLIENT_ACTIVATION_MSG: &str = "Devices can only be added through the XGuard client";

/// Refuses unless the session may add, edit or delete devices.
pub async fn ensure_may_manage_devices<'e, E: PgExecutor<'e>>(
    executor: E,
    session: &SessionInfo,
) -> Result<ClientSettings, WebError> {
    let settings = ClientSettings::current(executor).await?;
    if settings.may_manage_devices(session.is_admin) {
        Ok(settings)
    } else {
        warn!(
            "User {} tried to manage a device, but only admins may manage devices",
            session.user.username
        );
        Err(WebError::Forbidden(ADMIN_DEVICE_MANAGEMENT_MSG))
    }
}

/// Refuses unless the session may configure devices manually (own keys, config downloads).
pub async fn ensure_may_configure_manually<'e, E: PgExecutor<'e>>(
    executor: E,
    session: &SessionInfo,
) -> Result<ClientSettings, WebError> {
    let settings = ClientSettings::current(executor).await?;
    if settings.may_configure_manually(session.is_admin) {
        Ok(settings)
    } else {
        warn!(
            "User {} tried to configure a device manually, but devices can only be added \
            through the XGuard client",
            session.user.username
        );
        Err(WebError::Forbidden(ONLY_CLIENT_ACTIVATION_MSG))
    }
}

/// Whether a device may be created through Edge enrollment.
///
/// `issued_by_other_admin` is true when the enrollment token was issued by a different user who
/// is an admin now. A token a user issued for themselves counts as user-initiated.
#[must_use]
pub const fn enrollment_may_create_device(
    settings: &ClientSettings,
    user_is_admin: bool,
    issued_by_other_admin: bool,
) -> bool {
    !settings.admin_device_management || user_is_admin || issued_by_other_admin
}

/// Whether the enrollment token was issued by someone other than `user` who is an admin now.
pub async fn token_issued_by_other_admin<'e, E: PgExecutor<'e> + Copy>(
    executor: E,
    user: &User<Id>,
    admin_id: Option<Id>,
) -> sqlx::Result<bool> {
    let Some(admin_id) = admin_id.filter(|id| *id != user.id) else {
        return Ok(false);
    };
    match User::find_by_id(executor, admin_id).await? {
        Some(admin) if admin.is_active => admin.is_admin(executor).await,
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_device_creation_rules() {
        let open = ClientSettings::default();
        assert!(enrollment_may_create_device(&open, false, false));

        let restricted = ClientSettings {
            admin_device_management: true,
            ..ClientSettings::default()
        };
        assert!(!enrollment_may_create_device(&restricted, false, false));
        assert!(enrollment_may_create_device(&restricted, true, false));
        assert!(enrollment_may_create_device(&restricted, false, true));

        // Client activation is exactly what enrollment through Edge is, so it is never refused
        // for that reason.
        let client_only = ClientSettings {
            only_client_activation: true,
            ..ClientSettings::default()
        };
        assert!(enrollment_may_create_device(&client_only, false, false));
    }
}
