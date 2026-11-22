use sqlx::PgConnection;
use thiserror::Error;
use tokio::sync::mpsc::UnboundedSender;
use xguard_common::db::{
    Id,
    models::{
        ApiToken, ModelError, Settings, User, WireguardNetwork, WireguardNetworkError,
        device::DeviceInfo, settings::set_settings,
    },
};

use crate::{
    grpc::{GatewayCommand, send_multiple_gateway_commands},
    location_management::sync_allowed_devices_for_user,
};

/// Errors arising from user management operations.
#[derive(Debug, Error)]
pub enum UserManagementError {
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("Model error: {0}")]
    Model(#[from] ModelError),
    #[error("WireGuard network error: {0}")]
    Network(#[from] WireguardNetworkError),
}

pub struct UserManager {
    gateway_commands: Vec<GatewayCommand>,
}

impl UserManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            gateway_commands: Vec::new(),
        }
    }

    /// Deletes the user and cleans up his devices from gateways
    pub async fn delete_user_and_cleanup_devices(
        &mut self,
        user: User<Id>,
        conn: &mut PgConnection,
    ) -> Result<(), UserManagementError> {
        let username = user.username.clone();
        debug!("Deleting user {username}, removing his devices from gateways and updating ldap...",);
        let devices = user.devices(&mut *conn).await?;

        // get all locations affected by devices being deleted

        for device in devices {
            let device_info = DeviceInfo::from_device(&mut *conn, device).await?;
            self.gateway_commands
                .push(GatewayCommand::DeviceDeleted(device_info));
        }

        let was_default_admin = Settings::get_current_settings().default_admin_id == Some(user.id);

        user.delete(&mut *conn).await?;

        // Update settings because they may also change due to a DB constraint.
        if was_default_admin && let Some(settings) = Settings::get(&mut *conn).await? {
            set_settings(Some(settings));
        }

        info!("The user {username} has been deleted and his devices removed");

        Ok(())
    }

    /// Update Gateway state based on this user device access rights
    pub async fn sync_allowed_user_devices(
        &mut self,
        user: &User<Id>,
        conn: &mut PgConnection,
    ) -> Result<(), UserManagementError> {
        debug!("Syncing allowed devices of user {}", user.username);
        let locations = WireguardNetwork::all(&mut *conn).await?;
        for location in locations {
            sync_allowed_devices_for_user(
                &location,
                &mut *conn,
                user,
                None,
                &mut self.gateway_commands,
            )
            .await?;
        }

        info!("Allowed devices of user {} synced", user.username);

        Ok(())
    }

    /// Disable user, log out all his sessions and update Gateway state.
    pub async fn disable_user(
        &mut self,
        user: &mut User<Id>,
        conn: &mut PgConnection,
    ) -> Result<(), UserManagementError> {
        user.is_active = false;
        user.save(&mut *conn).await?;
        user.logout_all_sessions(&mut *conn).await?;
        ApiToken::delete_all_for_user(&mut *conn, user.id).await?;

        self.sync_allowed_user_devices(user, conn).await?;

        Ok(())
    }

    /// Append queued gateway commands from an isolated sub-operation.
    pub fn append(&mut self, other: &mut Self) {
        self.gateway_commands.append(&mut other.gateway_commands);
    }

    /// Send all commands to Gateway. Use this method *after* database transaction is committed.
    pub fn send(self, gateway_tx: &UnboundedSender<GatewayCommand>) {
        send_multiple_gateway_commands(self.gateway_commands, gateway_tx);
    }
}

impl Default for UserManager {
    fn default() -> Self {
        Self::new()
    }
}
