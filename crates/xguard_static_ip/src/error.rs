use thiserror::Error;
use xguard_common::db::{Id, models::wireguard::NetworkAddressError};

#[derive(Error, Debug)]
pub enum StaticIpError {
    #[error("Network (location) with ID {0} not found")]
    NetworkNotFound(Id),
    #[error("Device {0} is not assigned to network {1}")]
    DeviceNotInNetwork(Id, Id),
    #[error(transparent)]
    InvalidIpAssignment(#[from] NetworkAddressError),
    #[error(transparent)]
    SqlxError(#[from] sqlx::Error),
}
