pub mod gateway_conversions;

use std::fmt;

mod generated {
    pub mod xguard {
        pub mod proxy {
            pub mod v2 {
                tonic::include_proto!("xguard.proxy.v2");
            }
        }

        pub mod gateway {
            pub mod v2 {
                tonic::include_proto!("xguard.gateway.v2");
            }
        }

        pub mod worker {
            pub mod v1 {
                tonic::include_proto!("xguard.worker.v1");
            }
        }

        pub mod client_types {
            tonic::include_proto!("xguard.client_types");
        }

        pub mod common {
            pub mod v2 {
                tonic::include_proto!("xguard.common.v2");
            }
        }
    }
}

pub mod proxy {
    pub use crate::generated::xguard::proxy::v2::*;
}

pub mod gateway {
    pub use crate::generated::xguard::gateway::v2::*;
}

pub mod worker {
    pub use crate::generated::xguard::worker::v1::*;
}

pub mod client_types {
    pub use crate::generated::xguard::client_types::*;
}

pub mod common {
    pub use crate::generated::xguard::common::v2::*;
}

use client_types::MfaMethod;
use proxy::{CoreError, CoreErrorCode};
use serde::Serialize;
use tonic::{Code, Status};
use xguard_common::{
    db::{
        Id,
        models::{
            Device, User, WireguardNetwork,
            vpn_client_session::VpnClientMfaMethod,
            wireguard::{LocationMfaMode, ServiceLocationMode},
        },
    },
    gateway_types::WireguardPeer,
};

use crate::gateway::Configuration;

// Client MFA methods
impl fmt::Display for MfaMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Totp => "TOTP",
            Self::Email => "Email",
            Self::Oidc => "OIDC",
            Self::Biometric => "Biometric",
            Self::MobileApprove => "MobileApprove",
            Self::Fido2 => "FIDO2",
        })
    }
}

impl Serialize for MfaMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match *self {
            Self::Totp => serializer.serialize_unit_variant("MfaMethod", 0, "Totp"),
            Self::Email => serializer.serialize_unit_variant("MfaMethod", 1, "Email"),
            Self::Oidc => serializer.serialize_unit_variant("MfaMethod", 2, "Oidc"),
            Self::Biometric => serializer.serialize_unit_variant("MfaMethod", 3, "Biometric"),
            Self::MobileApprove => {
                serializer.serialize_unit_variant("MfaMethod", 4, "MobileApprove")
            }
            Self::Fido2 => serializer.serialize_unit_variant("MfaMethod", 5, "Fido2"),
        }
    }
}

impl From<MfaMethod> for VpnClientMfaMethod {
    fn from(val: MfaMethod) -> Self {
        match val {
            MfaMethod::Totp => Self::Totp,
            MfaMethod::Email => Self::Email,
            MfaMethod::Oidc => Self::Oidc,
            MfaMethod::Biometric => Self::Biometric,
            MfaMethod::MobileApprove => Self::MobileApprove,
            MfaMethod::Fido2 => Self::Fido2,
        }
    }
}

impl From<VpnClientMfaMethod> for MfaMethod {
    fn from(val: VpnClientMfaMethod) -> Self {
        match val {
            VpnClientMfaMethod::Totp => Self::Totp,
            VpnClientMfaMethod::Email => Self::Email,
            VpnClientMfaMethod::Oidc => Self::Oidc,
            VpnClientMfaMethod::Biometric => Self::Biometric,
            VpnClientMfaMethod::MobileApprove => Self::MobileApprove,
            VpnClientMfaMethod::Fido2 => Self::Fido2,
        }
    }
}

/// Message prefix of every device posture refusal.
pub const POSTURE_REJECTED_PREFIX: &str = "Device posture check failed: ";
/// Longest posture refusal message sent to a client.
const MAX_POSTURE_MESSAGE_LEN: usize = 1024;

/// The status core returns when a device does not meet a location's posture policies. It
/// reaches Edge as a `PERMISSION_DENIED` [`CoreError`] with [`CoreErrorCode::PostureRejected`].
#[must_use]
pub fn posture_rejected_status(failed_checks: &[String]) -> Status {
    let mut message = format!("{POSTURE_REJECTED_PREFIX}{}", failed_checks.join("; "));
    if message.len() > MAX_POSTURE_MESSAGE_LEN {
        let mut end = MAX_POSTURE_MESSAGE_LEN - 3;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push_str("...");
    }
    Status::permission_denied(message)
}

/// Whether `status` is a posture refusal made by [`posture_rejected_status`].
#[must_use]
pub fn is_posture_rejected(status: &Status) -> bool {
    status.code() == Code::PermissionDenied && status.message().starts_with(POSTURE_REJECTED_PREFIX)
}

impl From<Status> for CoreError {
    fn from(status: Status) -> Self {
        let mut error = Self {
            status_code: status.code().into(),
            message: status.message().into(),
            ..Default::default()
        };
        if is_posture_rejected(&status) {
            error.set_code(CoreErrorCode::PostureRejected);
        }
        error
    }
}

impl CoreError {
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self {
            status_code: Code::Unauthenticated.into(),
            message: message.into(),
            ..Default::default()
        }
    }

    /// Attaches the reason the proxy uses to pick a user-facing message.
    #[must_use]
    pub fn with_code(mut self, code: CoreErrorCode) -> Self {
        self.set_code(code);
        self
    }

    /// An `invalid_argument` error carrying a caller-facing message.
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self {
            status_code: tonic::Code::InvalidArgument.into(),
            message: message.into(),
            ..Default::default()
        }
    }

    /// An `internal` error carrying a caller-facing message.
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status_code: tonic::Code::Internal.into(),
            message: message.into(),
            ..Default::default()
        }
    }

    /// A `not_found` error carrying a caller-facing message.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status_code: tonic::Code::NotFound.into(),
            message: message.into(),
            ..Default::default()
        }
    }

    /// A `failed_precondition` error carrying a caller-facing message.
    pub fn failed_precondition(message: impl Into<String>) -> Self {
        Self {
            status_code: tonic::Code::FailedPrecondition.into(),
            message: message.into(),
            ..Default::default()
        }
    }
}

impl From<Device<Id>> for client_types::Device {
    fn from(device: Device<Id>) -> Self {
        Self {
            id: device.id,
            name: device.name,
            pubkey: device.wireguard_pubkey,
            user_id: device.user_id,
            created_at: device.created.and_utc().timestamp(),
        }
    }
}

impl From<User<Id>> for client_types::AdminInfo {
    fn from(admin: User<Id>) -> Self {
        Self {
            name: format!("{} {}", admin.first_name, admin.last_name),
            phone_number: admin.phone,
            email: admin.email,
        }
    }
}

impl From<LocationMfaMode> for client_types::LocationMfaMode {
    fn from(value: LocationMfaMode) -> Self {
        match value {
            LocationMfaMode::Disabled => Self::Disabled,
            LocationMfaMode::Internal => Self::Internal,
            LocationMfaMode::External => Self::External,
        }
    }
}

impl From<ServiceLocationMode> for client_types::ServiceLocationMode {
    fn from(value: ServiceLocationMode) -> Self {
        match value {
            ServiceLocationMode::Disabled => Self::Disabled,
            ServiceLocationMode::PreLogon => Self::Prelogon,
            ServiceLocationMode::AlwaysOn => Self::Alwayson,
        }
    }
}

impl Configuration {
    pub fn new(location: &WireguardNetwork<Id>, peers: Vec<WireguardPeer>) -> Self {
        Self {
            name: location.name.clone(),
            port: location.port.cast_unsigned(),
            private_key: location.prvkey.clone(),
            addresses: location.address().iter().map(ToString::to_string).collect(),
            peers: peers.into_iter().map(Into::into).collect(),
            mtu: location.mtu.cast_unsigned(),
            fwmark: location.fwmark as u32,
            // Set by callers that compiled the location's firewall policy.
            firewall: None,
        }
    }
}

#[cfg(test)]
mod posture_tests {
    use super::*;

    #[test]
    fn posture_refusal_carries_its_code() {
        let status = posture_rejected_status(&["disk encryption is required".into()]);
        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(is_posture_rejected(&status));
        let error = CoreError::from(status);
        assert_eq!(error.code(), CoreErrorCode::PostureRejected);
        assert_eq!(
            error.message,
            "Device posture check failed: disk encryption is required"
        );

        let other = CoreError::from(Status::permission_denied("device is not assigned"));
        assert_eq!(other.code(), CoreErrorCode::Unspecified);
    }

    #[test]
    fn posture_refusal_is_bounded() {
        let long = vec!["é".repeat(400); 10];
        let status = posture_rejected_status(&long);
        assert!(status.message().len() <= 1024);
        assert!(status.message().ends_with("..."));
    }
}
