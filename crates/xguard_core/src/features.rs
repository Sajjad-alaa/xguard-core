//! Feature availability for XGuard.
//!
//! XGuard is AGPL-only: there are no license keys or tiers. Every feature that is
//! implemented in this codebase is always available. The helpers below only
//! describe features that XGuard does not implement (they were part of the
//! Defguard enterprise edition, which is not included).

use xguard_common::db::models::{WireguardNetwork, vpn_client_session::VpnClientMfaMethod};
use xguard_common::db::{Id, models::wireguard::ServiceLocationMode};

/// Whether a VPN client MFA method can be used.
///
/// Every method is implemented: OpenID MFA runs through Edge with the external provider (see
/// [`crate::sso::edge`]), whether a provider is configured is checked separately; FIDO2 security
/// keys are verified by [`crate::fido2`].
#[must_use]
pub const fn is_mfa_method_supported(method: VpnClientMfaMethod) -> bool {
    matches!(
        method,
        VpnClientMfaMethod::Totp
            | VpnClientMfaMethod::Email
            | VpnClientMfaMethod::Oidc
            | VpnClientMfaMethod::Biometric
            | VpnClientMfaMethod::MobileApprove
            | VpnClientMfaMethod::Fido2
    )
}

/// MFA methods a client may set up.
#[must_use]
pub fn supported_mfa_setup_methods() -> Vec<VpnClientMfaMethod> {
    VpnClientMfaMethod::CONFIG_SETUP
        .into_iter()
        .filter(|method| is_mfa_method_supported(*method))
        .collect()
}

/// MFA methods a client may use to authorize configuration changes.
#[must_use]
pub fn supported_mfa_authorize_methods() -> Vec<VpnClientMfaMethod> {
    VpnClientMfaMethod::CONFIG_AUTHORIZE
        .into_iter()
        .filter(|method| is_mfa_method_supported(*method))
        .collect()
}

/// Whether a location is a service location (a pre-logon or always-on tunnel that the desktop
/// client's background service keeps up without a user session).
#[must_use]
pub fn is_service_location(location: &WireguardNetwork<Id>) -> bool {
    location.service_location_mode != ServiceLocationMode::Disabled
}

/// Whether a service location cannot be served: it has location MFA, which needs a user to
/// authorize each session. The API refuses this combination; this guards rows written before
/// (or around) that check, so no client is handed a configuration it cannot honour and the
/// gateway never gets peers for it.
#[must_use]
pub fn is_unservable_service_location(location: &WireguardNetwork<Id>) -> bool {
    is_service_location(location) && location.mfa_enabled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_methods_are_supported() {
        assert!(is_mfa_method_supported(VpnClientMfaMethod::Totp));
        assert!(is_mfa_method_supported(VpnClientMfaMethod::Email));
        assert!(is_mfa_method_supported(VpnClientMfaMethod::Biometric));
        assert!(is_mfa_method_supported(VpnClientMfaMethod::MobileApprove));
        assert!(is_mfa_method_supported(VpnClientMfaMethod::Oidc));
        assert!(is_mfa_method_supported(VpnClientMfaMethod::Fido2));
        assert!(supported_mfa_setup_methods().contains(&VpnClientMfaMethod::Fido2));
        assert!(!supported_mfa_setup_methods().contains(&VpnClientMfaMethod::Oidc));
        assert!(supported_mfa_authorize_methods().contains(&VpnClientMfaMethod::Oidc));
        assert!(supported_mfa_authorize_methods().contains(&VpnClientMfaMethod::Fido2));
    }

    #[test]
    fn service_locations_with_mfa_are_unservable() {
        let mut location = WireguardNetwork::default().with_id(1);
        assert!(!is_service_location(&location));
        assert!(!is_unservable_service_location(&location));
        location.service_location_mode = ServiceLocationMode::AlwaysOn;
        assert!(is_service_location(&location));
        assert!(!is_unservable_service_location(&location));
        location.mfa_enabled = true;
        assert!(is_unservable_service_location(&location));
    }
}
