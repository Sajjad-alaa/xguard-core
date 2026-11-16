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
/// OpenID-based MFA needs an external identity provider integration and FIDO2
/// VPN MFA needs the desktop FIDO2 module; neither is implemented in XGuard.
#[must_use]
pub const fn is_mfa_method_supported(method: VpnClientMfaMethod) -> bool {
    !matches!(method, VpnClientMfaMethod::Oidc | VpnClientMfaMethod::Fido2)
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

/// Service locations (pre-logon / always-on tunnels) need the desktop client's
/// service-location module, which XGuard does not include. Such locations are
/// skipped so no client is handed a configuration it cannot honour.
#[must_use]
pub fn is_service_location(location: &WireguardNetwork<Id>) -> bool {
    location.service_location_mode != ServiceLocationMode::Disabled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_methods_are_filtered() {
        assert!(is_mfa_method_supported(VpnClientMfaMethod::Totp));
        assert!(is_mfa_method_supported(VpnClientMfaMethod::Email));
        assert!(is_mfa_method_supported(VpnClientMfaMethod::Biometric));
        assert!(is_mfa_method_supported(VpnClientMfaMethod::MobileApprove));
        assert!(!is_mfa_method_supported(VpnClientMfaMethod::Oidc));
        assert!(!is_mfa_method_supported(VpnClientMfaMethod::Fido2));
        assert!(!supported_mfa_setup_methods().contains(&VpnClientMfaMethod::Fido2));
        assert!(!supported_mfa_authorize_methods().contains(&VpnClientMfaMethod::Oidc));
    }
}
