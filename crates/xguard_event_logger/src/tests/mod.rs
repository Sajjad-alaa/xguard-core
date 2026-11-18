use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;
use ipnetwork::IpNetwork;
use serde_json::Value;
use strum::EnumCount;
use xguard_common::db::{
    Id, NoId,
    models::{
        AuthenticationKey, AuthenticationKeyType, Device, DeviceType, MFAMethod, Settings, User,
        WebAuthn, WireguardNetwork,
        gateway::Gateway,
        group::Group,
        mfa_flow::{LocationMfaFlowAssignmentSnapshot, MfaFlow, MfaFlowSnapshot, MfaFlowStep},
        oauth2client::OAuth2Client,
        proxy::Proxy,
        settings::set_settings,
        vpn_client_mfa_session::{MfaAttribution, Step, StepsSnapshot},
        vpn_client_session::VpnClientMfaMethod,
        webauthn::{AuthenticatorKind, RegistrationSource},
        wireguard::ServiceLocationMode,
    },
};
use xguard_core::{
    db::models::{
        activity_log::{ActivityLogEvent, ActivityLogModule, EventType},
        webhook::WebHook,
    },
    events::{
        ApiEventType, BidiRequestContext, BidiStreamEvent, BidiStreamEventType,
        DesktopClientMfaEvent, DirectorySyncEvent, DirectorySyncEventType,
        EnrollmentEvent as CoreEnrollmentEvent, GatewayConnectionEvent, LdapSyncEventType,
        PasswordResetEvent, ProxyConnectionEvent,
    },
};
use xguard_session_manager::events::SessionManagerEventType;

use crate::{
    map_to_activity_log_event,
    message::{Event, EventContext, EventLoggerMessage},
};

fn sample_device() -> Device<Id> {
    Device::new(
        "vpn-device".to_owned(),
        "pubkey".to_owned(),
        1,
        DeviceType::User,
        None,
        true,
    )
    .with_id(20)
}

fn sample_location() -> WireguardNetwork<Id> {
    WireguardNetwork::new(
        "vpn-location".to_owned(),
        51820,
        "vpn.example.com".to_owned(),
        None,
        [IpNetwork::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).unwrap()],
        true,
        false,
        false,
        false,
        true, // mfa_enabled
        ServiceLocationMode::Disabled,
    )
    .set_address([IpNetwork::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24).unwrap()])
    .expect("sample location address should be valid")
    .with_id(10)
}

fn sample_user() -> User<Id> {
    User::new("testuser", Some("pass"), "Last", "First", "e@e", None).with_id(1)
}

fn sample_group() -> Group<Id> {
    Group {
        id: 1,
        name: "testgroup".into(),
        is_admin: false,
    }
}

#[test]
fn test_activity_log_event_serialization_supports_null_ip() {
    let event = ActivityLogEvent {
        id: NoId,
        timestamp: Utc::now().naive_utc(),
        user_id: Some(1),
        username: "admin".to_owned(),
        location: None,
        ip: None,
        event: EventType::UserLogin,
        module: ActivityLogModule::XGuard,
        device: "test-device".to_owned(),
        description: None,
        metadata: None,
    };

    let serialized = serde_json::to_value(event).expect("activity log event should serialize");

    assert_eq!(serialized.get("ip"), Some(&Value::Null));
}

fn sample_bidi_context() -> BidiRequestContext {
    BidiRequestContext::new(
        1,
        "alice".to_owned(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "desktop-app".to_owned(),
    )
}

#[test]
fn test_maps_disconnect_bidi_events_from_mfa_sessions_to_mfa_disconnect_logger_events() {
    let event = BidiStreamEvent {
        context: sample_bidi_context(),
        event: BidiStreamEventType::DesktopClientMfa(Box::new(
            DesktopClientMfaEvent::Disconnected {
                location: sample_location(),
                device: sample_device(),
                is_mfa_session: true,
            },
        )),
    };

    let message = EventLoggerMessage::from_bidi_event(event);

    match message.event {
        Event::Bidi(BidiStreamEventType::DesktopClientMfa(event)) => match *event {
            DesktopClientMfaEvent::Disconnected {
                location,
                device,
                is_mfa_session,
            } => {
                assert!(is_mfa_session);
                assert_eq!(location.id, sample_location().id);
                assert_eq!(device.id, sample_device().id);
            }
            _ => panic!("expected disconnect event"),
        },
        _ => panic!("expected bidi event"),
    }
}

#[test]
fn test_maps_disconnect_bidi_events_from_non_mfa_sessions_to_standard_disconnect_logger_events() {
    let event = BidiStreamEvent {
        context: sample_bidi_context(),
        event: BidiStreamEventType::DesktopClientMfa(Box::new(
            DesktopClientMfaEvent::Disconnected {
                location: sample_location(),
                device: sample_device(),
                is_mfa_session: false,
            },
        )),
    };

    let message = EventLoggerMessage::from_bidi_event(event);

    match message.event {
        Event::Bidi(BidiStreamEventType::DesktopClientMfa(event)) => match *event {
            DesktopClientMfaEvent::Disconnected {
                location,
                device,
                is_mfa_session,
            } => {
                assert!(!is_mfa_session);
                assert_eq!(location.id, sample_location().id);
                assert_eq!(device.id, sample_device().id);
            }
            _ => panic!("expected disconnect event"),
        },
        _ => panic!("expected bidi event"),
    }
}

#[test]
fn test_maps_replaced_bidi_events_from_non_mfa_sessions_to_standard_superseded_logger_events() {
    let event = BidiStreamEvent {
        context: sample_bidi_context(),
        event: BidiStreamEventType::DesktopClientMfa(Box::new(
            DesktopClientMfaEvent::SessionSuperseded {
                location: sample_location(),
                device: sample_device(),
                is_mfa_session: false,
            },
        )),
    };

    let result = map_to_activity_log_event(EventLoggerMessage::from_bidi_event(event));

    assert_eq!(result.event, EventType::VpnClientSessionSuperseded);
    assert_eq!(result.module, ActivityLogModule::Vpn);
}

/// A superseded in-progress MFA login is not a superseded VPN session: nothing was authorized,
/// so the entry must not claim a session existed or that an authorization replaced it.
#[test]
fn test_maps_superseded_mfa_login_to_its_own_event_and_description() {
    let event = BidiStreamEvent {
        context: sample_bidi_context(),
        event: BidiStreamEventType::DesktopClientMfa(Box::new(
            DesktopClientMfaEvent::MfaLoginSuperseded {
                location: sample_location(),
                device: sample_device(),
            },
        )),
    };

    let result = map_to_activity_log_event(EventLoggerMessage::from_bidi_event(event));

    assert_eq!(result.event, EventType::VpnClientMfaLoginSuperseded);
    assert_eq!(result.module, ActivityLogModule::Vpn);

    let description = result.description.expect("expected a description");
    assert!(
        description.contains("MFA login"),
        "description should name the login, got: {description}"
    );
    assert!(
        !description.contains("VPN session"),
        "description must not claim a VPN session was superseded, got: {description}"
    );
    assert!(
        !description.contains("authorization"),
        "description must not claim an authorization occurred, got: {description}"
    );
}

// Helper struct for testing mapping of all existing events
// to activity log entries
struct EventTestCase {
    name: &'static str,
    message: EventLoggerMessage,
    event_type: EventType,
    module: ActivityLogModule,
    description_contains: Option<&'static str>,
}

fn test_context() -> EventContext {
    EventContext {
        timestamp: Utc::now().naive_utc(),
        user_id: Some(1),
        username: "admin".into(),
        location: None,
        ip: None,
        device: "test".into(),
    }
}

fn sample_posture() -> xguard_core::posture::policy::ApiDevicePosture {
    xguard_core::posture::policy::ApiDevicePosture {
        id: 1,
        name: "Laptops".into(),
        description: None,
        min_desktop_client_version: Some("2.2.0".into()),
        min_mobile_client_version: None,
        allow_prerelease_client: false,
        os_rules: Vec::new(),
        locations: vec![1],
    }
}

fn api_message(event: ApiEventType) -> EventLoggerMessage {
    EventLoggerMessage {
        context: test_context(),
        event: Event::Api(event),
    }
}

fn api_event_cases() -> Vec<EventTestCase> {
    let user = User::new("testuser", Some("pass"), "Last", "First", "e@e", None).with_id(1);
    let device = Device {
        id: 2,
        name: "d2".into(),
        wireguard_pubkey: "pk".into(),
        user_id: 1,
        created: Utc::now().naive_utc(),
        device_type: DeviceType::User,
        description: None,
        configured: true,
    };
    let location = sample_location();
    let timestamp = Utc::now().naive_utc();
    let proxy = Proxy {
        id: 1,
        name: "px".into(),
        address: "a".into(),
        port: 1,
        connected_at: None,
        disconnected_at: None,
        version: None,
        enabled: true,
        certificate_serial: None,
        certificate_expiry: None,
        modified_at: timestamp,
        modified_by: "admin".into(),
        core_client_cert_der: None,
        core_client_cert_key_der: None,
        core_client_cert_expiry: None,
    };
    let proxy2 = Proxy {
        id: 2,
        name: "px2".into(),
        ..proxy.clone()
    };
    let gateway = Gateway {
        id: 1,
        location_id: 10,
        name: "gw".into(),
        address: "a".into(),
        port: 1,
        connected_at: None,
        disconnected_at: None,
        certificate_serial: None,
        certificate_expiry: None,
        version: None,
        enabled: true,
        modified_at: timestamp,
        modified_by: "admin".into(),
        core_client_cert_der: None,
        core_client_cert_key_der: None,
        core_client_cert_expiry: None,
    };
    let gateway2 = Gateway {
        id: 2,
        ..gateway.clone()
    };
    let firewall_rule = xguard_common::firewall::FirewallRule {
        id: 1,
        name: "web".into(),
        description: String::new(),
        enabled: true,
        priority: 1000,
        action: xguard_common::firewall::FirewallRuleAction::Allow,
        all_locations: true,
        locations: Vec::new(),
        any_source: true,
        all_users: false,
        all_network_devices: false,
        users: Vec::new(),
        groups: Vec::new(),
        devices: Vec::new(),
        any_destination: true,
        destinations: Vec::new(),
        protocols: Vec::new(),
        ports: Vec::new(),
        expires_at: None,
        created_at: chrono::NaiveDateTime::default(),
        updated_at: chrono::NaiveDateTime::default(),
    };
    let provider = xguard_core::sso::provider::OpenIdProvider {
        id: 1,
        kind: xguard_core::sso::provider::ProviderKind::Google,
        issuer: "https://accounts.google.com".into(),
        client_id: "client".into(),
        enabled: true,
        display_name: None,
        disable_password_management: false,
        client_secret_set: true,
        directory_sync: Default::default(),
    };
    let log_stream = xguard_core::log_stream::ActivityLogStream {
        id: 1,
        name: "siem".into(),
        stream_type: xguard_core::log_stream::StreamType::VectorHttp,
        url: "https://logs.example.org/".into(),
        username: None,
        cert: None,
        password_set: false,
    };
    let api_token = xguard_common::db::models::ApiToken {
        id: 1,
        user_id: 1,
        name: "ci".into(),
        hint: "xgt_AbCd".into(),
        created_at: chrono::NaiveDateTime::default(),
        expires_at: None,
        last_used_at: None,
        last_used_ip: None,
        read_only: true,
    };
    let snat_binding = xguard_common::firewall::SnatBinding {
        id: 1,
        user_id: 1,
        location_id: 1,
        public_ip: std::net::IpAddr::from([203, 0, 113, 7]),
    };
    let webhook = WebHook {
        id: 1,
        url: "http://x".into(),
        description: String::new(),
        token: "t".into(),
        enabled: true,
        on_user_created: false,
        on_user_deleted: false,
        on_user_modified: false,
        on_hwkey_provision: false,
    };
    let webhook2 = WebHook {
        id: 2,
        ..webhook.clone()
    };
    let auth_key = AuthenticationKey {
        id: 1,
        yubikey_id: None,
        name: Some("mykey".into()),
        user_id: 1,
        key: "kk".into(),
        key_type: AuthenticationKeyType::Ssh,
    };
    let oauth_app = OAuth2Client {
        id: 1,
        client_id: "cid".into(),
        client_secret: "cs".into(),
        redirect_uri: Vec::new(),
        scope: Vec::new(),
        name: "app".into(),
        enabled: true,
    };
    let group1 = Group {
        id: 1,
        name: "g1".into(),
        is_admin: false,
    };
    let group2 = Group {
        id: 2,
        name: "g2".into(),
        is_admin: true,
    };
    let admin_group = Group {
        id: 3,
        name: "admin".into(),
        is_admin: true,
    };
    let webauthn_key = WebAuthn {
        id: 1,
        user_id: 1,
        name: "k".into(),
        passkey: Vec::new(),
        authenticator_name: None,
        authenticator_kind: AuthenticatorKind::Unknown,
        registration_source: RegistrationSource::Core,
        attestation_aaguid: None,
        attestation_valid_until: None,
        attestation_chain: None,
        attestation_chain_sha256: None,
        registered_at: None,
    };

    let mfa_flow_snapshot = MfaFlowSnapshot {
        flow: MfaFlow {
            id: 1,
            title: "Strong MFA".into(),
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        },
        steps: vec![MfaFlowStep {
            id: 1,
            flow_id: 1,
            position: 0,
            methods: [VpnClientMfaMethod::Totp].into_iter().collect(),
        }],
    };
    let mfa_flow_snapshot2 = MfaFlowSnapshot {
        flow: MfaFlow {
            id: 1,
            title: "Stronger MFA".into(),
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        },
        steps: vec![
            MfaFlowStep {
                id: 1,
                flow_id: 1,
                position: 0,
                methods: [VpnClientMfaMethod::Totp].into_iter().collect(),
            },
            MfaFlowStep {
                id: 2,
                flow_id: 1,
                position: 1,
                methods: [VpnClientMfaMethod::Email].into_iter().collect(),
            },
        ],
    };

    let cases = vec![
        EventTestCase {
            name: "UserLogin",
            message: api_message(ApiEventType::UserLogin),
            event_type: EventType::UserLogin,
            module: ActivityLogModule::XGuard,
            description_contains: None,
        },
        EventTestCase {
            name: "UserLoginFailed",
            message: api_message(ApiEventType::UserLoginFailed {
                message: "bad".into(),
            }),
            event_type: EventType::UserLoginFailed,
            module: ActivityLogModule::XGuard,
            description_contains: Some("bad"),
        },
        EventTestCase {
            name: "UserLogout",
            message: api_message(ApiEventType::UserLogout),
            event_type: EventType::UserLogout,
            module: ActivityLogModule::XGuard,
            description_contains: None,
        },
        EventTestCase {
            name: "UserMfaLogin",
            message: api_message(ApiEventType::UserMfaLogin {
                mfa_method: MFAMethod::OneTimePassword,
            }),
            event_type: EventType::UserMfaLogin,
            module: ActivityLogModule::XGuard,
            description_contains: Some("TOTP"),
        },
        EventTestCase {
            name: "UserMfaLoginFailed",
            message: api_message(ApiEventType::UserMfaLoginFailed {
                mfa_method: MFAMethod::OneTimePassword,
                message: "err".into(),
            }),
            event_type: EventType::UserMfaLoginFailed,
            module: ActivityLogModule::XGuard,
            description_contains: Some("err"),
        },
        EventTestCase {
            name: "RecoveryCodeLoginFailed",
            message: api_message(ApiEventType::RecoveryCodeLoginFailed),
            event_type: EventType::UserMfaLoginFailed,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Recovery"),
        },
        EventTestCase {
            name: "RecoveryCodeUsed",
            message: api_message(ApiEventType::RecoveryCodeUsed),
            event_type: EventType::RecoveryCodeUsed,
            module: ActivityLogModule::XGuard,
            description_contains: None,
        },
        EventTestCase {
            name: "PasswordChangedByAdmin",
            message: api_message(ApiEventType::PasswordChangedByAdmin { user: user.clone() }),
            event_type: EventType::PasswordChangedByAdmin,
            module: ActivityLogModule::XGuard,
            description_contains: Some("admin"),
        },
        EventTestCase {
            name: "PasswordChanged",
            message: api_message(ApiEventType::PasswordChanged),
            event_type: EventType::PasswordChanged,
            module: ActivityLogModule::XGuard,
            description_contains: None,
        },
        EventTestCase {
            name: "PasswordReset",
            message: api_message(ApiEventType::PasswordReset { user: user.clone() }),
            event_type: EventType::PasswordReset,
            module: ActivityLogModule::XGuard,
            description_contains: Some("reset"),
        },
        EventTestCase {
            name: "MfaDisabled",
            message: api_message(ApiEventType::MfaDisabled),
            event_type: EventType::MfaDisabled,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Disabled"),
        },
        EventTestCase {
            name: "UserMfaDisabled",
            message: api_message(ApiEventType::UserMfaDisabled { user: user.clone() }),
            event_type: EventType::UserMfaDisabled,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Disabled"),
        },
        EventTestCase {
            name: "MfaTotpDisabled",
            message: api_message(ApiEventType::MfaTotpDisabled),
            event_type: EventType::MfaTotpDisabled,
            module: ActivityLogModule::XGuard,
            description_contains: Some("TOTP"),
        },
        EventTestCase {
            name: "MfaTotpEnabled",
            message: api_message(ApiEventType::MfaTotpEnabled),
            event_type: EventType::MfaTotpEnabled,
            module: ActivityLogModule::XGuard,
            description_contains: Some("TOTP"),
        },
        EventTestCase {
            name: "MfaEmailDisabled",
            message: api_message(ApiEventType::MfaEmailDisabled),
            event_type: EventType::MfaEmailDisabled,
            module: ActivityLogModule::XGuard,
            description_contains: Some("email"),
        },
        EventTestCase {
            name: "MfaEmailEnabled",
            message: api_message(ApiEventType::MfaEmailEnabled),
            event_type: EventType::MfaEmailEnabled,
            module: ActivityLogModule::XGuard,
            description_contains: Some("email"),
        },
        EventTestCase {
            name: "MfaSecurityKeyAdded",
            message: api_message(ApiEventType::MfaSecurityKeyAdded {
                key: webauthn_key.clone(),
            }),
            event_type: EventType::MfaSecurityKeyAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "MfaSecurityKeyRemoved",
            message: api_message(ApiEventType::MfaSecurityKeyRemoved { key: webauthn_key }),
            event_type: EventType::MfaSecurityKeyRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed"),
        },
        EventTestCase {
            name: "UserAdded",
            message: api_message(ApiEventType::UserAdded { user: user.clone() }),
            event_type: EventType::UserAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "UserImportBlocked",
            message: api_message(ApiEventType::UserImportBlocked {
                username: "testuser".to_owned(),
                email: "testuser@example.com".to_owned(),
                user_count: 10,
                limit: 10,
            }),
            event_type: EventType::UserImportBlocked,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Blocked"),
        },
        EventTestCase {
            name: "UserRemoved",
            message: api_message(ApiEventType::UserRemoved { user: user.clone() }),
            event_type: EventType::UserRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed"),
        },
        EventTestCase {
            name: "UserModified",
            message: api_message(ApiEventType::UserModified {
                before: user.clone(),
                after: user.clone(),
            }),
            event_type: EventType::UserModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Modified"),
        },
        EventTestCase {
            name: "UserGroupsModified",
            message: api_message(ApiEventType::UserGroupsModified {
                user: user.clone(),
                before: Vec::new(),
                after: Vec::new(),
            }),
            event_type: EventType::UserGroupsModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("modified"),
        },
        EventTestCase {
            name: "UserEnabled",
            message: api_message(ApiEventType::UserEnabled { user: user.clone() }),
            event_type: EventType::UserEnabled,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Enabled"),
        },
        EventTestCase {
            name: "UserDisabled",
            message: api_message(ApiEventType::UserDisabled { user: user.clone() }),
            event_type: EventType::UserDisabled,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Disabled"),
        },
        EventTestCase {
            name: "UserDeviceAdded",
            message: api_message(ApiEventType::UserDeviceAdded {
                owner: user.clone(),
                device: device.clone(),
            }),
            event_type: EventType::DeviceAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "UserDeviceRemoved",
            message: api_message(ApiEventType::UserDeviceRemoved {
                owner: user.clone(),
                device: device.clone(),
            }),
            event_type: EventType::DeviceRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed"),
        },
        EventTestCase {
            name: "UserDeviceModified",
            message: api_message(ApiEventType::UserDeviceModified {
                owner: user.clone(),
                before: device.clone(),
                after: device.clone(),
            }),
            event_type: EventType::DeviceModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Modified"),
        },
        EventTestCase {
            name: "NetworkDeviceAdded",
            message: api_message(ApiEventType::NetworkDeviceAdded {
                device: device.clone(),
                location: location.clone(),
            }),
            event_type: EventType::NetworkDeviceAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "NetworkDeviceRemoved",
            message: api_message(ApiEventType::NetworkDeviceRemoved {
                device: device.clone(),
                location: location.clone(),
            }),
            event_type: EventType::NetworkDeviceRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed"),
        },
        EventTestCase {
            name: "NetworkDeviceModified",
            message: api_message(ApiEventType::NetworkDeviceModified {
                before: device.clone(),
                after: device.clone(),
                location: location.clone(),
            }),
            event_type: EventType::NetworkDeviceModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Modified"),
        },
        EventTestCase {
            name: "VpnLocationAdded",
            message: api_message(ApiEventType::VpnLocationAdded {
                location: location.clone(),
            }),
            event_type: EventType::VpnLocationAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "VpnLocationRemoved",
            message: api_message(ApiEventType::VpnLocationRemoved {
                location: location.clone(),
            }),
            event_type: EventType::VpnLocationRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed"),
        },
        EventTestCase {
            name: "VpnLocationModified",
            message: api_message(ApiEventType::VpnLocationModified {
                before: location.clone(),
                after: location.clone(),
            }),
            event_type: EventType::VpnLocationModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("modified"),
        },
        EventTestCase {
            name: "OpenIdAppAdded",
            message: api_message(ApiEventType::OpenIdAppAdded {
                app: oauth_app.clone(),
            }),
            event_type: EventType::OpenIdAppAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "OpenIdAppRemoved",
            message: api_message(ApiEventType::OpenIdAppRemoved {
                app: oauth_app.clone(),
            }),
            event_type: EventType::OpenIdAppRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed"),
        },
        EventTestCase {
            name: "OpenIdAppModified",
            message: api_message(ApiEventType::OpenIdAppModified {
                before: oauth_app.clone(),
                after: oauth_app.clone(),
            }),
            event_type: EventType::OpenIdAppModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Modified"),
        },
        EventTestCase {
            name: "OpenIdAppStateChanged",
            message: api_message(ApiEventType::OpenIdAppStateChanged {
                app: oauth_app,
                enabled: false,
            }),
            event_type: EventType::OpenIdAppStateChanged,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Disabled"),
        },
        EventTestCase {
            name: "SettingsUpdated",
            message: api_message(ApiEventType::SettingsUpdated {
                before: Settings::default(),
                after: Settings::default(),
            }),
            event_type: EventType::SettingsUpdated,
            module: ActivityLogModule::XGuard,
            description_contains: None,
        },
        EventTestCase {
            name: "SettingsUpdatedPartial",
            message: api_message(ApiEventType::SettingsUpdatedPartial {
                before: Settings::default(),
                after: Settings::default(),
            }),
            event_type: EventType::SettingsUpdatedPartial,
            module: ActivityLogModule::XGuard,
            description_contains: None,
        },
        EventTestCase {
            name: "SettingsDefaultBrandingRestored",
            message: api_message(ApiEventType::SettingsDefaultBrandingRestored),
            event_type: EventType::SettingsDefaultBrandingRestored,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Restored"),
        },
        EventTestCase {
            name: "GroupsBulkAssigned",
            message: api_message(ApiEventType::GroupsBulkAssigned {
                users: vec![user.clone()],
                groups: vec![group1.clone()],
            }),
            event_type: EventType::GroupsBulkAssigned,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Assigned"),
        },
        EventTestCase {
            name: "GroupAdded",
            message: api_message(ApiEventType::GroupAdded {
                group: group1.clone(),
            }),
            event_type: EventType::GroupAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "GroupModified",
            message: api_message(ApiEventType::GroupModified {
                before: group1.clone(),
                after: group2,
            }),
            event_type: EventType::GroupModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Modified"),
        },
        EventTestCase {
            name: "GroupRemoved",
            message: api_message(ApiEventType::GroupRemoved { group: group1 }),
            event_type: EventType::GroupRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed"),
        },
        EventTestCase {
            name: "GroupMemberAdded",
            message: api_message(ApiEventType::GroupMemberAdded {
                group: admin_group.clone(),
                user: user.clone(),
            }),
            event_type: EventType::GroupMemberAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "GroupMemberRemoved",
            message: api_message(ApiEventType::GroupMemberRemoved {
                group: admin_group.clone(),
                user: user.clone(),
            }),
            event_type: EventType::GroupMemberRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed"),
        },
        EventTestCase {
            name: "GroupMembersModified",
            message: api_message(ApiEventType::GroupMembersModified {
                group: admin_group,
                added: vec![user.clone()],
                removed: Vec::new(),
            }),
            event_type: EventType::GroupMembersModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "WebHookAdded",
            message: api_message(ApiEventType::WebHookAdded {
                webhook: webhook.clone(),
            }),
            event_type: EventType::WebHookAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "WebHookModified",
            message: api_message(ApiEventType::WebHookModified {
                before: webhook.clone(),
                after: webhook2,
            }),
            event_type: EventType::WebHookModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Modified"),
        },
        EventTestCase {
            name: "WebHookRemoved",
            message: api_message(ApiEventType::WebHookRemoved {
                webhook: webhook.clone(),
            }),
            event_type: EventType::WebHookRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed"),
        },
        EventTestCase {
            name: "WebHookStateChanged",
            message: api_message(ApiEventType::WebHookStateChanged {
                webhook,
                enabled: false,
            }),
            event_type: EventType::WebHookStateChanged,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Disabled"),
        },
        EventTestCase {
            name: "OpenIdProviderModified",
            message: api_message(ApiEventType::OpenIdProviderModified {
                provider: provider.clone(),
            }),
            event_type: EventType::OpenIdProviderModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("https://accounts.google.com"),
        },
        EventTestCase {
            name: "OpenIdProviderRemoved",
            message: api_message(ApiEventType::OpenIdProviderRemoved { provider }),
            event_type: EventType::OpenIdProviderRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed the OpenID provider"),
        },
        EventTestCase {
            name: "DirectorySyncTested",
            message: api_message(ApiEventType::DirectorySyncTested {
                provider: "Okta".into(),
                success: true,
            }),
            event_type: EventType::DirectorySyncTested,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Tested the directory sync with Okta: connected"),
        },
        EventTestCase {
            name: "DirectorySyncStarted",
            message: api_message(ApiEventType::DirectorySyncStarted {
                provider: "Okta".into(),
                dry_run: true,
            }),
            event_type: EventType::DirectorySyncStarted,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Previewed a directory sync with Okta"),
        },
        EventTestCase {
            name: "ActivityLogStreamCreated",
            message: api_message(ApiEventType::ActivityLogStreamCreated {
                stream: log_stream.clone(),
            }),
            event_type: EventType::ActivityLogStreamCreated,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added activity log stream siem"),
        },
        EventTestCase {
            name: "ActivityLogStreamModified",
            message: api_message(ApiEventType::ActivityLogStreamModified {
                before: log_stream.clone(),
                after: log_stream.clone(),
            }),
            event_type: EventType::ActivityLogStreamModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Modified activity log stream siem"),
        },
        EventTestCase {
            name: "ActivityLogStreamRemoved",
            message: api_message(ApiEventType::ActivityLogStreamRemoved { stream: log_stream }),
            event_type: EventType::ActivityLogStreamRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed activity log stream siem"),
        },
        EventTestCase {
            name: "ApiTokenAdded",
            message: api_message(ApiEventType::ApiTokenAdded {
                owner: user.clone(),
                token: api_token.clone(),
            }),
            event_type: EventType::ApiTokenAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added API token ci (xgt_AbCd)"),
        },
        EventTestCase {
            name: "ApiTokenRemoved",
            message: api_message(ApiEventType::ApiTokenRemoved {
                owner: user.clone(),
                token: api_token.clone(),
            }),
            event_type: EventType::ApiTokenRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Revoked API token ci"),
        },
        EventTestCase {
            name: "ApiTokenRenamed",
            message: api_message(ApiEventType::ApiTokenRenamed {
                owner: user.clone(),
                token: api_token,
                old_name: "ci".into(),
                new_name: "deploy".into(),
            }),
            event_type: EventType::ApiTokenRenamed,
            module: ActivityLogModule::XGuard,
            description_contains: Some("from ci to deploy"),
        },
        EventTestCase {
            name: "FirewallRuleAdded",
            message: api_message(ApiEventType::FirewallRuleAdded {
                rule: firewall_rule.clone(),
            }),
            event_type: EventType::FirewallRuleAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added firewall rule web"),
        },
        EventTestCase {
            name: "FirewallRuleModified",
            message: api_message(ApiEventType::FirewallRuleModified {
                before: firewall_rule.clone(),
                after: firewall_rule.clone(),
            }),
            event_type: EventType::FirewallRuleModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Modified firewall rule web"),
        },
        EventTestCase {
            name: "FirewallRuleRemoved",
            message: api_message(ApiEventType::FirewallRuleRemoved {
                rule: firewall_rule,
            }),
            event_type: EventType::FirewallRuleRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed firewall rule web"),
        },
        EventTestCase {
            name: "UserSnatBindingAdded",
            message: api_message(ApiEventType::UserSnatBindingAdded {
                binding: snat_binding.clone(),
            }),
            event_type: EventType::UserSnatBindingAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added SNAT to 203.0.113.7"),
        },
        EventTestCase {
            name: "UserSnatBindingModified",
            message: api_message(ApiEventType::UserSnatBindingModified {
                before: snat_binding.clone(),
                after: snat_binding.clone(),
            }),
            event_type: EventType::UserSnatBindingModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Changed SNAT"),
        },
        EventTestCase {
            name: "UserSnatBindingRemoved",
            message: api_message(ApiEventType::UserSnatBindingRemoved {
                binding: snat_binding,
            }),
            event_type: EventType::UserSnatBindingRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed SNAT"),
        },
        EventTestCase {
            name: "AuthenticationKeyAdded",
            message: api_message(ApiEventType::AuthenticationKeyAdded {
                key: auth_key.clone(),
            }),
            event_type: EventType::AuthenticationKeyAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "AuthenticationKeyRemoved",
            message: api_message(ApiEventType::AuthenticationKeyRemoved {
                key: auth_key.clone(),
            }),
            event_type: EventType::AuthenticationKeyRemoved,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Removed"),
        },
        EventTestCase {
            name: "AuthenticationKeyRenamed",
            message: api_message(ApiEventType::AuthenticationKeyRenamed {
                key: auth_key,
                old_name: Some("old".into()),
                new_name: Some("new".into()),
            }),
            event_type: EventType::AuthenticationKeyRenamed,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Renamed"),
        },
        EventTestCase {
            name: "EnrollmentTokenAdded",
            message: api_message(ApiEventType::EnrollmentTokenAdded { user: user.clone() }),
            event_type: EventType::EnrollmentTokenAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "ClientConfigurationTokenAdded",
            message: api_message(ApiEventType::ClientConfigurationTokenAdded {
                user: user.clone(),
            }),
            event_type: EventType::ClientConfigurationTokenAdded,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "ProvisioningFileCreated",
            message: api_message(ApiEventType::ProvisioningFileCreated {
                user: user.clone(),
                expires_at: chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap(),
            }),
            event_type: EventType::ProvisioningFileCreated,
            module: ActivityLogModule::XGuard,
            description_contains: Some("provisioning file"),
        },
        EventTestCase {
            name: "ProxyModified",
            message: api_message(ApiEventType::ProxyModified {
                before: proxy.clone(),
                after: proxy2,
            }),
            event_type: EventType::ProxyModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Modified"),
        },
        EventTestCase {
            name: "ProxyDeleted",
            message: api_message(ApiEventType::ProxyDeleted { proxy }),
            event_type: EventType::ProxyDeleted,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Deleted"),
        },
        EventTestCase {
            name: "GatewayModified",
            message: api_message(ApiEventType::GatewayModified {
                before: gateway.clone(),
                after: gateway2,
            }),
            event_type: EventType::GatewayModified,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Modified"),
        },
        EventTestCase {
            name: "GatewayDeleted",
            message: api_message(ApiEventType::GatewayDeleted { gateway }),
            event_type: EventType::GatewayDeleted,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Deleted"),
        },
        EventTestCase {
            name: "MfaFlowCreated",
            message: api_message(ApiEventType::MfaFlowCreated {
                snapshot: mfa_flow_snapshot.clone(),
            }),
            event_type: EventType::MfaFlowCreated,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Created MFA flow"),
        },
        EventTestCase {
            name: "MfaFlowUpdated",
            message: api_message(ApiEventType::MfaFlowUpdated {
                before: mfa_flow_snapshot.clone(),
                after: mfa_flow_snapshot2.clone(),
            }),
            event_type: EventType::MfaFlowUpdated,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Updated MFA flow"),
        },
        EventTestCase {
            name: "MfaFlowDeleted",
            message: api_message(ApiEventType::MfaFlowDeleted {
                snapshot: mfa_flow_snapshot.clone(),
            }),
            event_type: EventType::MfaFlowDeleted,
            module: ActivityLogModule::XGuard,
            description_contains: Some("Deleted MFA flow"),
        },
        EventTestCase {
            name: "LocationMfaFlowsAssigned",
            message: api_message(ApiEventType::LocationMfaFlowsAssigned {
                location_id: location.id,
                location_name: location.name.clone(),
                assignments: vec![
                    LocationMfaFlowAssignmentSnapshot {
                        flow_id: 1,
                        position: 0,
                        is_default: false,
                        group_ids: vec![7],
                    },
                    LocationMfaFlowAssignmentSnapshot {
                        flow_id: 2,
                        position: 1,
                        is_default: true,
                        group_ids: Vec::new(),
                    },
                ],
            }),
            event_type: EventType::LocationMfaFlowsAssigned,
            module: ActivityLogModule::XGuard,
            description_contains: Some("MFA flow"),
        },
        EventTestCase {
            name: "ClientSettingsUpdated",
            message: api_message(ApiEventType::ClientSettingsUpdated {
                before: xguard_common::db::models::client_settings::ClientSettingsInfo::default(),
                after: xguard_common::db::models::client_settings::ClientSettingsInfo::default(),
            }),
            event_type: EventType::EnterpriseSettingsUpdated,
            module: ActivityLogModule::XGuard,
            description_contains: Some("client and device settings"),
        },
        EventTestCase {
            name: "LocationGroupMtusChanged",
            message: api_message(ApiEventType::LocationGroupMtusChanged {
                location_id: location.id,
                location_name: location.name.clone(),
                before: Vec::new(),
                after: vec![xguard_common::db::models::wireguard::GroupClientMtu {
                    client_mtu: 1280,
                    group_ids: vec![7],
                }],
            }),
            event_type: EventType::LocationGroupMtusChanged,
            module: ActivityLogModule::XGuard,
            description_contains: Some("group MTU"),
        },
        EventTestCase {
            name: "DevicePostureCreated",
            message: api_message(ApiEventType::DevicePostureCreated {
                posture: sample_posture(),
            }),
            event_type: EventType::DevicePostureCreated,
            module: ActivityLogModule::Posture,
            description_contains: Some("Created posture policy 'Laptops'"),
        },
        EventTestCase {
            name: "DevicePostureUpdated",
            message: api_message(ApiEventType::DevicePostureUpdated {
                before: sample_posture(),
                after: sample_posture(),
            }),
            event_type: EventType::DevicePostureUpdated,
            module: ActivityLogModule::Posture,
            description_contains: Some("Updated posture policy"),
        },
        EventTestCase {
            name: "DevicePostureDeleted",
            message: api_message(ApiEventType::DevicePostureDeleted {
                posture: sample_posture(),
            }),
            event_type: EventType::DevicePostureDeleted,
            module: ActivityLogModule::Posture,
            description_contains: Some("Deleted posture policy"),
        },
        EventTestCase {
            name: "DevicePostureDuplicated",
            message: api_message(ApiEventType::DevicePostureDuplicated {
                original: sample_posture(),
                duplicate: sample_posture(),
            }),
            event_type: EventType::DevicePostureDuplicated,
            module: ActivityLogModule::Posture,
            description_contains: Some("Duplicated posture policy"),
        },
        EventTestCase {
            name: "DevicePostureLocationsAssigned",
            message: api_message(ApiEventType::DevicePostureLocationsAssigned {
                posture_id: 1,
                posture_name: "Laptops".into(),
                location_ids: vec![1, 2],
            }),
            event_type: EventType::DevicePostureLocationsAssigned,
            module: ActivityLogModule::Posture,
            description_contains: Some("to 2 location(s)"),
        },
        EventTestCase {
            name: "LocationPosturesAssigned",
            message: api_message(ApiEventType::LocationPosturesAssigned {
                location_id: location.id,
                location_name: location.name.clone(),
                posture_ids: vec![1],
            }),
            event_type: EventType::LocationPosturesAssigned,
            module: ActivityLogModule::Posture,
            description_contains: Some("posture policy(ies)"),
        },
    ];

    assert_eq!(
        cases.len(),
        ApiEventType::COUNT,
        "missing test case for new ApiEventType variant"
    );
    cases
}

fn bidi_event_cases() -> Vec<EventTestCase> {
    let location = sample_location();
    let device = sample_device();

    fn bidi_msg(
        stream_event: BidiStreamEventType,
        loc: Option<WireguardNetwork<Id>>,
    ) -> EventLoggerMessage {
        EventLoggerMessage {
            context: EventContext::from_bidi_context(
                BidiRequestContext::new(
                    1,
                    "alice".into(),
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    "desktop-app".into(),
                ),
                loc,
            ),
            event: Event::Bidi(stream_event),
        }
    }

    let cases = vec![
        EventTestCase {
            name: "EnrollmentStarted",
            message: bidi_msg(
                BidiStreamEventType::Enrollment(Box::new(CoreEnrollmentEvent::EnrollmentStarted)),
                None,
            ),
            event_type: EventType::EnrollmentStarted,
            module: ActivityLogModule::Enrollment,
            description_contains: Some("started"),
        },
        EventTestCase {
            name: "EnrollmentCompleted",
            message: bidi_msg(
                BidiStreamEventType::Enrollment(Box::new(CoreEnrollmentEvent::EnrollmentCompleted)),
                None,
            ),
            event_type: EventType::EnrollmentCompleted,
            module: ActivityLogModule::Enrollment,
            description_contains: Some("completed"),
        },
        EventTestCase {
            name: "EnrollmentDeviceAdded",
            message: bidi_msg(
                BidiStreamEventType::Enrollment(Box::new(
                    CoreEnrollmentEvent::EnrollmentDeviceAdded {
                        device: device.clone(),
                    },
                )),
                None,
            ),
            event_type: EventType::EnrollmentDeviceAdded,
            module: ActivityLogModule::Enrollment,
            description_contains: Some("Added"),
        },
        EventTestCase {
            name: "PasswordResetRequested",
            message: bidi_msg(
                BidiStreamEventType::PasswordReset(Box::new(
                    PasswordResetEvent::PasswordResetRequested,
                )),
                None,
            ),
            event_type: EventType::PasswordResetRequested,
            module: ActivityLogModule::Enrollment,
            description_contains: None,
        },
        EventTestCase {
            name: "PasswordResetStarted",
            message: bidi_msg(
                BidiStreamEventType::PasswordReset(Box::new(
                    PasswordResetEvent::PasswordResetStarted,
                )),
                None,
            ),
            event_type: EventType::PasswordResetStarted,
            module: ActivityLogModule::Enrollment,
            description_contains: None,
        },
        EventTestCase {
            name: "PasswordResetCompleted",
            message: bidi_msg(
                BidiStreamEventType::PasswordReset(Box::new(
                    PasswordResetEvent::PasswordResetCompleted,
                )),
                None,
            ),
            event_type: EventType::PasswordResetCompleted,
            module: ActivityLogModule::Enrollment,
            description_contains: None,
        },
        EventTestCase {
            name: "ClientMfaSuccess",
            message: bidi_msg(
                BidiStreamEventType::DesktopClientMfa(Box::new(DesktopClientMfaEvent::Success {
                    location: location.clone(),
                    device: device.clone(),
                    attribution: MfaAttribution {
                        snapshot: StepsSnapshot {
                            flow_id: 1,
                            steps: vec![Step {
                                methods: [VpnClientMfaMethod::MobileApprove].into_iter().collect(),
                                satisfied: Some(VpnClientMfaMethod::MobileApprove),
                                mobile_auth_device_name: Some("pixel-7".to_owned()),
                            }],
                        },
                        flow_name: Some("flow".to_owned()),
                    },
                    mobile_auth_device_name: Some("pixel-7".to_owned()),
                })),
                Some(location.clone()),
            ),
            event_type: EventType::VpnClientMfaSuccess,
            module: ActivityLogModule::Vpn,
            // the approving device name is included in the description for mobile approve logins
            description_contains: Some("approved on pixel-7"),
        },
        EventTestCase {
            name: "ClientMfaFailed",
            message: bidi_msg(
                BidiStreamEventType::DesktopClientMfa(Box::new(DesktopClientMfaEvent::Failed {
                    location: location.clone(),
                    device: device.clone(),
                    method: xguard_core::events::ClientMFAMethod::Totp,
                    message: "bad".into(),
                })),
                Some(location.clone()),
            ),
            event_type: EventType::VpnClientMfaFailed,
            module: ActivityLogModule::Vpn,
            description_contains: Some("failed"),
        },
        EventTestCase {
            name: "ClientMfaAborted",
            message: bidi_msg(
                BidiStreamEventType::DesktopClientMfa(Box::new(DesktopClientMfaEvent::Aborted {
                    location: location.clone(),
                    device: device.clone(),
                    attribution: MfaAttribution {
                        snapshot: StepsSnapshot {
                            flow_id: 1,
                            steps: vec![Step {
                                methods: [VpnClientMfaMethod::Totp].into_iter().collect(),
                                satisfied: None,
                                mobile_auth_device_name: None,
                            }],
                        },
                        flow_name: Some("flow".to_owned()),
                    },
                })),
                Some(location.clone()),
            ),
            event_type: EventType::VpnClientMfaAborted,
            module: ActivityLogModule::Vpn,
            description_contains: Some("attempt limit reached"),
        },
        EventTestCase {
            name: "ClientMfaDisconnected",
            message: bidi_msg(
                BidiStreamEventType::DesktopClientMfa(Box::new(
                    DesktopClientMfaEvent::Disconnected {
                        location: location.clone(),
                        device: device.clone(),
                        is_mfa_session: true,
                    },
                )),
                Some(location.clone()),
            ),
            event_type: EventType::VpnClientMfaDisconnected,
            module: ActivityLogModule::Vpn,
            description_contains: Some("disconnected"),
        },
        EventTestCase {
            name: "SessionSuperseded",
            message: bidi_msg(
                BidiStreamEventType::DesktopClientMfa(Box::new(
                    DesktopClientMfaEvent::SessionSuperseded {
                        location: location.clone(),
                        device: device.clone(),
                        is_mfa_session: true,
                    },
                )),
                Some(location.clone()),
            ),
            event_type: EventType::VpnClientMfaSessionSuperseded,
            module: ActivityLogModule::Vpn,
            description_contains: Some("superseded"),
        },
        EventTestCase {
            name: "MfaLoginSuperseded",
            message: bidi_msg(
                BidiStreamEventType::DesktopClientMfa(Box::new(
                    DesktopClientMfaEvent::MfaLoginSuperseded {
                        location: location.clone(),
                        device: device.clone(),
                    },
                )),
                Some(location.clone()),
            ),
            event_type: EventType::VpnClientMfaLoginSuperseded,
            module: ActivityLogModule::Vpn,
            description_contains: Some("superseded"),
        },
        EventTestCase {
            name: "PostureCheckPassed",
            message: bidi_msg(
                BidiStreamEventType::DesktopClientMfa(Box::new(
                    DesktopClientMfaEvent::PostureCheckPassed {
                        location: location.clone(),
                        device: device.clone(),
                        facts: Some(xguard_core::posture::PostureFacts::default()),
                    },
                )),
                Some(location.clone()),
            ),
            event_type: EventType::DevicePostureCheckPassed,
            module: ActivityLogModule::Posture,
            description_contains: Some("passed the posture check"),
        },
        EventTestCase {
            name: "PostureCheckFailed",
            message: bidi_msg(
                BidiStreamEventType::DesktopClientMfa(Box::new(
                    DesktopClientMfaEvent::PostureCheckFailed {
                        location: location.clone(),
                        device: device.clone(),
                        facts: None,
                        failed_checks: vec!["disk encryption is required".into()],
                    },
                )),
                Some(location.clone()),
            ),
            event_type: EventType::DevicePostureCheckFailed,
            module: ActivityLogModule::Posture,
            description_contains: Some("disk encryption is required"),
        },
    ];

    assert_eq!(
        cases.len(),
        CoreEnrollmentEvent::COUNT + PasswordResetEvent::COUNT + DesktopClientMfaEvent::COUNT,
        "missing test case for new BidiStreamEventType leaf variant"
    );
    cases
}

fn session_manager_cases() -> Vec<EventTestCase> {
    let location = sample_location();
    let device = sample_device();

    fn session_manager_msg(
        event: SessionManagerEventType,
        loc: WireguardNetwork<Id>,
        dev: Device<Id>,
    ) -> EventLoggerMessage {
        EventLoggerMessage {
            context: test_context(),
            event: Event::SessionManager {
                event,
                location: loc,
                device: dev,
            },
        }
    }

    let cases = vec![
        EventTestCase {
            name: "ClientConnected",
            message: session_manager_msg(
                SessionManagerEventType::ClientConnected,
                location.clone(),
                device.clone(),
            ),
            event_type: EventType::VpnClientConnected,
            module: ActivityLogModule::Vpn,
            description_contains: Some("connected"),
        },
        EventTestCase {
            name: "ClientDisconnected",
            message: session_manager_msg(
                SessionManagerEventType::ClientDisconnected,
                location.clone(),
                device.clone(),
            ),
            event_type: EventType::VpnClientDisconnected,
            module: ActivityLogModule::Vpn,
            description_contains: Some("disconnected"),
        },
        EventTestCase {
            name: "MfaClientConnected",
            message: session_manager_msg(
                SessionManagerEventType::MfaClientConnected,
                location.clone(),
                device.clone(),
            ),
            event_type: EventType::VpnClientMfaConnected,
            module: ActivityLogModule::Vpn,
            description_contains: Some("connected"),
        },
        EventTestCase {
            name: "MfaClientDisconnected",
            message: session_manager_msg(
                SessionManagerEventType::MfaClientDisconnected,
                location,
                device,
            ),
            event_type: EventType::VpnClientMfaDisconnected,
            module: ActivityLogModule::Vpn,
            description_contains: Some("disconnected"),
        },
    ];

    assert_eq!(
        cases.len(),
        SessionManagerEventType::COUNT,
        "missing test case for new SessionManagerEventType variant"
    );
    cases
}

fn ldap_event_cases() -> Vec<EventTestCase> {
    let user = sample_user();
    let mut modified_user = user.clone();
    modified_user.email = "changed@example.com".into();
    let group = sample_group();

    // Build the message directly (rather than via `from_ldap_sync_event`, which reads
    // global settings) so these mapping cases stay pure. `uses_ad: false` => the `Ldap`
    // module; the AD branch is covered by `test_ldap_sync_event_module_follows_uses_ad`.
    fn ldap_msg(event: LdapSyncEventType) -> EventLoggerMessage {
        EventLoggerMessage {
            context: test_context(),
            event: Event::LdapSync {
                uses_ad: false,
                event,
            },
        }
    }

    let cases = vec![
        EventTestCase {
            name: "LdapSyncUserCreated",
            message: ldap_msg(LdapSyncEventType::UserCreated { user: user.clone() }),
            event_type: EventType::LdapSyncUserCreated,
            module: ActivityLogModule::Ldap,
            description_contains: Some("created user"),
        },
        EventTestCase {
            name: "LdapSyncUserDeleted",
            message: ldap_msg(LdapSyncEventType::UserDeleted { user: user.clone() }),
            event_type: EventType::LdapSyncUserDeleted,
            module: ActivityLogModule::Ldap,
            description_contains: Some("deleted user"),
        },
        EventTestCase {
            name: "LdapSyncUserModified",
            message: ldap_msg(LdapSyncEventType::UserModified {
                before: user.clone(),
                after: modified_user.clone(),
            }),
            event_type: EventType::LdapSyncUserModified,
            module: ActivityLogModule::Ldap,
            description_contains: Some("modified user"),
        },
        EventTestCase {
            name: "LdapSyncUserEnabled",
            message: ldap_msg(LdapSyncEventType::UserEnabled { user: user.clone() }),
            event_type: EventType::LdapSyncUserEnabled,
            module: ActivityLogModule::Ldap,
            description_contains: Some("enabled user"),
        },
        EventTestCase {
            name: "LdapSyncUserDisabled",
            message: ldap_msg(LdapSyncEventType::UserDisabled { user: user.clone() }),
            event_type: EventType::LdapSyncUserDisabled,
            module: ActivityLogModule::Ldap,
            description_contains: Some("disabled user"),
        },
        EventTestCase {
            name: "LdapSyncGroupCreated",
            message: ldap_msg(LdapSyncEventType::GroupCreated {
                group: group.clone(),
            }),
            event_type: EventType::LdapSyncGroupCreated,
            module: ActivityLogModule::Ldap,
            description_contains: Some("created group"),
        },
        EventTestCase {
            name: "LdapSyncGroupMemberAdded",
            message: ldap_msg(LdapSyncEventType::GroupMemberAdded {
                group: group.clone(),
                user: user.clone(),
            }),
            event_type: EventType::LdapSyncGroupMemberAdded,
            module: ActivityLogModule::Ldap,
            description_contains: Some("added user"),
        },
        EventTestCase {
            name: "LdapSyncGroupMemberRemoved",
            message: ldap_msg(LdapSyncEventType::GroupMemberRemoved {
                group: group.clone(),
                user: user.clone(),
            }),
            event_type: EventType::LdapSyncGroupMemberRemoved,
            module: ActivityLogModule::Ldap,
            description_contains: Some("removed user"),
        },
        EventTestCase {
            name: "LdapSyncOutboundUserCreated",
            message: ldap_msg(LdapSyncEventType::OutboundUserCreated { user: user.clone() }),
            event_type: EventType::LdapSyncOutboundUserCreated,
            module: ActivityLogModule::Ldap,
            description_contains: Some("synced user"),
        },
        EventTestCase {
            name: "LdapSyncOutboundUserDeleted",
            message: ldap_msg(LdapSyncEventType::OutboundUserDeleted {
                username: user.username.clone(),
            }),
            event_type: EventType::LdapSyncOutboundUserDeleted,
            module: ActivityLogModule::Ldap,
            description_contains: Some("removed user"),
        },
        EventTestCase {
            name: "LdapSyncOutboundUserModified",
            message: ldap_msg(LdapSyncEventType::OutboundUserModified {
                user: modified_user,
            }),
            event_type: EventType::LdapSyncOutboundUserModified,
            module: ActivityLogModule::Ldap,
            description_contains: Some("attributes"),
        },
        EventTestCase {
            name: "LdapSyncOutboundUserEnabled",
            message: ldap_msg(LdapSyncEventType::OutboundUserEnabled { user: user.clone() }),
            event_type: EventType::LdapSyncOutboundUserEnabled,
            module: ActivityLogModule::Ldap,
            description_contains: Some("enabled LDAP account"),
        },
        EventTestCase {
            name: "LdapSyncOutboundUserDisabled",
            message: ldap_msg(LdapSyncEventType::OutboundUserDisabled { user: user.clone() }),
            event_type: EventType::LdapSyncOutboundUserDisabled,
            module: ActivityLogModule::Ldap,
            description_contains: Some("disabled LDAP account"),
        },
        EventTestCase {
            name: "LdapSyncOutboundGroupMemberAdded",
            message: ldap_msg(LdapSyncEventType::OutboundGroupMemberAdded {
                group: group.name.clone(),
                username: user.username.clone(),
            }),
            event_type: EventType::LdapSyncOutboundGroupMemberAdded,
            module: ActivityLogModule::Ldap,
            description_contains: Some("added user"),
        },
        EventTestCase {
            name: "LdapSyncOutboundGroupMemberRemoved",
            message: ldap_msg(LdapSyncEventType::OutboundGroupMemberRemoved {
                group: group.name,
                username: user.username,
            }),
            event_type: EventType::LdapSyncOutboundGroupMemberRemoved,
            module: ActivityLogModule::Ldap,
            description_contains: Some("removed user"),
        },
    ];

    assert_eq!(
        cases.len(),
        LdapSyncEventType::COUNT,
        "missing test case for new LdapSyncEventType variant"
    );
    cases
}

fn directory_sync_event_cases() -> Vec<EventTestCase> {
    let user = sample_user();
    let group = sample_group();

    fn dirsync_msg(event: DirectorySyncEventType) -> EventLoggerMessage {
        EventLoggerMessage {
            context: test_context(),
            event: Event::OidcDirectorySync {
                provider: "Google".to_owned(),
                event,
            },
        }
    }

    let cases = vec![
        EventTestCase {
            name: "OidcDirectorySyncUserCreated",
            message: dirsync_msg(DirectorySyncEventType::UserCreated { user: user.clone() }),
            event_type: EventType::OidcDirectorySyncUserCreated,
            module: ActivityLogModule::OidcDirectorySync,
            description_contains: Some("created user"),
        },
        EventTestCase {
            name: "OidcDirectorySyncUserDeleted",
            message: dirsync_msg(DirectorySyncEventType::UserDeleted { user: user.clone() }),
            event_type: EventType::OidcDirectorySyncUserDeleted,
            module: ActivityLogModule::OidcDirectorySync,
            description_contains: Some("deleted user"),
        },
        EventTestCase {
            name: "OidcDirectorySyncUserModified",
            message: dirsync_msg(DirectorySyncEventType::UserModified {
                before: user.clone(),
                after: user.clone(),
            }),
            event_type: EventType::OidcDirectorySyncUserModified,
            module: ActivityLogModule::OidcDirectorySync,
            description_contains: Some("modified user"),
        },
        EventTestCase {
            name: "OidcDirectorySyncUserEnabled",
            message: dirsync_msg(DirectorySyncEventType::UserEnabled { user: user.clone() }),
            event_type: EventType::OidcDirectorySyncUserEnabled,
            module: ActivityLogModule::OidcDirectorySync,
            description_contains: Some("enabled user"),
        },
        EventTestCase {
            name: "OidcDirectorySyncUserDisabled",
            message: dirsync_msg(DirectorySyncEventType::UserDisabled { user: user.clone() }),
            event_type: EventType::OidcDirectorySyncUserDisabled,
            module: ActivityLogModule::OidcDirectorySync,
            description_contains: Some("disabled user"),
        },
        EventTestCase {
            name: "OidcDirectorySyncGroupCreated",
            message: dirsync_msg(DirectorySyncEventType::GroupCreated {
                group: group.clone(),
            }),
            event_type: EventType::OidcDirectorySyncGroupCreated,
            module: ActivityLogModule::OidcDirectorySync,
            description_contains: Some("created group"),
        },
        EventTestCase {
            name: "OidcDirectorySyncGroupMemberAdded",
            message: dirsync_msg(DirectorySyncEventType::GroupMemberAdded {
                group: group.clone(),
                user: user.clone(),
            }),
            event_type: EventType::OidcDirectorySyncGroupMemberAdded,
            module: ActivityLogModule::OidcDirectorySync,
            description_contains: Some("added user"),
        },
        EventTestCase {
            name: "OidcDirectorySyncGroupMemberRemoved",
            message: dirsync_msg(DirectorySyncEventType::GroupMemberRemoved {
                group: group.clone(),
                user: user.clone(),
            }),
            event_type: EventType::OidcDirectorySyncGroupMemberRemoved,
            module: ActivityLogModule::OidcDirectorySync,
            description_contains: Some("removed user"),
        },
    ];

    assert_eq!(
        cases.len(),
        DirectorySyncEventType::COUNT,
        "missing test case for new DirectorySyncEventType variant"
    );
    cases
}

#[test]
fn test_directory_sync_events_use_system_context() {
    let message = EventLoggerMessage::from_directory_sync_event(DirectorySyncEvent {
        provider: "Google".to_owned(),
        event: DirectorySyncEventType::UserCreated {
            user: sample_user(),
        },
    });

    assert_eq!(message.context.user_id, None);
    assert_eq!(message.context.username, "system:oidc-directory-sync");
    assert_eq!(message.context.device, "system");
    match message.event {
        Event::OidcDirectorySync { provider, .. } => {
            assert_eq!(provider, "Google");
        }
        _ => panic!("expected an OIDC directory sync event"),
    }
}

#[test]
fn test_directory_sync_description_contains_provider() {
    // The provider name must be present in the activity log entry so it's clear
    // which directory the change came from.
    let result = map_to_activity_log_event(EventLoggerMessage {
        context: test_context(),
        event: Event::OidcDirectorySync {
            provider: "Okta".to_owned(),
            event: DirectorySyncEventType::UserCreated {
                user: sample_user(),
            },
        },
    });
    assert_eq!(result.module, ActivityLogModule::OidcDirectorySync);
    assert_eq!(result.event, EventType::OidcDirectorySyncUserCreated);
    assert!(
        result.description.unwrap_or_default().contains("Okta"),
        "description should mention the provider name"
    );
}

#[test]
fn test_ldap_sync_events_use_system_context() {
    // `from_ldap_sync_event` reads `ldap_uses_ad` from global settings, which panics if
    // uninitialized; seed defaults (`ldap_uses_ad` defaults to false).
    set_settings(Some(Settings::default()));

    let message = EventLoggerMessage::from_ldap_sync_event(LdapSyncEventType::UserCreated {
        user: sample_user(),
    });

    assert_eq!(message.context.user_id, None);
    assert_eq!(message.context.username, "system:ldap-sync");
    assert_eq!(message.context.device, "system");
    match message.event {
        Event::LdapSync { uses_ad, .. } => {
            assert!(!uses_ad, "default settings should report plain LDAP");
        }
        _ => panic!("expected an LDAP sync event"),
    }
}

#[test]
fn test_gateway_connection_events_map_to_system_activity_events() {
    for (event, expected_type, description) in [
        (
            GatewayConnectionEvent::Connected {
                gateway_id: 7,
                gateway_name: "edge-a".to_owned(),
            },
            EventType::GatewayConnected,
            "Gateway edge-a connected",
        ),
        (
            GatewayConnectionEvent::Disconnected {
                gateway_id: 7,
                gateway_name: "edge-a".to_owned(),
            },
            EventType::GatewayDisconnected,
            "Gateway edge-a disconnected",
        ),
    ] {
        let message = EventLoggerMessage::from_gateway_connection_event(event);
        assert_eq!(message.context.user_id, None);
        assert_eq!(message.context.username, "system:gateway");

        let result = map_to_activity_log_event(message);
        assert_eq!(result.event, expected_type);
        assert_eq!(result.module, ActivityLogModule::XGuard);
        assert_eq!(result.description.as_deref(), Some(description));
    }
}

#[test]
fn test_proxy_connection_events_map_to_system_activity_events() {
    for (event, expected_type, description) in [
        (
            ProxyConnectionEvent::Connected {
                proxy_id: 7,
                proxy_name: "proxy-a".to_owned(),
            },
            EventType::ProxyConnected,
            "Proxy proxy-a connected",
        ),
        (
            ProxyConnectionEvent::Disconnected {
                proxy_id: 7,
                proxy_name: "proxy-a".to_owned(),
            },
            EventType::ProxyDisconnected,
            "Proxy proxy-a disconnected",
        ),
    ] {
        let message = EventLoggerMessage::from_proxy_connection_event(event);
        assert_eq!(message.context.user_id, None);
        assert_eq!(message.context.username, "system:edge");

        let result = map_to_activity_log_event(message);
        assert_eq!(result.event, expected_type);
        assert_eq!(result.module, ActivityLogModule::XGuard);
        assert_eq!(result.description.as_deref(), Some(description));
    }
}

#[test]
fn test_ldap_sync_event_module_follows_uses_ad() {
    // The event types are shared between Active Directory and plain LDAP; only the
    // module differs, driven by the `uses_ad` flag resolved at log time.
    let ldap = map_to_activity_log_event(EventLoggerMessage {
        context: test_context(),
        event: Event::LdapSync {
            uses_ad: false,
            event: LdapSyncEventType::UserCreated {
                user: sample_user(),
            },
        },
    });
    assert_eq!(ldap.module, ActivityLogModule::Ldap);
    assert_eq!(ldap.event, EventType::LdapSyncUserCreated);

    let active_directory = map_to_activity_log_event(EventLoggerMessage {
        context: test_context(),
        event: Event::LdapSync {
            uses_ad: true,
            event: LdapSyncEventType::UserCreated {
                user: sample_user(),
            },
        },
    });
    assert_eq!(active_directory.module, ActivityLogModule::ActiveDirectory);
    assert_eq!(active_directory.event, EventType::LdapSyncUserCreated);
}

#[test]
fn test_all_event_variants_map_to_correct_activity_log_events() {
    let mut cases = api_event_cases();
    cases.extend(bidi_event_cases());
    cases.extend(session_manager_cases());
    cases.extend(ldap_event_cases());
    cases.extend(directory_sync_event_cases());

    for case in cases {
        let result = map_to_activity_log_event(case.message);
        assert_eq!(
            result.event, case.event_type,
            "{}: wrong event type",
            case.name
        );
        assert_eq!(result.module, case.module, "{}: wrong module", case.name);
        if let Some(substr) = case.description_contains {
            let description = result
                .description
                .unwrap_or_else(|| panic!("{}: expected description", case.name));
            assert!(
                description.to_lowercase().contains(&substr.to_lowercase()),
                "{}: description '{description}' missing '{substr}'",
                case.name
            );
        }
    }
}
