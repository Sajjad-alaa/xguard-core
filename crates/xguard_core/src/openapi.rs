use utoipa::{
    Modify, OpenApi,
    openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
};
use xguard_common::{
    CARGO_VERSION,
    db::models::{
        Device,
        device::{AddDevice, ModifyDevice, UserDevice},
    },
    types::user_info::UserInfo,
};

use super::handlers::{
    ApiErrorResponse, Auth, EditGroupInfo, GroupInfo, PasswordChange, PasswordChangeSelf,
    SESSION_COOKIE_NAME, StartEnrollmentRequest, Username, activity_log, api_tokens, app_info,
    auth, component_setup, core_certs, directory, firewall, forward_auth, gateway,
    group::{self, BulkAssignToGroupsRequest},
    location_stats, log_stream, mail, mfa_flow, network_devices, openid_clients, openid_flow,
    proxy, reserved, resource_display, session_info, settings, ssh_authorized_keys, static_ips,
    support, updates,
    user::{self, UserDetails},
    webhooks, wireguard as device, wireguard as network,
    wireguard::AddDeviceResult,
};

#[derive(OpenApi)]
#[openapi(
    modifiers(&SecurityAddon),
    info(
        title = "xguard Core API",
        version = CARGO_VERSION,
        description = "
REST API of xguard Core.

Authentication is done either with the session cookie obtained from `POST /api/v1/auth`,
or, for admins, with an API token passed as `Authorization: Bearer xgt_...`.

An admin creates their own tokens with `POST /api/v1/user/{username}/api_token` while signed in.
The token is returned only once, in that response. A token can expire and can be limited to
read-only (GET) requests. Tokens are revoked when their owner is disabled or stops being an admin.

Errors are returned as a JSON object with a `msg` field and, for some of them, a machine-readable `code` field.",
    ),
    paths(
        // system
        forward_auth::forward_auth,
        crate::health_check,
        app_info::get_app_info,
        updates::outdated_components,
        reserved::check_reserved,
        session_info::get_session_info,
        updates::check_new_version,
        // auth
        auth::authenticate,
        auth::request_email_mfa_code,
        auth::email_mfa_enable,
        auth::email_mfa_init,
        auth::email_mfa_code,
        auth::logout,
        auth::mfa_disable,
        auth::mfa_enable,
        auth::recovery_code,
        auth::totp_enable,
        auth::totp_secret,
        auth::totp_code,
        auth::webauthn_end,
        auth::webauthn_finish,
        auth::webauthn_init,
        auth::webauthn_start,
        // user
        user::me,
        user::list_users,
        user::add_user,
        user::username_available,
        user::bulk_delete_users,
        user::bulk_disable_users,
        user::bulk_enable_users,
        user::bulk_start_enrollment,
        user::change_self_password,
        user::delete_user,
        user::get_user,
        user::modify_user,
        auth::email_mfa_disable,
        auth::disable_user_mfa,
        user::delete_authorized_app,
        user::change_password,
        user::reset_password,
        user::delete_security_key,
        user::start_remote_desktop_configuration,
        user::start_enrollment,
        auth::totp_disable,
        // group
        group::list_groups,
        group::create_group,
        group::list_groups_info,
        group::delete_group,
        group::get_group,
        group::add_group_member,
        group::modify_group,
        group::remove_group_member,
        group::bulk_assign_to_groups,
        // device
        device::list_devices,
        device::list_user_devices,
        device::delete_device,
        device::get_device,
        device::add_device,
        device::modify_device,
        device::user_device_configs,
        // network device
        network_devices::list_network_devices,
        network_devices::add_network_device,
        network_devices::find_available_ips,
        network_devices::check_ip_availability,
        network_devices::start_network_device_setup,
        network_devices::start_network_device_setup_for_device,
        network_devices::get_network_device,
        network_devices::modify_network_device,
        network_devices::network_device_configs,
        // static IP
        static_ips::get_all_user_device_ips,
        static_ips::assign_static_ips,
        static_ips::validate_ip_assignment,
        static_ips::get_device_ips,
        // network
        network::list_networks,
        network::create_network,
        network::count_networks,
        resource_display::get_locations_display,
        network::import_network,
        network::delete_network,
        network::network_details,
        network::modify_network,
        network::download_config,
        network::add_user_devices,
        // location stats
        location_stats::locations_overview_stats,
        location_stats::location_connected_network_devices,
        location_stats::location_connected_users,
        location_stats::location_connected_user_devices,
        location_stats::location_stats,
        // gateway
        gateway::gateway_list,
        gateway::delete_gateway,
        gateway::gateway_details,
        gateway::update_gateway,
        network::all_gateways_status,
        network::gateway_status,
        component_setup::adopt_gateway,
        component_setup::setup_gateway_tls_stream,
        // proxy
        proxy::proxy_list,
        component_setup::stream_proxy_acme,
        component_setup::setup_proxy_tls_stream,
        proxy::delete_proxy,
        proxy::proxy_details,
        proxy::update_proxy,
        // certificates
        core_certs::get_ca,
        core_certs::get_certs,
        core_certs::set_internal_url_settings,
        core_certs::set_external_url_settings,
        // SSH key
        ssh_authorized_keys::get_authorized_keys,
        ssh_authorized_keys::fetch_authentication_keys,
        ssh_authorized_keys::add_authentication_key,
        ssh_authorized_keys::delete_authentication_key,
        ssh_authorized_keys::rename_authentication_key,
        // webhook
        webhooks::list_webhooks,
        webhooks::add_webhook,
        webhooks::delete_webhook,
        webhooks::get_webhook,
        webhooks::change_enabled,
        webhooks::change_webhook,
        // activity log streaming
        log_stream::list_streams,
        log_stream::create_stream,
        log_stream::update_stream,
        log_stream::delete_stream,
        log_stream::test_stream,
        // directory
        directory::test_directory,
        directory::sync_directory,
        directory::preview_directory_sync,
        // API tokens
        api_tokens::list_api_tokens,
        api_tokens::create_api_token,
        api_tokens::rename_api_token,
        api_tokens::delete_api_token,
        // firewall
        firewall::list_firewall_rules,
        firewall::get_firewall_rule,
        firewall::create_firewall_rule,
        firewall::update_firewall_rule,
        firewall::delete_firewall_rule,
        firewall::location_firewall_policy,
        firewall::list_snat_bindings,
        firewall::create_snat_binding,
        firewall::update_snat_binding,
        firewall::delete_snat_binding,
        // settings
        settings::get_settings,
        settings::patch_settings,
        settings::update_settings,
        settings::set_default_branding,
        settings::get_settings_essentials,
        // activity log
        activity_log::get_activity_log_event,
        activity_log::get_activity_log_events,
        // OAuth2
        openid_flow::openid_configuration,
        openid_clients::list_openid_clients,
        openid_clients::add_openid_client,
        openid_flow::authorization,
        openid_flow::secure_authorization,
        openid_flow::discovery_keys,
        openid_flow::token,
        openid_flow::userinfo,
        openid_clients::delete_openid_client,
        openid_clients::get_openid_client,
        openid_clients::change_openid_client_state,
        openid_clients::change_openid_client,
        // mfa flow
        mfa_flow::list_mfa_flows,
        mfa_flow::create_mfa_flow,
        mfa_flow::get_mfa_flow,
        mfa_flow::update_mfa_flow,
        mfa_flow::delete_mfa_flow,
        mfa_flow::get_location_mfa_flows,
        mfa_flow::get_method_availability,
        // support
        mail::send_support_data,
        mail::test_mail,
        support::configuration,
        support::logs,
    ),
    components(
        schemas(
            ApiErrorResponse, Auth, UserInfo, UserDetails, UserDevice, Username,
            StartEnrollmentRequest, PasswordChangeSelf, PasswordChange, AddDevice, AddDeviceResult,
            Device, ModifyDevice, BulkAssignToGroupsRequest, GroupInfo, EditGroupInfo,
            user::SortKey, user::SortOrder, reserved::CheckResource,
            xguard_common::firewall::FirewallRule, xguard_common::firewall::FirewallRuleInput,
            xguard_common::firewall::FirewallRuleAction, xguard_common::firewall::SnatBinding,
            xguard_common::firewall::SnatBindingInput,
            xguard_common::db::models::ApiToken,
            xguard_common::db::models::api_token::NewApiToken,
            api_tokens::CreatedApiToken, api_tokens::RenameApiToken,
            directory::SyncRequest, directory::ConnectionTest,
            log_stream::StreamWithStatus, crate::log_stream::StreamInput,
            crate::log_stream::StreamType, crate::log_stream::sender::StreamStatus
        ),
    ),
    tags(
        (name = "system", description = "Health check, instance info and other utility endpoints."),
        (name = "auth", description = "User authentication, second authentication factor and session management."),
        (name = "user", description = "User accounts, their MFA methods, enrollment and bulk operations."),
        (name = "group", description = "User groups and their members."),
        (name = "device", description = "User devices and their WireGuard configuration."),
        (name = "network device", description = "Network devices, as opposed to user devices, and their IP addresses."),
        (name = "static IP", description = "Static IP addresses assigned to user devices."),
        (name = "network", description = "WireGuard networks, including import from a WireGuard configuration file."),
        (name = "location stats", description = "Traffic statistics and active connections per location."),
        (name = "gateway", description = "Gateways registered in your locations, their connection status and setup."),
        (name = "proxy", description = "Edge (proxy) instances, their TLS and ACME setup."),
        (name = "certificates", description = "Internal (core) and external (edge) URL certificates."),
        (name = "SSH key", description = "SSH and GPG authentication keys of users."),
        (name = "webhook", description = "Webhooks triggered by user and provisioning events."),
        (name = "api token", description = "Personal API tokens of admins, for automation."),
        (name = "firewall", description = "XGuard firewall rules and the policies compiled from them."),
        (name = "settings", description = "Instance settings."),
        (name = "activity log", description = "Activity log events."),
        (name = "OAuth2", description = "xguard acting as an OAuth2 / OpenID Connect provider for other applications."),
        (name = "support", description = "Diagnostics, logs and support data."),
        (name = "mfa flow", description = "MFA flow templates - ordered multi-step authentication recipes."),
    )
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi.info.license = None;
        if let Some(components) = openapi.components.as_mut() {
            // session cookie auth
            components.add_security_scheme(
                "cookie",
                SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new(SESSION_COOKIE_NAME))),
            );
            // API token auth (`Authorization: Bearer xgt_...`)
            components.add_security_scheme(
                "api_token",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
            );
        }
    }
}
