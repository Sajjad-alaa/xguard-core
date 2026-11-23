mod activity_log;
mod api_tokens;
mod auth;
mod client_downloads;
mod client_settings;
mod common;
pub(crate) use common::make_test_client;
mod component_setup;
mod core_certs;
mod device_posture;
mod dirsync;
mod enrollment;
mod firewall;
mod forward_auth;
mod gateway;
mod group;
mod location_stats;
mod mfa_flow;
mod oauth;
mod openid;
mod provisioning;
mod proxy;
mod proxy_certs;
mod resources;
mod settings;
mod ssh_authorized_keys;
mod sso;
mod user;
mod webhook;
mod wireguard;
mod wireguard_network_allowed_groups;
mod wireguard_network_devices;
mod wireguard_network_import;
// FIXME(mwojcik): rewrite for new stats implementation
// mod wireguard_network_stats;
mod worker;

const TEST_SERVER_URL: &str = "http://localhost:3000/";

#[derive(serde::Deserialize)]
struct PaginatedApiResponse<T> {
    data: Vec<T>,
    // pagination: PaginationMeta,
}
