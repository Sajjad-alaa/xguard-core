use std::{
    collections::hash_map::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use reqwest::Url;
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::mpsc::UnboundedSender;
use xguard_common::{
    auth::claims::ClaimsType,
    config::server_config,
    db::{
        Id,
        models::{Settings, User, WireguardNetwork, vpn_client_session::VpnClientMfaMethod},
    },
    types::UrlParseError,
};

use crate::{
    db::AppEvent,
    features::{is_service_location, supported_mfa_authorize_methods, supported_mfa_setup_methods},
    grpc::{interceptor::JwtInterceptor, worker::WorkerServer},
    sso::{
        edge::edge_public_url,
        provider::{ProviderConfig, ProviderKind},
    },
};

pub mod client_version;
pub mod interceptor;
pub mod proxy;
pub mod utils;
pub mod worker;

use tonic::transport::{Identity, Server, ServerTlsConfig, server::Router};
use xguard_proto::{
    client_types::{
        ClientTrafficPolicy, MfaCapabilities, MfaMethod, MfaUserState, OpenIdProviderKind,
    },
    worker::worker_service_server::WorkerServiceServer,
};

// gRPC header for passing auth token from clients
pub static AUTHORIZATION_HEADER: &str = "authorization";

// gRPC header for passing hostname from clients
pub static HOSTNAME_HEADER: &str = "hostname";
const TEN_SECS: Duration = Duration::from_secs(10);

/// Runs gRPC server with core services.
#[instrument(skip_all)]
pub async fn run_grpc_server(
    worker_state: Arc<Mutex<WorkerState>>,
    pool: PgPool,
    grpc_cert: Option<String>,
    grpc_key: Option<String>,
) -> Result<(), anyhow::Error> {
    // Build gRPC services
    let server = if let (Some(cert), Some(key)) = (grpc_cert, grpc_key) {
        let identity = Identity::from_pem(cert, key);
        Server::builder().tls_config(ServerTlsConfig::new().identity(identity))?
    } else {
        Server::builder()
    };

    let router = build_grpc_service_router(server, pool, worker_state).await?;

    // Run gRPC server
    let addr = SocketAddr::new(
        server_config()
            .grpc_bind_address
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        server_config().grpc_port,
    );
    debug!("Starting gRPC services");
    router.serve(addr).await?;
    info!("gRPC server started on {addr}");
    Ok(())
}

pub async fn build_grpc_service_router(
    server: Server,
    pool: PgPool,
    worker_state: Arc<Mutex<WorkerState>>,
) -> Result<Router, anyhow::Error> {
    let worker_service = WorkerServiceServer::with_interceptor(
        WorkerServer::new(pool.clone(), worker_state),
        JwtInterceptor::new(ClaimsType::YubiBridge),
    );

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<WorkerServiceServer<WorkerServer>>()
        .await;
    health_reporter
        .set_serving::<WorkerServiceServer<WorkerServer>>()
        .await;

    let router = server
        .http2_keepalive_interval(Some(TEN_SECS))
        .tcp_keepalive(Some(TEN_SECS))
        .add_service(health_service)
        .add_service(worker_service);

    Ok(router)
}

pub struct Job {
    id: u32,
    first_name: String,
    last_name: String,
    email: String,
    username: String,
}

#[derive(Serialize)]
pub struct JobResponse {
    pub success: bool,
    pub serial: String,
    pub error: String,
    #[serde(skip)]
    pub username: String,
}

pub struct WorkerInfo {
    last_seen: Instant,
    ip: IpAddr,
    jobs: Vec<Job>,
}

pub struct WorkerState {
    current_job_id: u32,
    workers: HashMap<String, WorkerInfo>,
    job_status: HashMap<u32, JobResponse>,
    webhook_tx: UnboundedSender<AppEvent>,
}

#[derive(Deserialize, Serialize)]
pub struct WorkerDetail {
    id: String,
    ip: IpAddr,
    connected: bool,
}

#[derive(Debug)]
pub struct InstanceInfo {
    id: uuid::Uuid,
    name: String,
    url: Url,
    proxy_url: Url,
    username: String,
    smtp_configured: bool,
    /// The provider users can sign in with through Edge (display name and kind).
    openid: Option<(Option<String>, ProviderKind)>,
    pub configured_methods: Vec<VpnClientMfaMethod>,
}

#[derive(Debug, thiserror::Error)]
/// Errors that can occur while building client instance information.
pub enum InstanceInfoBuildError {
    #[error("failed to load instance data: {0}")]
    Database(#[from] sqlx::Error),
    #[error("failed to parse instance URL: {0}")]
    UrlParse(#[from] UrlParseError),
}

impl InstanceInfo {
    /// Builds client instance information for a user.
    pub async fn build(
        pool: &PgPool,
        settings: &Settings,
        user: &User<Id>,
        device_id: Option<Id>,
    ) -> Result<Self, InstanceInfoBuildError> {
        let smtp_configured = settings.smtp_configured();
        let openid = if edge_public_url().is_ok() {
            ProviderConfig::enabled(pool)
                .await?
                .map(|config| (config.provider.display_name, config.provider.kind))
        } else {
            None
        };
        let mut configured_methods = Vec::with_capacity(VpnClientMfaMethod::ALL.len());
        for method in VpnClientMfaMethod::ALL {
            if method
                .is_configured(pool, user, device_id, smtp_configured, openid.is_some())
                .await?
            {
                configured_methods.push(method);
            }
        }
        let url = Settings::url()?;
        let proxy_url = settings.proxy_public_url()?;
        Ok(Self {
            id: settings.uuid,
            name: settings.instance_name.clone(),
            url,
            proxy_url,
            username: user.username.clone(),
            smtp_configured,
            openid,
            configured_methods,
        })
    }
}

impl From<InstanceInfo> for xguard_proto::client_types::InstanceInfo {
    fn from(instance: InstanceInfo) -> Self {
        Self {
            name: instance.name,
            id: instance.id.to_string(),
            url: instance.url.to_string(),
            proxy_url: instance.proxy_url.to_string(),
            username: instance.username,
            // Ensure backwards compatibility.
            #[allow(deprecated)]
            disable_all_traffic: false,
            client_traffic_policy: Some(ClientTrafficPolicy::None as i32),
            enterprise_enabled: false,
            openid_display_name: instance.openid.as_ref().and_then(|(name, _)| name.clone()),
            openid_provider_kind: instance
                .openid
                .as_ref()
                .map(|(_, kind)| OpenIdProviderKind::from(*kind) as i32),
            disable_tunnels: Some(false),
            smtp_configured: Some(instance.smtp_configured),
            openid_available: Some(instance.openid.is_some()),
            mfa_user_state: Some(MfaUserState {
                configured_methods: instance
                    .configured_methods
                    .into_iter()
                    .map(|method| MfaMethod::from(method) as i32)
                    .collect(),
            }),
            mfa_capabilities: Some(MfaCapabilities {
                setup_methods: supported_mfa_setup_methods()
                    .into_iter()
                    .map(|method| MfaMethod::from(method) as i32)
                    .collect(),
                authorize_methods: supported_mfa_authorize_methods()
                    .into_iter()
                    .map(|method| MfaMethod::from(method) as i32)
                    .collect(),
            }),
        }
    }
}

pub use xguard_common::gateway_event::{
    GatewayCommand, send_gateway_command, send_multiple_gateway_commands,
};

/// Service locations are not supported by XGuard (see [`crate::features`]), so peers are never
/// handed out for them.
#[must_use]
pub fn should_prevent_service_location_usage(location: &WireguardNetwork<Id>) -> bool {
    is_service_location(location)
}
