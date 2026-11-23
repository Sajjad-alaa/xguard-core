#[cfg(test)]
use std::path::PathBuf;
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum_extra::extract::cookie::Key;
use chrono::NaiveDateTime;
use reqwest::Url;
use semver::Version;
use sqlx::PgPool;
use tokio::{
    select,
    sync::{
        Mutex, Semaphore, TryAcquireError,
        mpsc::{self, UnboundedSender},
        oneshot, watch,
    },
    task::JoinSet,
    time::sleep,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
#[cfg(test)]
use tonic::transport::Endpoint;
use tonic::{
    Code, Request, Streaming, service::interceptor::InterceptedService, transport::Channel,
};
use xguard_common::{
    VERSION,
    db::{
        Id,
        models::{Certificates, Settings, proxy::Proxy},
    },
};
use xguard_core::{
    events::{ApiEvent, DirectorySyncEvent, LdapSyncEventType, ProxyConnectionEvent},
    grpc::{
        GatewayCommand,
        proxy::client_mfa::{ClientMfaServer, MfaStartRejection, RemoteAuthWaiters},
    },
    handlers::settings::{edge_public_settings, load_edge_settings},
    version::{IncompatibleComponents, IncompatibleProxyData, is_proxy_version_supported},
};
use xguard_grpc_tls::certs::{ProxyTlsTarget, proxy_mtls_channel};
use xguard_proto::proxy::{
    CoreError, CoreRequest, CoreResponse, HttpsCerts, InitialInfo, core_request, core_response,
    proxy_client::ProxyClient,
};
use xguard_version::{
    ComponentInfo, XGuardComponent, client::ClientVersionInterceptor, get_tracing_variables,
};

#[cfg(test)]
use crate::ProxyManagerTestSupport;
use crate::{
    HandlerTxMap, ProxyError, ProxyTxSet, TEN_SECS,
    servers::{
        EnrollmentServer, MfaConfigServer, OpenIdServer, PasswordResetServer, PollingServer,
    },
};

const VERSION_ZERO: Version = Version::new(0, 0, 0);

type ShutdownReceiver = oneshot::Receiver<bool>;

#[cfg(test)]
#[derive(Default)]
struct ProxyTestTransport {
    socket_path: Option<PathBuf>,
}

#[cfg(test)]
impl ProxyTestTransport {
    fn with_socket_path(socket_path: PathBuf) -> Self {
        Self {
            socket_path: Some(socket_path),
        }
    }

    fn socket_path(&self) -> Option<&PathBuf> {
        self.socket_path.as_ref()
    }
}

/// Represents a single Core - Proxy connection.
///
/// A `ProxyHandler` is responsible for establishing and maintaining a gRPC
/// bidirectional stream to one proxy instance, handling incoming requests
/// from that proxy, and forwarding responses back through the same stream.
pub(super) struct ProxyHandler {
    pool: PgPool,
    /// gRPC servers
    services: Arc<ProxyServices>,
    /// Proxy server gRPC URL
    pub(super) url: Url,
    shutdown_signal: Arc<Mutex<ShutdownReceiver>>,
    proxy_id: Id,
    proxy_cookie_key: Key,
    client: Option<ProxyClient<InterceptedService<Channel, ClientVersionInterceptor>>>,
    /// Shared map used to register this handler's active stream sender so the manager
    /// can push messages to a specific proxy.
    handler_tx_map: HandlerTxMap,
    connection_events_tx: UnboundedSender<ProxyConnectionEvent>,
    semaphore: Arc<Semaphore>,
    #[cfg(test)]
    test_transport: ProxyTestTransport,
    #[cfg(test)]
    test_support: Option<ProxyManagerTestSupport>,
}

impl ProxyHandler {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        pool: PgPool,
        url: Url,
        tx: &ProxyTxSet,
        remote_mfa_responses: RemoteAuthWaiters,
        shutdown_signal: Arc<Mutex<ShutdownReceiver>>,
        proxy_id: Id,
        proxy_cookie_key: Key,
        handler_tx_map: HandlerTxMap,
        semaphore: Arc<Semaphore>,
    ) -> Self {
        // Instantiate gRPC servers.
        let services = Arc::new(ProxyServices::new(&pool, tx, remote_mfa_responses));

        Self {
            pool,
            services,
            url,
            shutdown_signal,
            proxy_id,
            proxy_cookie_key,
            client: None,
            handler_tx_map,
            connection_events_tx: tx.connection_events.clone(),
            semaphore,
            #[cfg(test)]
            test_transport: ProxyTestTransport::default(),
            #[cfg(test)]
            test_support: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_proxy(
        proxy: &Proxy<Id>,
        pool: PgPool,
        tx: &ProxyTxSet,
        remote_mfa_responses: RemoteAuthWaiters,
        shutdown_signal: Arc<Mutex<ShutdownReceiver>>,
        proxy_cookie_key: Key,
        handler_tx_map: HandlerTxMap,
        semaphore: Arc<Semaphore>,
    ) -> Result<Self, ProxyError> {
        let url = Url::from_str(&format!("http://{}:{}", proxy.address, proxy.port))?;
        let proxy_id = proxy.id;
        Ok(Self::new(
            pool,
            url,
            tx,
            remote_mfa_responses,
            shutdown_signal,
            proxy_id,
            proxy_cookie_key,
            handler_tx_map,
            semaphore,
        ))
    }

    async fn mark_connected(&self, version: &Version) -> Result<(), ProxyError> {
        if let Some(mut proxy) = Proxy::find_by_id(&self.pool, self.proxy_id).await? {
            let was_connected = proxy.is_connected();
            proxy
                .mark_connected(&self.pool, version.to_string())
                .await?;
            if !was_connected {
                let _ = self
                    .connection_events_tx
                    .send(ProxyConnectionEvent::Connected {
                        proxy_id: proxy.id,
                        proxy_name: proxy.name,
                    });
            }
        } else {
            warn!("Couldn't find Proxy by ID for URL: {}", self.url);
        }

        Ok(())
    }

    async fn mark_disconnected(&self) -> Result<(), ProxyError> {
        let Some(mut proxy) = Proxy::find_by_id(&self.pool, self.proxy_id).await? else {
            warn!("Couldn't find proxy by id, URL: {}", self.url);
            return Ok(());
        };

        // Make sure we don't continuously update disconnected time in connection loop
        let should_mark = match (proxy.connected_at, proxy.disconnected_at) {
            (Some(connected), Some(disconnected)) => disconnected < connected,
            (Some(_), None) => true,
            _ => false,
        };

        if should_mark {
            proxy.mark_disconnected(&self.pool).await?;
            let _ = self
                .connection_events_tx
                .send(ProxyConnectionEvent::Disconnected {
                    proxy_id: proxy.id,
                    proxy_name: proxy.name,
                });
        }

        Ok(())
    }

    fn retry_delay(&self) -> Duration {
        #[cfg(test)]
        {
            self.handler_retry_delay()
        }
        #[cfg(not(test))]
        {
            TEN_SECS
        }
    }

    async fn connect_channel_mtls(
        &self,
        certs_rx: watch::Receiver<Arc<HashMap<Id, String>>>,
    ) -> Result<Channel, ProxyError> {
        let certs = Certificates::get(&self.pool)
            .await
            .map_err(ProxyError::SqlxError)?
            .ok_or_else(|| {
                ProxyError::MissingConfiguration(
                    "Core CA is not setup, can't create a Proxy endpoint.".to_owned(),
                )
            })?;
        let ca_cert_der = certs.ca_cert_der.ok_or_else(|| {
            ProxyError::MissingConfiguration(
                "Core CA is not setup, can't create a Proxy endpoint.".to_owned(),
            )
        })?;

        // Load the Proxy model to retrieve the per-component Core client cert.
        let proxy = Proxy::find_by_id(&self.pool, self.proxy_id)
            .await
            .map_err(ProxyError::SqlxError)?
            .ok_or_else(|| {
                ProxyError::MissingConfiguration(format!(
                    "Proxy id={} not found in DB, can't load Core client certificate",
                    self.proxy_id
                ))
            })?;

        proxy_mtls_channel(
            ProxyTlsTarget {
                id: proxy.id,
                address: &proxy.address,
                port: proxy.port,
                client_cert_der: proxy.core_client_cert_der.as_deref(),
                client_key_der: proxy.core_client_cert_key_der.as_deref(),
            },
            &ca_cert_der,
            certs_rx,
        )
        .map_err(|e| ProxyError::TlsConfigError(e.to_string()))
    }

    #[cfg(not(test))]
    async fn connect_channel(
        &self,
        certs_rx: watch::Receiver<Arc<HashMap<Id, String>>>,
    ) -> Result<Channel, ProxyError> {
        self.connect_channel_mtls(certs_rx).await
    }

    /// Establishes and maintains a gRPC bidirectional stream to the proxy.
    ///
    /// The proxy connection is retried on failure, compatibility is checked
    /// on each successful connection, and incoming messages are handled
    /// until the stream is closed.
    pub(super) async fn run(
        mut self,
        tx_set: ProxyTxSet,
        incompatible_components: Arc<RwLock<IncompatibleComponents>>,
        certs_rx: watch::Receiver<Arc<HashMap<Id, String>>>,
    ) -> Result<(), ProxyError> {
        let parsed_version = Version::parse(VERSION)?;
        loop {
            let channel = match self.connect_channel(certs_rx.clone()).await {
                Ok(ch) => ch,
                Err(err) => {
                    error!(
                        "Failed to create proxy channel for {}: {err}, retrying in {:?}",
                        self.url,
                        self.retry_delay()
                    );
                    self.mark_disconnected().await?;
                    let mut shutdown = self.shutdown_signal.lock().await;
                    select! {
                        () = sleep(self.retry_delay()) => {}
                        _ = &mut *shutdown => {
                            debug!("Shutdown signal received during reconnect backoff (connect_channel failure), stopping");
                            break;
                        }
                    }
                    continue;
                }
            };

            debug!("Connecting to proxy at {}", self.url);
            let interceptor = ClientVersionInterceptor::new(parsed_version.clone());
            let mut client = ProxyClient::with_interceptor(channel, interceptor);
            self.client = Some(client.clone());
            let (tx, rx) = mpsc::unbounded_channel();

            // Register this handler's sender so the manager can push messages to this proxy.
            if let Ok(mut map) = self.handler_tx_map.write() {
                map.insert(self.proxy_id, tx.clone());
            }

            let response = match client.bidi(UnboundedReceiverStream::new(rx)).await {
                Ok(response) => response,
                Err(err) => {
                    match err.code() {
                        Code::FailedPrecondition => {
                            error!(
                                "Failed to connect to proxy @ {}, version check failed, retrying in \
                            {:?}: {err}",
                                self.url,
                                self.retry_delay()
                            );
                            // TODO push event
                        }
                        err => {
                            error!(
                                "Failed to connect to proxy @ {}, retrying in {:?}: {err}",
                                self.url,
                                self.retry_delay()
                            );
                        }
                    }
                    // Deregister tx on connection failure.
                    if let Ok(mut map) = self.handler_tx_map.write() {
                        map.remove(&self.proxy_id);
                    }
                    self.mark_disconnected().await?;
                    let mut shutdown = self.shutdown_signal.lock().await;
                    select! {
                        () = sleep(self.retry_delay()) => {}
                        _ = &mut *shutdown => {
                            debug!("Shutdown signal received during reconnect backoff (bidi failure), stopping");
                            break;
                        }
                    }
                    continue;
                }
            };
            let maybe_info = ComponentInfo::from_metadata(response.metadata());

            // Check proxy version and continue if it's not supported.
            let (version, info) = get_tracing_variables(&maybe_info);
            let proxy_is_supported = is_proxy_version_supported(Some(&version));

            let span = tracing::info_span!("proxy_bidi", component = %XGuardComponent::Proxy,
            version = version.to_string(), info);
            let _guard = span.enter();
            if !proxy_is_supported {
                // Store incompatible proxy
                let maybe_version = if version == VERSION_ZERO {
                    None
                } else {
                    Some(version)
                };
                let data = IncompatibleProxyData::new(maybe_version);
                data.insert(&incompatible_components);

                // Sleep before trying to reconnect
                let mut shutdown = self.shutdown_signal.lock().await;
                select! {
                    () = sleep(self.retry_delay()) => {}
                    _ = &mut *shutdown => {
                        debug!("Shutdown signal received during reconnect backoff (version incompatible), stopping");
                        break;
                    }
                }
                continue;
            }
            self.mark_connected(&version).await?;
            IncompatibleComponents::remove_proxy(&incompatible_components);

            info!("Connected to proxy at {}", self.url);
            let mut resp_stream = response.into_inner();

            // Send initial info with private cookies key.
            let initial_info = InitialInfo {
                private_cookies_key: self.proxy_cookie_key.master().to_vec(),
            };
            let _ = tx.send(CoreResponse {
                id: 0,
                payload: Some(core_response::Payload::InitialInfo(initial_info)),
            });

            // Push public settings (Edge UI controls) to the newly-connected proxy.
            // Skipped when the settings cannot be read: the Edge then keeps its previous values
            // rather than being told to show pages the admin may have hidden.
            if let Some((client, downloads)) = load_edge_settings(&self.pool).await {
                let public_settings =
                    edge_public_settings(&Settings::get_current_settings(), &client, &downloads);
                let _ = tx.send(CoreResponse {
                    id: 0,
                    payload: Some(core_response::Payload::PublicSettings(public_settings)),
                });
            }

            // If a certificate has already been provisioned, push it to the newly-connected
            // proxy immediately so it can start serving HTTPS without a manual trigger.
            // The active source determines which cert/key pair to send.
            match Certificates::get(&self.pool).await {
                Ok(Some(certs)) => {
                    if let Some((cert_pem, key_pem)) = certs.proxy_http_cert_pair() {
                        info!(
                            "Sending stored {:?} certificate to proxy {} on connect",
                            certs.proxy_http_cert_source, self.proxy_id
                        );
                        let _ = tx.send(CoreResponse {
                            id: 0,
                            payload: Some(core_response::Payload::HttpsCerts(HttpsCerts {
                                cert_pem: cert_pem.to_owned(),
                                key_pem: key_pem.to_owned(),
                            })),
                        });
                    }
                }
                Ok(None) => {
                    warn!("Certificates row not found; skipping cert push on connect");
                }
                Err(err) => {
                    error!("Failed to load certificates for cert push on connect: {err}");
                }
            }

            let shutdown_signal = Arc::clone(&self.shutdown_signal);
            select! {
                res = self.message_loop(tx, tx_set.wireguard.clone(), &mut resp_stream) => {
                    if let Err(err) = res {
                        error!("Proxy message loop ended with error: {err}, reconnecting in {:?}", self.retry_delay());
                    } else {
                        info!("Proxy message loop ended, reconnecting in {:?}", self.retry_delay());
                    }
                    if let Ok(mut map) = self.handler_tx_map.write() {
                        map.remove(&self.proxy_id);
                    }
                    self.mark_disconnected().await?;
                    sleep(self.retry_delay()).await;
                }
                res = &mut *shutdown_signal.lock().await => {
                    match res {
                        Err(err) => {
                            error!("An error occurred when trying to wait for a shutdown signal for Proxy: {err}. Reconnecting to: {}", self.url);
                        }
                        Ok(purge) => {
                            info!("Shutdown signal received, purge: {purge}, stopping proxy connection to {}", self.url);
                            if purge
                                && let Some(client) = self.client.as_mut() {
                                    debug!("Sending purge request to proxy {}", self.url);
                                    if let Err(err) = client.purge(Request::new(())).await {
                                        error!("Error sending purge request to proxy {}: {err}", self.url);
                                    } else {
                                        info!("Sent purge request to proxy {}", self.url);
                                    }
                                }
                        }
                    }
                    if let Ok(mut map) = self.handler_tx_map.write() {
                        map.remove(&self.proxy_id);
                    }
                    self.mark_disconnected().await?;
                    break;
                }
            }
        }

        Ok(())
    }

    fn send_error(
        tx: &UnboundedSender<CoreResponse>,
        request_id: u64,
        status_code: Code,
        message: &'static str,
    ) {
        let response = CoreResponse {
            id: request_id,
            payload: Some(core_response::Payload::CoreError(CoreError {
                status_code: status_code as i32,
                message: message.to_owned(),
                ..Default::default()
            })),
        };
        if tx.send(response).is_err() {
            debug!("Failed to send error response for request {request_id}");
        }
    }

    fn send_internal_error(tx: &UnboundedSender<CoreResponse>, request_id: u64) {
        Self::send_error(tx, request_id, Code::Internal, "internal server error");
    }

    async fn handle_request(
        pool: PgPool,
        received: CoreRequest,
        response_tx: UnboundedSender<CoreResponse>,
        services: Arc<ProxyServices>,
        _gateway_tx: UnboundedSender<GatewayCommand>,
        handler_tx_map: HandlerTxMap,
    ) -> Result<(), ProxyError> {
        let payload = match received.payload {
            // rpc MfaConfigStart return (MfaConfigStartResponse)
            Some(core_request::Payload::MfaConfigStart(request)) => {
                match boxed(services.mfa_config.mfa_config_start(request)).await {
                    Ok(response) => Some(core_response::Payload::MfaConfigStart(response)),
                    Err(err) => {
                        error!("MFA config start error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            Some(core_request::Payload::MfaConfigSendCode(request)) => {
                match boxed(services.mfa_config.mfa_config_send_code(request)).await {
                    Ok(response) => Some(core_response::Payload::MfaConfigSendCode(response)),
                    Err(err) => {
                        error!("MFA config send code error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            Some(core_request::Payload::MfaConfigFido2Challenge(request)) => {
                match boxed(services.mfa_config.mfa_config_fido2_challenge(request)).await {
                    Ok(response) => Some(core_response::Payload::MfaConfigFido2Challenge(response)),
                    Err(err) => {
                        error!("MFA config FIDO2 challenge error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            Some(core_request::Payload::MfaConfigAuthorize(request)) => {
                match boxed(
                    services
                        .mfa_config
                        .mfa_config_authorize(request, received.device_info),
                )
                .await
                {
                    Ok(response) => Some(core_response::Payload::MfaConfigAuthorize(response)),
                    Err(err) => {
                        if err.code() == Code::FailedPrecondition {
                            // Includes the client polling an unfinished OIDC authentication.
                            debug!("MFA config authorize error {err}");
                        } else {
                            error!("MFA config authorize error {err}");
                        }
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // RPC MfaConfigEnd (MfaConfigEndRequest) returns google.protobuf.Empty.
            Some(core_request::Payload::MfaConfigEnd(request)) => {
                match boxed(services.mfa_config.mfa_config_end(request)).await {
                    Ok(()) => Some(core_response::Payload::Empty(())),
                    Err(err) => {
                        error!("MFA config end error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc CodeMfaSetupStart return (CodeMfaSetupStartResponse)
            Some(core_request::Payload::CodeMfaSetupStart(request)) => {
                match boxed(services.enrollment.mfa_setup_start(request)).await {
                    Ok(response) => {
                        Some(core_response::Payload::CodeMfaSetupStartResponse(response))
                    }
                    Err(err) => {
                        error!("MFA setup start error {err:?}");
                        Some(core_response::Payload::CoreError(err))
                    }
                }
            }
            // rpc CodeMfaSetupFinish return (CodeMfaSetupFinishResponse)
            Some(core_request::Payload::CodeMfaSetupFinish(request)) => {
                match boxed(
                    services
                        .enrollment
                        .mfa_setup_finish(request, received.device_info),
                )
                .await
                {
                    Ok(response) => {
                        Some(core_response::Payload::CodeMfaSetupFinishResponse(response))
                    }
                    Err(err) => {
                        error!("MFA setup finish error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc ClientMfaTokenValidation return (ClientMfaTokenValidationResponse)
            Some(core_request::Payload::ClientMfaTokenValidation(request)) => {
                match boxed(services.client_mfa.validate_mfa_token(request)).await {
                    Ok(response_payload) => Some(core_response::Payload::ClientMfaTokenValidation(
                        response_payload,
                    )),
                    Err(err) => {
                        error!("Client MFA validate token error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc RegisterMobileAuth (RegisterMobileAuthRequest) return (google.protobuf.Empty)
            Some(core_request::Payload::RegisterMobileAuth(request)) => {
                match boxed(services.enrollment.register_mobile_auth(request)).await {
                    Ok(()) => Some(core_response::Payload::Empty(())),
                    Err(err) => {
                        error!("Register mobile auth error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc StartEnrollment (EnrollmentStartRequest) returns (EnrollmentStartResponse)
            Some(core_request::Payload::EnrollmentStart(request)) => {
                match boxed(
                    services
                        .enrollment
                        .start_enrollment(request, received.device_info),
                )
                .await
                {
                    Ok(response_payload) => {
                        Some(core_response::Payload::EnrollmentStart(response_payload))
                    }
                    Err(err) => {
                        error!("start enrollment error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc ActivateUser (ActivateUserRequest) returns (google.protobuf.Empty)
            Some(core_request::Payload::ActivateUser(request)) => {
                match boxed(
                    services
                        .enrollment
                        .activate_user(request, received.device_info),
                )
                .await
                {
                    Ok(()) => Some(core_response::Payload::Empty(())),
                    Err(err) => {
                        error!("activate user error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc CreateDevice (NewDevice) returns (DeviceConfigResponse)
            Some(core_request::Payload::NewDevice(request)) => {
                match boxed(
                    services
                        .enrollment
                        .create_device(request, received.device_info),
                )
                .await
                {
                    Ok(response_payload) => {
                        Some(core_response::Payload::DeviceConfig(response_payload))
                    }
                    Err(err) => {
                        error!("create device error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc GetNetworkInfo (ExistingDevice) returns (DeviceConfigResponse)
            Some(core_request::Payload::ExistingDevice(request)) => {
                match boxed(
                    services
                        .enrollment
                        .get_network_info(request, received.device_info),
                )
                .await
                {
                    Ok(response_payload) => {
                        Some(core_response::Payload::DeviceConfig(response_payload))
                    }
                    Err(err) => {
                        error!("get network info error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc RequestPasswordReset (PasswordResetInitializeRequest) returns (google.protobuf.Empty)
            Some(core_request::Payload::PasswordResetInit(request)) => {
                match boxed(
                    services
                        .password_reset
                        .request_password_reset(request, received.device_info),
                )
                .await
                {
                    Ok(()) => Some(core_response::Payload::Empty(())),
                    Err(err) => {
                        error!("password reset init error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc StartPasswordReset (PasswordResetStartRequest) returns (PasswordResetStartResponse)
            Some(core_request::Payload::PasswordResetStart(request)) => {
                match boxed(
                    services
                        .password_reset
                        .start_password_reset(request, received.device_info),
                )
                .await
                {
                    Ok(response_payload) => {
                        Some(core_response::Payload::PasswordResetStart(response_payload))
                    }
                    Err(err) => {
                        error!("password reset start error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc ResetPassword (PasswordResetRequest) returns (google.protobuf.Empty)
            Some(core_request::Payload::PasswordReset(request)) => {
                match boxed(
                    services
                        .password_reset
                        .reset_password(request, received.device_info),
                )
                .await
                {
                    Ok(()) => Some(core_response::Payload::Empty(())),
                    Err(err) => {
                        error!("password reset error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc ClientMfaStart (ClientMfaStartRequest) returns (ClientMfaStartResponse)
            Some(core_request::Payload::ClientMfaStart(request)) => {
                match boxed(
                    services
                        .client_mfa
                        .legacy_mfa_start(request, received.device_info),
                )
                .await
                {
                    Ok(response_payload) => {
                        Some(core_response::Payload::ClientMfaStart(response_payload))
                    }
                    Err(MfaStartRejection::Status(err)) => {
                        error!("client MFA start error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc MfaFlowStart (MfaFlowStartRequest) returns (MfaFlowStartResponse)
            Some(core_request::Payload::MfaFlowStart(request)) => {
                match boxed(
                    services
                        .client_mfa
                        .mfa_flow_start(request, received.device_info),
                )
                .await
                {
                    Ok(response) => Some(core_response::Payload::MfaFlowStart(response)),
                    Err(MfaStartRejection::Status(err)) => {
                        error!("client MFA flow start error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc MfaFlowStepStart (MfaFlowStepStartRequest) returns (MfaFlowStepStartResponse)
            Some(core_request::Payload::MfaFlowStepStart(request)) => {
                match boxed(services.client_mfa.mfa_flow_step_start(request)).await {
                    Ok(response) => Some(core_response::Payload::MfaFlowStepStart(response)),
                    Err(err) => {
                        error!("client MFA flow step start error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc ClientRemoteMfaFinish (ClientRemoteMfaFinishRequest) returns (ClientRemoteMfaFinishResponse)
            Some(core_request::Payload::AwaitRemoteMfaFinish(request)) => {
                match boxed(services.client_mfa.legacy_mfa_remote(
                    request,
                    response_tx.clone(),
                    received.id,
                    received.device_info,
                ))
                .await
                {
                    Ok(()) => None,
                    Err(err) => {
                        error!("Client remote MFA finish error: {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc MfaFlowStepFinish (MfaFlowStepFinishRequest) returns (MfaFlowStepFinishResponse)
            Some(core_request::Payload::MfaFlowStepFinish(request)) => {
                match boxed(
                    services
                        .client_mfa
                        .mfa_flow_step_finish(request, received.device_info),
                )
                .await
                {
                    Ok(response) => Some(core_response::Payload::MfaFlowStepFinish(response)),
                    Err(err) => {
                        error!("client MFA flow step finish error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc MfaFlowRemote (MfaFlowRemoteRequest) returns (MfaFlowRemoteResponse)
            Some(core_request::Payload::MfaFlowRemote(request)) => {
                match boxed(services.client_mfa.mfa_flow_remote(
                    request,
                    response_tx.clone(),
                    received.id,
                    received.device_info,
                ))
                .await
                {
                    Ok(()) => None,
                    Err(err) => {
                        error!("client MFA flow remote finish error: {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc MfaFlowApprove (MfaFlowApproveRequest) returns (google.protobuf.Empty)
            Some(core_request::Payload::MfaFlowApprove(request)) => {
                match boxed(
                    services
                        .client_mfa
                        .mfa_flow_approve(request, received.device_info),
                )
                .await
                {
                    Ok(()) => Some(core_response::Payload::Empty(())),
                    Err(err) => {
                        error!("client MFA flow approve error {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // Posture-only connection (location with posture policies and no MFA).
            Some(core_request::Payload::PostureConnect(request)) => {
                match boxed(
                    services
                        .client_mfa
                        .posture_connect(request, received.device_info),
                )
                .await
                {
                    Ok(response) => Some(core_response::Payload::PostureConnect(response)),
                    Err(err) => {
                        info!("posture connect refused: {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc ClientMfaFinish (ClientMfaFinishRequest) returns (ClientMfaFinishResponse)
            Some(core_request::Payload::ClientMfaFinish(request)) => {
                match boxed(
                    services
                        .client_mfa
                        .legacy_mfa_finish(request, received.device_info),
                )
                .await
                {
                    Ok(response_payload) => {
                        Some(core_response::Payload::ClientMfaFinish(response_payload))
                    }
                    Err(err) => {
                        match err.code() {
                            Code::FailedPrecondition => {
                                // User not yet done with OIDC authentication. Don't log it
                                // as an error.
                                debug!("Client MFA finish error: {err}");
                            }
                            _ => {
                                // Log other errors as errors.
                                error!("Client MFA finish error: {err}");
                            }
                        }
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc ClientMfaOidcAuthenticate (ClientMfaOidcAuthenticateRequest) returns (google.protobuf.Empty)
            Some(core_request::Payload::ClientMfaOidcAuthenticate(request)) => {
                match boxed(services.openid.mfa_authenticate(
                    request,
                    received.device_info,
                    &services.client_mfa,
                    &services.mfa_config,
                ))
                .await
                {
                    Ok(()) => Some(core_response::Payload::Empty(())),
                    Err(err) => {
                        warn!("OpenID MFA sign-in through Edge failed: {}", err.message);
                        Some(core_response::Payload::CoreError(err))
                    }
                }
            }
            // rpc LocationInfo (LocationInfoRequest) returns (LocationInfoResponse)
            Some(core_request::Payload::InstanceInfo(request)) => {
                match boxed(services.polling.info(request, received.device_info)).await {
                    Ok(response) => Some(core_response::Payload::InstanceInfo(response)),
                    Err(err) => {
                        debug!("Config polling refused: {err}");
                        Some(core_response::Payload::CoreError(err.into()))
                    }
                }
            }
            // rpc AuthInfo (AuthInfoRequest) returns (AuthInfoResponse)
            Some(core_request::Payload::AuthInfo(request)) => {
                match boxed(services.openid.auth_info(
                    request,
                    received.device_info,
                    &services.client_mfa,
                    &services.mfa_config,
                ))
                .await
                {
                    Ok(response) => Some(core_response::Payload::AuthInfo(response)),
                    Err(err) => {
                        debug!("OpenID sign-in through Edge not started: {}", err.message);
                        Some(core_response::Payload::CoreError(err))
                    }
                }
            }
            // Remote enrollment of a directory user with their directory password.
            Some(core_request::Payload::DirectoryEnrollment(request)) => {
                match boxed(
                    services
                        .enrollment
                        .directory_enrollment(request, received.device_info),
                )
                .await
                {
                    Ok(response) => Some(core_response::Payload::DirectoryEnrollment(response)),
                    Err(err) => {
                        debug!("Directory enrollment through Edge refused: {}", err.message);
                        Some(core_response::Payload::CoreError(err))
                    }
                }
            }
            // rpc AuthCallback (AuthCallbackRequest) returns (AuthCallbackResponse)
            Some(core_request::Payload::AuthCallback(request)) => {
                match boxed(services.openid.auth_callback(request, received.device_info)).await {
                    Ok(response) => Some(core_response::Payload::AuthCallback(response)),
                    Err(err) => {
                        warn!(
                            "OpenID enrollment sign-in through Edge failed: {}",
                            err.message
                        );
                        Some(core_response::Payload::CoreError(err))
                    }
                }
            }
            None => None,
            Some(core_request::Payload::AcmeCertificate(cert)) => {
                info!("Received AcmeCertificate from proxy, saving and broadcasting");
                let acme_cert_expiry = parse_cert_expiry(&cert.cert_pem);
                match boxed(Certificates::get_or_default(&pool)).await {
                    Ok(mut certs) => {
                        certs.proxy_http_cert_pem = Some(cert.cert_pem.clone());
                        certs.proxy_http_cert_key_pem = Some(cert.key_pem.clone());
                        certs.acme_account_credentials =
                            Some(cert.account_credentials_json.clone());
                        certs.proxy_http_cert_expiry = acme_cert_expiry;
                        certs.proxy_http_cert_source =
                            xguard_common::db::models::ProxyCertSource::LetsEncrypt;
                        if let Err(err) = boxed(certs.save(&pool)).await {
                            error!("Failed to save ACME certificate to certificates: {err}");
                        } else {
                            info!("ACME certificate saved to certificates");
                            let https_certs = CoreResponse {
                                id: 0,
                                payload: Some(core_response::Payload::HttpsCerts(HttpsCerts {
                                    cert_pem: cert.cert_pem,
                                    key_pem: cert.key_pem,
                                })),
                            };
                            if let Ok(map) = handler_tx_map.read() {
                                for (pid, handler_tx) in map.iter() {
                                    debug!("Broadcasting HttpsCerts to proxy {pid}");
                                    let _ = handler_tx.send(https_certs.clone());
                                }
                            }
                        }
                    }
                    Err(err) => {
                        error!("Failed to load certificates for ACME save: {err}");
                    }
                }
                None
            }
        };

        if let Some(payload) = payload {
            let req = CoreResponse {
                id: received.id,
                payload: Some(payload),
            };
            let _ = response_tx.send(req);
        }
        Ok(())
    }

    /// Processes incoming requests from the proxy over an active gRPC stream.
    ///
    /// This loop receives `CoreRequest` messages from the proxy, dispatches
    /// them to the appropriate Core-side handlers, and sends corresponding
    /// `CoreResponse` messages back through the stream. Certain requests may
    /// also register routing state for future responses.
    async fn message_loop(
        &mut self,
        tx: UnboundedSender<CoreResponse>,
        gateway_tx: UnboundedSender<GatewayCommand>,
        resp_stream: &mut Streaming<CoreRequest>,
    ) -> Result<(), ProxyError> {
        let mut tasks = JoinSet::new();
        'message: loop {
            tokio::select! {
                biased;
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    match result {
                        Ok((request_id, Ok(()))) => debug!("Request {request_id} completed"),
                        Ok((request_id, Err(err))) => {
                            error!("Request {request_id} failed: {err}");
                            Self::send_internal_error(&tx, request_id);
                        }
                        Err(err) => error!("Request task failed or panicked: {err}"),
                    }
                }
                message = resp_stream.message() => {
                    match message {
                        Ok(None) => {
                            info!("stream was closed by the sender");
                            break 'message;
                        }
                        Ok(Some(request)) => {
                            debug!("Received message from proxy; ID={}", request.id);
                            let services = Arc::clone(&self.services);
                            let handler_tx_map = Arc::clone(&self.handler_tx_map);
                            let pool = self.pool.clone();
                            let response_tx = tx.clone();
                            let gateway_tx = gateway_tx.clone();
                            let request_id = request.id;
                            let permit = match Arc::clone(&self.semaphore).try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(TryAcquireError::NoPermits) => {
                                    Self::send_error(
                                        &tx,
                                        request_id,
                                        Code::ResourceExhausted,
                                        "BIDI request concurrency limit reached",
                                    );
                                    continue;
                                }
                                Err(TryAcquireError::Closed) => {
                                    debug!("ProxyManager semaphore was closed");
                                    break 'message;
                                }
                            };
                            tasks.spawn(async move {
                                // Keep the semaphore permit owned by the task. It is released automatically
                                // when the request task finishes, allowing another request to start.
                                let _permit = permit;
                                let result = Self::handle_request(
                                    pool,
                                    request,
                                    response_tx,
                                    services,
                                    gateway_tx,
                                    handler_tx_map,
                                ).await;
                                (request_id, result)
                            });
                        }
                        Err(err) => {
                            error!("Disconnected from Edge at {}: {err}", self.url);
                            self.mark_disconnected().await?;
                            break 'message;
                        }
                    }
                }
            }
        }
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((request_id, Ok(()))) => {
                    debug!("Request {request_id} completed during shutdown");
                }
                Ok((request_id, Err(err))) => {
                    error!("Request {request_id} failed during shutdown: {err}");
                }
                Err(err) => debug!("Request task cancelled during shutdown: {err}"),
            }
        }
        Ok(())
    }
}

fn boxed<'a, T>(
    fut: impl Future<Output = T> + Send + 'a,
) -> Pin<Box<dyn Future<Output = T> + Send + 'a>> {
    Box::pin(fut)
}

#[cfg(test)]
impl ProxyHandler {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_test_socket(
        pool: PgPool,
        url: Url,
        tx: &ProxyTxSet,
        remote_mfa_responses: RemoteAuthWaiters,
        shutdown_signal: Arc<Mutex<ShutdownReceiver>>,
        proxy_id: Id,
        proxy_cookie_key: Key,
        socket_path: PathBuf,
        semaphore: Arc<Semaphore>,
    ) -> Self {
        let handler_tx_map: HandlerTxMap = Arc::new(RwLock::new(HashMap::new()));
        let mut handler = Self::new(
            pool,
            url,
            tx,
            remote_mfa_responses,
            shutdown_signal,
            proxy_id,
            proxy_cookie_key,
            handler_tx_map,
            semaphore,
        );
        handler.test_transport = ProxyTestTransport::with_socket_path(socket_path);
        handler
    }

    pub(crate) fn attach_test_support(&mut self, test_support: ProxyManagerTestSupport) {
        self.test_support = Some(test_support);
    }

    /// Override the transport to connect via a Unix socket instead of TLS.
    ///
    /// Used in manager-level tests where the handler must share the manager's
    /// `handler_tx_map` (constructed via `from_proxy`) but still reach a mock
    /// proxy over a Unix socket.
    pub(crate) fn set_test_socket_path(&mut self, socket_path: PathBuf) {
        self.test_transport = ProxyTestTransport::with_socket_path(socket_path);
    }

    fn handler_retry_delay(&self) -> Duration {
        self.test_support
            .as_ref()
            .map_or(TEN_SECS, ProxyManagerTestSupport::handler_reconnect_delay)
    }

    async fn connect_channel(
        &self,
        certs_rx: watch::Receiver<Arc<HashMap<Id, String>>>,
    ) -> Result<Channel, ProxyError> {
        if let Some(socket_path) = self.test_transport.socket_path().cloned() {
            // Build a minimal endpoint for the Unix socket connector.
            // The scheme and host are irrelevant - the connector ignores the URI.
            let endpoint = Endpoint::from_shared(self.url.to_string())?;
            return Ok(endpoint.connect_with_connector_lazy(tower::service_fn(
                move |_: tonic::transport::Uri| {
                    let socket_path = socket_path.clone();
                    async move {
                        Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                            tokio::net::UnixStream::connect(socket_path).await?,
                        ))
                    }
                },
            )));
        }

        self.connect_channel_mtls(certs_rx).await
    }

    /// Single-iteration version of `run()` for use in tests.
    ///
    /// Attempts one connection to the proxy, processes the bidirectional
    /// stream until it closes or an error occurs, then returns. Does not
    /// retry or loop.
    pub(crate) async fn run_once(
        mut self,
        tx_set: ProxyTxSet,
        incompatible_components: Arc<RwLock<IncompatibleComponents>>,
        certs_rx: watch::Receiver<Arc<HashMap<Id, String>>>,
    ) -> Result<(), ProxyError> {
        let parsed_version = Version::parse(VERSION)?;
        let channel = self.connect_channel(certs_rx).await?;

        debug!(
            "Connecting to proxy at {} (test, single iteration)",
            self.url
        );
        let interceptor = ClientVersionInterceptor::new(parsed_version);
        let mut client = ProxyClient::with_interceptor(channel, interceptor);
        self.client = Some(client.clone());
        let (tx, rx) = mpsc::unbounded_channel();
        let response = match client.bidi(UnboundedReceiverStream::new(rx)).await {
            Ok(response) => response,
            Err(err) => {
                self.mark_disconnected().await?;
                return Err(err.into());
            }
        };
        let maybe_info = ComponentInfo::from_metadata(response.metadata());

        let (version, info) = get_tracing_variables(&maybe_info);
        let proxy_is_supported = is_proxy_version_supported(Some(&version));

        let span = tracing::info_span!("proxy_bidi", component = %XGuardComponent::Proxy,
            version = version.to_string(), info);
        let _guard = span.enter();
        if !proxy_is_supported {
            let maybe_version = if version == VERSION_ZERO {
                None
            } else {
                Some(version)
            };
            let data = IncompatibleProxyData::new(maybe_version);
            data.insert(&incompatible_components);
            self.mark_disconnected().await?;
            return Ok(());
        }
        self.mark_connected(&version).await?;
        IncompatibleComponents::remove_proxy(&incompatible_components);

        info!("Connected to proxy at {} (test)", self.url);
        let mut resp_stream = response.into_inner();

        let initial_info = InitialInfo {
            private_cookies_key: self.proxy_cookie_key.master().to_vec(),
        };
        let _ = tx.send(CoreResponse {
            id: 0,
            payload: Some(core_response::Payload::InitialInfo(initial_info)),
        });

        // Push public settings to the test proxy.
        // Skipped when the settings cannot be read: the Edge then keeps its previous values
        // rather than being told to show pages the admin may have hidden.
        if let Some((client, downloads)) = load_edge_settings(&self.pool).await {
            let public_settings =
                edge_public_settings(&Settings::get_current_settings(), &client, &downloads);
            let _ = tx.send(CoreResponse {
                id: 0,
                payload: Some(core_response::Payload::PublicSettings(public_settings)),
            });
        }

        let result = self
            .message_loop(tx, tx_set.wireguard.clone(), &mut resp_stream)
            .await;
        self.mark_disconnected().await?;
        result
    }
}

/// Groups Core-side service handlers used to process requests originating
/// from a proxy instance.
///
/// Each `ProxyServices` instance is owned by a single `Proxy` and provides
/// the concrete handlers for enrollment and authentication-related
/// requests received over the gRPC bidirectional stream.
struct ProxyServices {
    enrollment: EnrollmentServer,
    password_reset: PasswordResetServer,
    client_mfa: ClientMfaServer,
    mfa_config: MfaConfigServer,
    openid: OpenIdServer,
    polling: PollingServer,
    // Directory-sync channels are reserved for the XGuard LDAP / directory sync rebuild.
    #[allow(dead_code)]
    ldap: UnboundedSender<LdapSyncEventType>,
    #[allow(dead_code)]
    dirsync: UnboundedSender<DirectorySyncEvent>,
    #[allow(dead_code)]
    event_tx: UnboundedSender<ApiEvent>,
}

impl ProxyServices {
    pub fn new(pool: &PgPool, tx: &ProxyTxSet, remote_mfa_responses: RemoteAuthWaiters) -> Self {
        let enrollment = EnrollmentServer::new(
            pool.clone(),
            tx.wireguard.clone(),
            tx.bidi_events.clone(),
            tx.ldap.clone(),
            tx.event_tx.clone(),
        );
        let password_reset =
            PasswordResetServer::new(pool.clone(), tx.bidi_events.clone(), tx.ldap.clone());
        let client_mfa = ClientMfaServer::new(
            pool.clone(),
            tx.wireguard.clone(),
            tx.bidi_events.clone(),
            remote_mfa_responses,
        );
        let mfa_config = MfaConfigServer::new(pool.clone(), tx.event_tx.clone());
        let openid = OpenIdServer::new(pool.clone());
        let polling = PollingServer::new(pool.clone());

        Self {
            enrollment,
            password_reset,
            client_mfa,
            mfa_config,
            openid,
            polling,
            ldap: tx.ldap.clone(),
            dirsync: tx.dirsync.clone(),
            event_tx: tx.event_tx.clone(),
        }
    }
}

/// Parse the `not_after` expiry timestamp from a PEM-encoded certificate.
///
/// Returns `None` if the PEM is unparseable (e.g. empty or malformed), so the
/// caller can still proceed without a stored expiry.
fn parse_cert_expiry(cert_pem: &str) -> Option<NaiveDateTime> {
    use xguard_certs::{CertificateInfo, parse_pem_certificate};

    let der = parse_pem_certificate(cert_pem)
        .map_err(|e| warn!("Failed to parse ACME cert PEM for expiry: {e}"))
        .ok()?;
    CertificateInfo::from_der(&der)
        .map(|info| info.not_after)
        .map_err(|e| warn!("Failed to extract expiry from ACME cert: {e}"))
        .ok()
}
