//! Sign-in with the external OpenID provider through Edge (see [`xguard_core::sso::edge`]):
//!
//! - **Enrollment portal:** "Sign in with …" finds, links or creates the account with the same
//!   strict rules as the web sign-in ([`sso::resolve_user`]) and returns a fresh enrollment
//!   token, which Edge uses to start enrollment or to configure the desktop client.
//! - **VPN MFA:** completes the OpenID step of the desktop client's MFA attempt.
//! - **MFA configuration:** authorizes a desktop client's MFA configuration session.

use std::net::IpAddr;

use sqlx::PgPool;
use tonic::Status;
use xguard_common::db::models::Settings;
use xguard_common::types::AuthFlowType;
use xguard_core::{
    db::models::enrollment::{ENROLLMENT_TOKEN_TYPE, Token},
    grpc::{proxy::client_mfa::ClientMfaServer, utils::parse_client_ip_agent},
    sso::{
        self, LinkError,
        edge::{self, EdgeError, FinishError, Purpose, parse_mfa_state},
        provider::ProviderConfig,
    },
};
use xguard_proto::{
    client_types::{AuthFlowType as ProtoAuthFlowType, AuthInfoRequest, OpenIdProviderKind},
    proxy::{
        AuthCallbackRequest, AuthCallbackResponse, AuthInfoResponse,
        ClientMfaOidcAuthenticateRequest, CoreError, CoreErrorCode, DeviceInfo,
    },
};

use super::MfaConfigServer;

fn verification_failed() -> CoreError {
    CoreError::unauthenticated("unauthorized").with_code(CoreErrorCode::OidcVerificationFailed)
}

fn edge_error(err: EdgeError, flow: AuthFlowType) -> CoreError {
    match err {
        EdgeError::Expired => match flow {
            AuthFlowType::Mfa => CoreError::unauthenticated(err.to_string())
                .with_code(CoreErrorCode::MfaSessionExpired),
            AuthFlowType::Enrollment => CoreError::unauthenticated(err.to_string()),
        },
        EdgeError::Invalid(message) => CoreError::invalid_argument(message),
        EdgeError::Config(message) => {
            error!("OpenID sign-in through Edge is misconfigured: {message}");
            CoreError::failed_precondition(message)
        }
        EdgeError::Flow(err) => {
            warn!("OpenID sign-in through Edge failed: {err}");
            verification_failed()
        }
    }
}

fn client_ip(info: Option<&DeviceInfo>) -> Option<IpAddr> {
    info.and_then(|info| info.ip_address.parse().ok())
}

pub(crate) struct OpenIdServer {
    pool: PgPool,
}

impl OpenIdServer {
    #[must_use]
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn provider(&self) -> Result<ProviderConfig, CoreError> {
        ProviderConfig::enabled(&self.pool)
            .await
            .map_err(|err| {
                error!("Failed to read the OpenID provider: {err}");
                CoreError::internal("unexpected error")
            })?
            .ok_or_else(|| CoreError::not_found("no external OpenID provider is enabled"))
    }

    /// Where Edge should send the browser to sign in, for enrollment or an MFA step.
    #[instrument(skip_all)]
    pub(crate) async fn auth_info(
        &self,
        request: AuthInfoRequest,
        info: Option<DeviceInfo>,
        client_mfa: &ClientMfaServer,
        mfa_config: &MfaConfigServer,
    ) -> Result<AuthInfoResponse, CoreError> {
        let flow = match request.auth_flow_type() {
            ProtoAuthFlowType::Enrollment => AuthFlowType::Enrollment,
            ProtoAuthFlowType::Mfa => AuthFlowType::Mfa,
            // Pre-2.0 clients chose their own redirect URL, which Core no longer accepts.
            ProtoAuthFlowType::Unspecified => {
                return Err(CoreError::invalid_argument("missing sign-in flow type"));
            }
        };
        let config = self.provider().await?;
        let purpose = match flow {
            AuthFlowType::Enrollment => Purpose::Enrollment,
            AuthFlowType::Mfa => {
                let state = request.state.as_deref().unwrap_or_default();
                let (token, attempt_id) = parse_mfa_state(state).ok_or_else(|| {
                    debug!("OpenID MFA requested with a malformed session reference");
                    CoreError::invalid_argument("invalid MFA session reference")
                })?;
                if let Some(target) = client_mfa.oidc_begin(token, attempt_id).await? {
                    Purpose::VpnMfa(target)
                } else if attempt_id.is_none()
                    && let Some(target) = mfa_config.oidc_begin(token).await?
                {
                    Purpose::MfaConfig(target)
                } else {
                    debug!("OpenID MFA requested for an unknown or expired session");
                    return Err(
                        CoreError::unauthenticated("MFA session not found or expired")
                            .with_code(CoreErrorCode::MfaSessionExpired),
                    );
                }
            }
        };
        let started = edge::start(&config, purpose, client_ip(info.as_ref()))
            .await
            .map_err(|err| edge_error(err, flow))?;
        debug!("Started an OpenID sign-in through Edge ({flow:?})");
        Ok(AuthInfoResponse {
            url: started.url,
            csrf_token: started.state,
            nonce: started.binding,
            button_display_name: started.display_name,
            provider_kind: OpenIdProviderKind::from(started.kind) as i32,
        })
    }

    /// Finishes an enrollment portal sign-in and returns a new enrollment token.
    #[instrument(skip_all)]
    pub(crate) async fn auth_callback(
        &self,
        request: AuthCallbackRequest,
        info: Option<DeviceInfo>,
    ) -> Result<AuthCallbackResponse, CoreError> {
        let config = self.provider().await?;
        let (identity, purpose) = edge::finish(
            &config,
            AuthFlowType::Enrollment,
            &request.nonce,
            None,
            &request.code,
        )
        .await
        .map_err(|err| edge_error(err.error, AuthFlowType::Enrollment))?;
        if purpose != Purpose::Enrollment {
            return Err(edge_error(EdgeError::Expired, AuthFlowType::Enrollment));
        }
        let user = match sso::resolve_user(&self.pool, &identity).await {
            Ok(user) => user,
            Err(LinkError::Database(err)) => {
                error!("Failed to resolve the OpenID account: {err}");
                return Err(CoreError::internal("unexpected error"));
            }
            Err(err) => {
                warn!("Enrollment portal OpenID sign-in refused: {err}");
                return Err(Status::permission_denied(err.to_string()).into());
            }
        };
        if !user.is_active {
            warn!(
                "Disabled user {} tried to enroll through OpenID",
                user.username
            );
            return Err(Status::permission_denied("the account is disabled").into());
        }

        let settings = Settings::get_current_settings();
        let public_url =
            edge::edge_public_url().map_err(|err| edge_error(err, AuthFlowType::Enrollment))?;
        let mut transaction = self.pool.begin().await.map_err(|err| {
            error!("Failed to begin a transaction: {err}");
            CoreError::internal("unexpected error")
        })?;
        // Earlier unused enrollment tokens of this user stop working.
        Token::delete_unused_user_tokens_of_type(&mut *transaction, user.id, ENROLLMENT_TOKEN_TYPE)
            .await
            .map_err(Status::from)?;
        let token = Token::new(
            user.id,
            settings.default_admin_id,
            Some(user.email.clone()),
            settings.enrollment_token_timeout().as_secs(),
            Some(ENROLLMENT_TOKEN_TYPE.to_owned()),
        );
        token.save(&mut *transaction).await.map_err(Status::from)?;
        transaction.commit().await.map_err(|err| {
            error!("Failed to commit the enrollment token: {err}");
            CoreError::internal("unexpected error")
        })?;
        let ip = parse_client_ip_agent(&info)
            .map(|(ip, _)| ip.to_string())
            .unwrap_or_default();
        info!(
            "User {} signed in through OpenID on the enrollment portal from {ip}",
            user.username
        );
        Ok(AuthCallbackResponse {
            url: public_url.to_string(),
            token: token.id,
        })
    }

    /// Finishes an OpenID MFA step (VPN MFA or MFA configuration).
    #[instrument(skip_all)]
    pub(crate) async fn mfa_authenticate(
        &self,
        request: ClientMfaOidcAuthenticateRequest,
        info: Option<DeviceInfo>,
        client_mfa: &ClientMfaServer,
        mfa_config: &MfaConfigServer,
    ) -> Result<(), CoreError> {
        let ip = parse_client_ip_agent(&info)
            .map(|(ip, _)| ip)
            .map_err(CoreError::invalid_argument)?;
        let config = self.provider().await?;
        let result = edge::finish(
            &config,
            AuthFlowType::Mfa,
            &request.nonce,
            Some(&request.state),
            &request.code,
        )
        .await;
        let (identity, purpose) = match result {
            Ok(result) => result,
            Err(FinishError { error, purpose }) => {
                // Audit sign-ins for a VPN MFA attempt that the provider or Core refused.
                if let (EdgeError::Flow(reason), Some(Purpose::VpnMfa(target))) = (&error, &purpose)
                {
                    client_mfa
                        .oidc_failed(target, ip, &reason.to_string())
                        .await;
                }
                return Err(edge_error(error, AuthFlowType::Mfa));
            }
        };
        match purpose {
            Purpose::VpnMfa(target) => client_mfa.oidc_complete(&target, &identity, ip).await,
            Purpose::MfaConfig(target) => mfa_config.oidc_complete(&target, &identity).await,
            Purpose::Enrollment => Err(edge_error(EdgeError::Expired, AuthFlowType::Mfa)),
        }
    }
}
