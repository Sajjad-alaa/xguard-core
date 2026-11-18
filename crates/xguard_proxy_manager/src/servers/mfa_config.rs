use sqlx::PgPool;
use tokio::sync::mpsc::UnboundedSender;
use tonic::Status;
use xguard_common::{
    db::{
        Id,
        models::{
            Device, MFAMethod, Settings, User, polling_token::PollingToken,
            vpn_client_session::VpnClientMfaMethod,
        },
    },
    random::gen_alphanumeric,
};
use xguard_core::{
    db::models::enrollment::{
        MFA_CONFIG_SESSION_TIMEOUT, MFA_CONFIG_TOKEN_TYPE, MfaConfigAuthState, Token, TokenError,
    },
    events::{ApiEvent, ApiEventType},
    fido2::{self, Fido2Assertion, Fido2Error},
    mail::templates::mfa_code_mail,
    sso::{
        edge::{self, MfaConfigTarget, subject_matches},
        flow::Identity,
    },
};
use xguard_proto::{
    client_types::{
        MfaConfigAuthorizeRequest, MfaConfigAuthorizeResponse, MfaConfigEndRequest,
        MfaConfigFido2ChallengeRequest, MfaConfigFido2ChallengeResponse, MfaConfigSendCodeRequest,
        MfaConfigSendCodeResponse, MfaConfigStartRequest, MfaConfigStartResponse, MfaMethod,
    },
    proxy::{CoreError, CoreErrorCode, DeviceInfo},
};

use super::mfa_setup::{RecoveryCodesPolicy, finalize_mfa_factor};

fn session_expired() -> CoreError {
    CoreError::unauthenticated("MFA session not found or expired")
        .with_code(CoreErrorCode::MfaSessionExpired)
}

/// An unauthorized MFA configuration session and its user's current factor state.
struct MfaConfigSession {
    token: Token,
    user: User<Id>,
    totp_configured: bool,
    email_configured: bool,
    fido2_configured: bool,
    oidc_configured: bool,
}

impl MfaConfigSession {
    /// With no MFA at all, an email code is the fallback authorization method.
    /// MFA the client cannot use, like a software passkey, blocks it since email would bypass it.
    fn email_fallback(&self) -> bool {
        !self.user.mfa_enabled
            && !self.totp_configured
            && !self.email_configured
            && !self.fido2_configured
            && !self.oidc_configured
    }
}

/// OIDC authorization runs through Edge with the external provider.
async fn oidc_available(pool: &PgPool) -> Result<bool, Status> {
    edge::available(pool).await.map_err(|err| {
        error!("MFA config: failed to read the OpenID provider: {err}");
        Status::internal("unexpected error")
    })
}

async fn is_configured(
    pool: &PgPool,
    method: VpnClientMfaMethod,
    user: &User<Id>,
    device_id: Id,
    smtp_configured: bool,
    oidc_available: bool,
) -> Result<bool, Status> {
    method
        .is_configured(pool, user, Some(device_id), smtp_configured, oidc_available)
        .await
        .map_err(|err| {
            error!(
                "MFA config: failed to read {method:?} state for user {}: {err}",
                user.username
            );
            Status::internal("unexpected error")
        })
}

/// Loads an unauthorized MFA configuration session and its user's current factor state.
async fn load_session(pool: &PgPool, session_token: &str) -> Result<MfaConfigSession, Status> {
    let token = Token::find_by_id(pool, session_token).await?;
    if token.token_type.as_deref() != Some(MFA_CONFIG_TOKEN_TYPE) {
        error!(
            "MFA config: token {} has type {:?}, expected {MFA_CONFIG_TOKEN_TYPE}",
            token.id, token.token_type
        );
        return Err(Status::unauthenticated("invalid token"));
    }
    if token.is_expired() {
        error!("MFA config: token {} expired", token.id);
        return Err(Status::unauthenticated("invalid token"));
    }
    if token.is_used() {
        error!("MFA config: token {} is already authorized", token.id);
        return Err(Status::failed_precondition("session already authorized"));
    }
    let user = token.fetch_user(pool).await?;
    if !user.is_active {
        error!("MFA config: user {} is inactive", user.username);
        return Err(Status::permission_denied("user is inactive"));
    }
    let Some(device_id) = token.device_id else {
        error!("MFA config: token {} has no device", token.id);
        return Err(Status::internal("unexpected error"));
    };

    let smtp_configured = Settings::get_current_settings().smtp_configured();
    let oidc_available = user.openid_sub.is_some() && oidc_available(pool).await?;
    // Biometric and mobile-approve are mobile-only, carry no recovery codes and never
    // reach this flow, so they stay ignored.
    let configured = async |method| {
        is_configured(
            pool,
            method,
            &user,
            device_id,
            smtp_configured,
            oidc_available,
        )
        .await
    };
    let totp_configured = configured(VpnClientMfaMethod::Totp).await?;
    let email_configured = configured(VpnClientMfaMethod::Email).await?;
    // The owner of a key from an earlier Enterprise license must still add another factor, and the
    // email fallback would bypass the key, so FIDO2 authorizes with no license check.
    let fido2_configured = configured(VpnClientMfaMethod::Fido2).await?;
    let oidc_configured = configured(VpnClientMfaMethod::Oidc).await?;

    Ok(MfaConfigSession {
        token,
        user,
        totp_configured,
        email_configured,
        fido2_configured,
        oidc_configured,
    })
}

/// Handles MFA factor configuration requested by an already enrolled desktop client.
pub(crate) struct MfaConfigServer {
    pool: PgPool,
    event_tx: UnboundedSender<ApiEvent>,
}

impl MfaConfigServer {
    #[must_use]
    pub fn new(pool: PgPool, event_tx: UnboundedSender<ApiEvent>) -> Self {
        Self { pool, event_tx }
    }

    /// Starts an MFA configuration session for the device identified by the polling token.
    ///
    /// The returned token remains unused until the user proves an existing factor.
    /// The client requests an email code with `mfa_config_send_code` and a FIDO2 challenge with
    /// `mfa_config_fido2_challenge`; OIDC runs through Edge's OpenID MFA page.
    /// A user without MFA authorizes with an email code instead. A user whose MFA cannot
    /// authorize here gets no session, signalled by no methods and no email fallback.
    #[instrument(skip_all)]
    pub(crate) async fn mfa_config_start(
        &self,
        request: MfaConfigStartRequest,
    ) -> Result<MfaConfigStartResponse, Status> {
        debug!(
            "Starting MFA configuration for device pubkey {}",
            request.pubkey
        );
        // Authenticate before any lookup so error codes cannot probe which pubkeys exist.
        if request.token.is_empty() {
            error!("MFA config start: missing polling token");
            return Err(Status::unauthenticated("missing token"));
        }
        let polling_token = PollingToken::find(&self.pool, &request.token)
            .await
            .map_err(|err| {
                error!("MFA config start: failed to look up polling token: {err}");
                Status::internal("unexpected error")
            })?
            .ok_or_else(|| {
                error!("MFA config start: unknown polling token");
                Status::unauthenticated("invalid token")
            })?;
        let Ok(Some(device)) = Device::find_by_pubkey(&self.pool, &request.pubkey).await else {
            error!(
                "MFA config start: device with pubkey {} not found",
                request.pubkey
            );
            return Err(Status::unauthenticated("invalid token"));
        };
        if polling_token.device_id != device.id {
            error!(
                "MFA config start: polling token belongs to device {} but request claims device {}",
                polling_token.device_id, device.id
            );
            return Err(Status::unauthenticated("token does not match device"));
        }
        let Ok(Some(mut user)) = User::find_by_id(&self.pool, device.user_id).await else {
            error!("MFA config start: user {} not found", device.user_id);
            return Err(Status::internal("user not found"));
        };
        if !user.is_active {
            error!("MFA config start: user {} is inactive", user.username);
            return Err(Status::permission_denied("user is inactive"));
        }

        let settings = Settings::get_current_settings();
        let smtp_configured = settings.smtp_configured();
        let oidc_available = user.openid_sub.is_some() && oidc_available(&self.pool).await?;
        let mut available_methods = Vec::with_capacity(VpnClientMfaMethod::CONFIG_AUTHORIZE.len());
        for method in VpnClientMfaMethod::CONFIG_AUTHORIZE {
            if is_configured(
                &self.pool,
                method,
                &user,
                device.id,
                smtp_configured,
                oidc_available,
            )
            .await?
            {
                available_methods.push(MfaMethod::from(method) as i32);
            }
        }

        if available_methods.is_empty() && user.mfa_enabled {
            info!(
                "User {} has MFA that cannot authorize MFA configuration from device {}",
                user.username, device.name
            );
            return Ok(MfaConfigStartResponse {
                session_token: String::new(),
                available_methods,
                email_fallback: false,
                deadline_timestamp: 0,
            });
        }

        let mut transaction = self.pool.begin().await.map_err(|err| {
            error!("MFA config start: failed to begin transaction: {err}");
            Status::internal("unexpected error")
        })?;

        let email_fallback = available_methods.is_empty();
        if email_fallback {
            if !smtp_configured {
                error!(
                    "MFA config start: user {} has no MFA method and SMTP is not configured",
                    user.username
                );
                return Err(Status::failed_precondition("SMTP not configured"));
            }
            // Rotate the secret because a disabled email factor retains its old secret.
            user.new_email_secret(&mut *transaction)
                .await
                .map_err(|err| {
                    error!("MFA config start: failed to create email secret: {err}");
                    Status::internal("unexpected error")
                })?;
        }

        Token::delete_user_tokens_of_type(&mut *transaction, user.id, MFA_CONFIG_TOKEN_TYPE)
            .await?;
        let mut token = Token::new(
            user.id,
            None,
            None,
            MFA_CONFIG_SESSION_TIMEOUT.as_secs(),
            Some(MFA_CONFIG_TOKEN_TYPE.to_owned()),
        );
        token.device_id = Some(device.id);
        token.save(&mut *transaction).await?;

        transaction.commit().await.map_err(|err| {
            error!("MFA config start: failed to commit transaction: {err}");
            Status::internal("unexpected error")
        })?;
        info!(
            "User {} started MFA configuration from device {} (email fallback: {email_fallback})",
            user.username, device.name
        );

        Ok(MfaConfigStartResponse {
            session_token: token.id,
            available_methods,
            email_fallback,
            deadline_timestamp: token.expires_at.and_utc().timestamp(),
        })
    }

    /// Sends the email code used to authorize an MFA configuration session.
    ///
    /// The client calls this after the user selects Email, including the no-factor fallback.
    #[instrument(skip_all)]
    pub(crate) async fn mfa_config_send_code(
        &self,
        request: MfaConfigSendCodeRequest,
    ) -> Result<MfaConfigSendCodeResponse, Status> {
        debug!("Sending MFA configuration email code");
        let session = load_session(&self.pool, &request.session_token).await?;
        let user = &session.user;
        if !session.email_configured && !session.email_fallback() {
            error!(
                "MFA config send code: user {} has no configured email MFA",
                user.username
            );
            return Err(Status::permission_denied("method not configured"));
        }

        let code = user.generate_email_mfa_code().map_err(|err| {
            error!("MFA config send code: failed to generate email code: {err}");
            Status::internal("unexpected error")
        })?;
        let mut conn = self.pool.acquire().await.map_err(|err| {
            error!("MFA config send code: failed to acquire connection: {err}");
            Status::internal("unexpected error")
        })?;
        mfa_code_mail(&user.email, &mut conn, &user.first_name, &code, None, true)
            .await
            .map_err(|err| {
                error!("MFA config send code: failed to send email code: {err}");
                Status::internal("unexpected error")
            })?;
        info!(
            "Sent MFA configuration email code to user {}",
            user.username
        );

        Ok(MfaConfigSendCodeResponse {})
    }

    /// Issues the single-use challenge for authorizing an MFA configuration session with FIDO2.
    ///
    /// A new challenge replaces any pending one; it can be answered once, within
    /// [`fido2::CHALLENGE_TTL`].
    #[instrument(skip_all)]
    pub(crate) async fn mfa_config_fido2_challenge(
        &self,
        request: MfaConfigFido2ChallengeRequest,
    ) -> Result<MfaConfigFido2ChallengeResponse, Status> {
        debug!("Issuing a FIDO2 challenge for MFA configuration");
        let session = load_session(&self.pool, &request.session_token).await?;
        if !session.fido2_configured {
            error!(
                "MFA config FIDO2 challenge: user {} has no security key for VPN MFA",
                session.user.username
            );
            return Err(Status::permission_denied("method not configured"));
        }
        let issued = fido2::issue_challenge(&self.pool, session.user.id)
            .await
            .map_err(|err| match err {
                Fido2Error::NotConfigured => Status::permission_denied("method not configured"),
                err => {
                    error!("MFA config FIDO2 challenge: {err}");
                    Status::internal("unexpected error")
                }
            })?;
        let mut token = session.token;
        if !token
            .begin_mfa_config_fido2(&self.pool, issued.state)
            .await
            .map_err(Status::from)?
        {
            return Err(Status::failed_precondition(
                "OpenID sign-in already completed",
            ));
        }
        Ok(MfaConfigFido2ChallengeResponse {
            challenge: issued.challenge,
            credential_ids: issued.credential_ids,
        })
    }

    /// Verifies a FIDO2 assertion against the session's pending challenge, using it up.
    async fn verify_fido2_authorization(
        &self,
        token: &mut Token,
        user: &User<Id>,
        request: &MfaConfigAuthorizeRequest,
    ) -> Result<bool, Status> {
        let assertion = Fido2Assertion {
            rp_id_hash: Vec::new(),
            authenticator_data: request.auth_data.clone().unwrap_or_default(),
            signature: request.signature.clone().unwrap_or_default(),
            credential_id: request.credential_id.clone().unwrap_or_default(),
        };
        if let Err(err) = assertion.validate() {
            error!("MFA config authorize: malformed FIDO2 assertion: {err}");
            return Err(Status::invalid_argument(err.to_string()));
        }
        let Some(state) = token
            .take_mfa_config_fido2(&self.pool)
            .await
            .map_err(Status::from)?
        else {
            error!(
                "MFA config authorize: no FIDO2 challenge pending for user {}",
                user.username
            );
            return Err(Status::failed_precondition(
                "no security key challenge pending",
            ));
        };
        match fido2::verify_assertion(&self.pool, user.id, &state, &assertion).await {
            Ok(key) => {
                info!(
                    "User {} answered the MFA configuration challenge with security key \"{}\"",
                    user.username, key.name
                );
                Ok(true)
            }
            Err(Fido2Error::Expired) => Err(Status::failed_precondition(
                "security key challenge expired",
            )),
            Err(Fido2Error::Rejected(message)) => {
                warn!(
                    "MFA config authorize: security key of user {} refused: {message}",
                    user.username
                );
                Ok(false)
            }
            Err(Fido2Error::NotConfigured) => Ok(false),
            Err(Fido2Error::Malformed(message)) => Err(Status::invalid_argument(message)),
            Err(err) => {
                error!("MFA config authorize: failed to verify a FIDO2 assertion: {err}");
                Err(Status::internal("unexpected error"))
            }
        }
    }

    /// Authorizes an MFA configuration session with a TOTP or email code, a FIDO2 assertion
    /// or a completed OIDC authentication.
    ///
    /// Authorization turns the token into a setup session. In the email fallback a valid code
    /// also enables the email factor and returns fresh recovery codes.
    /// For OIDC the client polls this until the Edge callback has completed the attempt.
    #[instrument(skip_all)]
    pub(crate) async fn mfa_config_authorize(
        &self,
        request: MfaConfigAuthorizeRequest,
        device_info: Option<DeviceInfo>,
    ) -> Result<MfaConfigAuthorizeResponse, Status> {
        debug!("Authorizing MFA configuration session");
        let session = load_session(&self.pool, &request.session_token).await?;
        let email_fallback = session.email_fallback();
        let MfaConfigSession {
            mut token,
            mut user,
            totp_configured,
            email_configured,
            fido2_configured,
            oidc_configured,
        } = session;

        let method = MfaMethod::try_from(request.method).map_err(|_| {
            error!("MFA config authorize: unknown method {}", request.method);
            Status::invalid_argument("unknown method")
        })?;
        let allowed = match method {
            MfaMethod::Totp => totp_configured,
            MfaMethod::Email => email_configured || email_fallback,
            MfaMethod::Fido2 => fido2_configured,
            MfaMethod::Oidc => oidc_configured,
            _ => {
                error!("MFA config authorize: method {method} cannot authorize a session");
                return Err(Status::invalid_argument("method cannot authorize"));
            }
        };
        if !allowed {
            error!(
                "MFA config authorize: user {} has no configured {method}",
                user.username
            );
            return Err(Status::permission_denied("method not configured"));
        }

        let valid = match method {
            MfaMethod::Totp => user.verify_totp_code(&request.code),
            MfaMethod::Fido2 => {
                self.verify_fido2_authorization(&mut token, &user, &request)
                    .await?
            }
            MfaMethod::Oidc => {
                if !matches!(
                    token.get_mfa_config_auth_state(),
                    Some(MfaConfigAuthState::Oidc {
                        completed: true,
                        ..
                    })
                ) {
                    debug!(
                        "MFA config authorize: OIDC authentication of user {} not completed yet",
                        user.username
                    );
                    return Err(Status::failed_precondition(
                        "OIDC authentication not completed",
                    ));
                }
                true
            }
            _ => user.verify_email_mfa_code(&request.code),
        };
        if !valid {
            error!(
                "MFA config authorize: invalid {method} code for user {}",
                user.username
            );
            return Err(Status::unauthenticated("invalid code"));
        }

        let mut transaction = self.pool.begin().await.map_err(|err| {
            error!("MFA config authorize: failed to begin transaction: {err}");
            Status::internal("unexpected error")
        })?;
        let deadline = match token
            .authorize_mfa_config_session(&mut transaction, MFA_CONFIG_SESSION_TIMEOUT.as_secs())
            .await
        {
            Ok(deadline) => deadline,
            Err(TokenError::TokenUsed) => {
                error!(
                    "MFA config authorize: a concurrent request already authorized user {}",
                    user.username
                );
                return Err(Status::failed_precondition("session already authorized"));
            }
            Err(err) => return Err(err.into()),
        };

        // In the fallback the verified code also enables email MFA, otherwise authorization
        // only opens the setup session and configuring a factor is a separate step.
        let recovery_codes = if email_fallback {
            user.enable_email_mfa(&mut *transaction)
                .await
                .map_err(|err| {
                    error!("MFA config authorize: failed to enable email MFA: {err}");
                    Status::internal("unexpected error")
                })?;
            finalize_mfa_factor(
                &self.pool,
                &self.event_tx,
                transaction,
                &mut user,
                MFAMethod::Email,
                ApiEventType::MfaEmailEnabled,
                device_info,
                RecoveryCodesPolicy::Fresh,
            )
            .await?
        } else {
            transaction.commit().await.map_err(|err| {
                error!("MFA config authorize: failed to commit transaction: {err}");
                Status::internal("unexpected error")
            })?;
            Vec::new()
        };

        info!(
            "User {} authorized MFA configuration with {method} (email fallback: {email_fallback})",
            user.username
        );

        Ok(MfaConfigAuthorizeResponse {
            deadline_timestamp: deadline.and_utc().timestamp(),
            recovery_codes,
        })
    }

    /// Starts an OpenID authorization of the MFA configuration session `session_token`, for a
    /// browser sign-in through Edge. Returns `None` when there is no such session.
    ///
    /// Each start supersedes the previous attempt, so only the latest browser sign-in counts.
    pub(crate) async fn oidc_begin(
        &self,
        session_token: &str,
    ) -> Result<Option<MfaConfigTarget>, CoreError> {
        match Token::find_by_id(&self.pool, session_token).await {
            Ok(token) if token.token_type.as_deref() == Some(MFA_CONFIG_TOKEN_TYPE) => {}
            Ok(_) | Err(TokenError::NotFound) => return Ok(None),
            Err(err) => return Err(Status::from(err).into()),
        }
        let session =
            load_session(&self.pool, session_token)
                .await
                .map_err(|status| match status.code() {
                    tonic::Code::Unauthenticated => session_expired(),
                    _ => status.into(),
                })?;
        if !session.oidc_configured {
            error!(
                "MFA config OIDC: user {} cannot authorize with OpenID",
                session.user.username
            );
            return Err(Status::permission_denied("method not configured").into());
        }
        let mut token = session.token;
        let attempt_id = gen_alphanumeric(32);
        let replaced = token
            .replace_mfa_config_auth_state(
                &self.pool,
                &MfaConfigAuthState::Oidc {
                    attempt_id: attempt_id.clone(),
                    completed: false,
                },
            )
            .await
            .map_err(Status::from)?;
        if !replaced {
            debug!(
                "MFA config OIDC: user {} already completed the OpenID sign-in",
                session.user.username
            );
            return Err(Status::failed_precondition("OpenID sign-in already completed").into());
        }
        Ok(Some(MfaConfigTarget {
            token_id: token.id,
            attempt_id,
            user_id: session.user.id,
        }))
    }

    /// Completes the OpenID authorization once the provider confirmed the user's identity.
    ///
    /// A sign-in as anyone else ends the configuration session.
    pub(crate) async fn oidc_complete(
        &self,
        target: &MfaConfigTarget,
        identity: &Identity,
    ) -> Result<(), CoreError> {
        let mut token = match Token::find_by_id(&self.pool, &target.token_id).await {
            Ok(token) if token.user_id == target.user_id && !token.is_expired() => token,
            Ok(_) | Err(TokenError::NotFound) => return Err(session_expired()),
            Err(err) => return Err(Status::from(err).into()),
        };
        let user = token.fetch_user(&self.pool).await.map_err(Status::from)?;
        if !user.is_active || !subject_matches(user.openid_sub.as_deref(), identity) {
            warn!(
                "MFA config OIDC: the OpenID sign-in for user {} was another identity; ending \
                 the session",
                user.username
            );
            token
                .delete_pending_mfa_config_oidc_attempt(&self.pool, &target.attempt_id)
                .await
                .map_err(Status::from)?;
            return Err(CoreError::unauthenticated("unauthorized")
                .with_code(CoreErrorCode::OidcAccountMismatch));
        }
        if !token
            .mark_mfa_config_oidc_completed(&self.pool, &target.attempt_id)
            .await
            .map_err(Status::from)?
        {
            return Err(session_expired());
        }
        info!(
            "User {} completed the OpenID sign-in for MFA configuration",
            user.username
        );
        Ok(())
    }

    /// Ends the user's MFA configuration session.
    #[instrument(skip_all)]
    pub(crate) async fn mfa_config_end(&self, request: MfaConfigEndRequest) -> Result<(), Status> {
        let token = Token::find_by_id(&self.pool, &request.session_token).await?;
        // Only MFA configuration tokens may be deleted here.
        if token.token_type.as_deref() != Some(MFA_CONFIG_TOKEN_TYPE) {
            error!(
                "MFA config end: token {} has type {:?}, expected {MFA_CONFIG_TOKEN_TYPE}",
                token.id, token.token_type
            );
            return Err(Status::permission_denied("invalid token"));
        }
        Token::delete_user_tokens_of_type(&self.pool, token.user_id, MFA_CONFIG_TOKEN_TYPE).await?;
        info!("Ended MFA configuration session for user {}", token.user_id);

        Ok(())
    }
}
