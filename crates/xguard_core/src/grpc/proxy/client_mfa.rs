use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    net::IpAddr,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use sqlx::{PgPool, Postgres, pool::PoolConnection};
use tokio::{
    sync::{mpsc::UnboundedSender, oneshot},
    time,
};
use tonic::{Code, Status};
use xguard_common::{
    db::{
        Id,
        models::{
            Device, User, WireguardNetwork,
            device::WireguardNetworkDevice,
            mfa_flow::{MfaFlow, MfaFlowStep},
            polling_token::polling_token_digest,
            vpn_client_mfa_session::{VpnClientMfaSession, VpnMfaFlowKind, hash_token},
            vpn_client_session::{VpnClientMfaMethod, VpnClientSession},
        },
        wireguard_key::WireguardKey,
    },
    secret::SecretStringWrapper,
    types::user_info::UserInfo,
};
use xguard_proto::{
    client_types::{
        ClientMfaFinishRequest, ClientMfaFinishResponse, ClientMfaStartRequest,
        ClientMfaStartResponse, DevicePostureFacts, MfaAdvanced, MfaAwaitingExternal,
        MfaBiometricSignature, MfaCodeCredential, MfaCompleted, MfaFido2Assertion,
        MfaFido2Challenge, MfaFlowApproveRequest, MfaFlowRemoteRejected, MfaFlowRemoteRequest,
        MfaFlowRemoteResponse, MfaFlowStartAccepted, MfaFlowStartRejected, MfaFlowStartRequest,
        MfaFlowStartResponse, MfaFlowStepFinishRequest, MfaFlowStepFinishResponse,
        MfaFlowStepStartRequest, MfaFlowStepStartResponse, MfaMethod, MfaRemoteRejectionReason,
        MfaSignatureChallenge, MfaStartRejectionReason, MfaStepRejection, MfaStepResult,
        MfaStepStarted, PostureConnectRequest, PostureConnectResponse, mfa_flow_remote_response,
        mfa_flow_start_response, mfa_flow_step_finish_request, mfa_step_result, mfa_step_started,
    },
    posture_rejected_status,
    proxy::{
        self, AwaitRemoteMfaFinishRequest, AwaitRemoteMfaFinishResponse,
        ClientMfaTokenValidationRequest, ClientMfaTokenValidationResponse, CoreError,
        CoreErrorCode, CoreResponse, core_response::Payload,
    },
};

use crate::{
    events::{BidiRequestContext, BidiStreamEvent, BidiStreamEventType, DesktopClientMfaEvent},
    grpc::{GatewayCommand, utils::parse_client_ip_agent},
    mfa_engine::{
        MfaEngine,
        authorize::{
            AuthorizeError, ClientMfaServerError, EventChannels, SessionDisconnectReason,
            build_authorized_gateway_network_info, create_new_session, disconnect_session,
        },
        error::StartError,
        legacy::{FinishError, LegacyProof},
        method::InitiateError,
        multi_step::{
            Fido2Assertion, MobileApprovalProof, StartRejectionReason, StartResult, StepCredential,
            StepError, StepFinishError, StepProof, StepRejection,
        },
        oidc::OidcMfaError,
        types::{FinishOutcome, LegacyFinishOutcome, LegacyStartOutcome, MultiStepStartOutcome},
    },
    posture::{self, PostureCheck, PostureResult},
    sso::{constant_time_eq, edge::VpnMfaTarget, flow::Identity},
};

// Must cover the client's MOBILE_APPROVE_TIMEOUT.
const REMOTE_AUTH_TIMEOUT: Duration = Duration::from_mins(2);

/// Messages for a client waiting for remote MFA. The message never contains the VPN key.
#[derive(Debug)]
pub enum RemoteAuthSignal {
    Superseded,
    Approved,
    MobileClientOutdated,
}

enum RemoteAuthWaiterKind {
    Legacy {
        preshared_key: Arc<Mutex<Option<String>>>,
    },
    MultiStep {
        step_attempt_id: String,
    },
}

/// State for a client waiting for remote MFA.
pub struct RemoteAuthWaiter {
    /// Each parked waiter gets a fresh `Arc` identity; its cleanup task keeps a clone.
    /// `Arc::ptr_eq` stops stale cleanup from removing a replacement under the same token hash.
    waiter_identity: Arc<()>,
    signal_tx: oneshot::Sender<RemoteAuthSignal>,
    kind: RemoteAuthWaiterKind,
}

pub type RemoteAuthWaiters = Arc<RwLock<HashMap<String, RemoteAuthWaiter>>>;

struct ClientMfaStartContext {
    location: WireguardNetwork<Id>,
    device: Device<Id>,
    user: User<Id>,
    ip: IpAddr,
}

pub struct ClientMfaServer {
    pub(crate) pool: PgPool,
    channels: EventChannels,
    remote_mfa_responses: RemoteAuthWaiters,
    engine: MfaEngine,
}

/// Acquire a pooled connection, mapping a pool error to an internal status.
async fn acquire_connection(pool: &PgPool) -> Result<PoolConnection<Postgres>, Status> {
    pool.acquire().await.map_err(|_| {
        error!("Failed to acquire DB connection");
        Status::internal("unexpected error")
    })
}

/// Removes a waiting client only if it still belongs to this cleanup task.
fn remove_remote_mfa_waiter(waiters: &RemoteAuthWaiters, hash: &str, waiter_identity: &Arc<()>) {
    let mut waiters = waiters
        .write()
        .expect("Failed to write-lock ClientMfaServer::remote_mfa_responses");
    let owns_current_waiter = waiters
        .get(hash)
        .is_some_and(|waiter| Arc::ptr_eq(&waiter.waiter_identity, waiter_identity));
    if owns_current_waiter {
        waiters.remove(hash);
    }
}

fn remove_waiter_and_send_error(
    waiters: &RemoteAuthWaiters,
    hash: &str,
    waiter_identity: &Arc<()>,
    response_tx: &UnboundedSender<CoreResponse>,
    request_id: u64,
    status: Status,
) {
    remove_remote_mfa_waiter(waiters, hash, waiter_identity);
    let _ = response_tx.send(CoreResponse {
        id: request_id,
        payload: Some(Payload::CoreError(status.into())),
    });
}

/// Removes and returns the waiting client for `hash`; signal it after unlocking.
fn take_remote_mfa_waiter_by_hash(
    waiters: &RemoteAuthWaiters,
    hash: &str,
) -> Option<RemoteAuthWaiter> {
    waiters
        .write()
        .expect("Failed to write-lock ClientMfaServer::remote_mfa_responses")
        .remove(hash)
}

fn take_legacy_remote_mfa_waiter(
    waiters: &RemoteAuthWaiters,
    token: &str,
) -> Option<(RemoteAuthWaiter, Arc<Mutex<Option<String>>>)> {
    let hash = hash_token(token);
    let mut waiters = waiters
        .write()
        .expect("Failed to write-lock ClientMfaServer::remote_mfa_responses");
    let Entry::Occupied(entry) = waiters.entry(hash) else {
        return None;
    };
    let preshared_key = match &entry.get().kind {
        RemoteAuthWaiterKind::Legacy { preshared_key } => Arc::clone(preshared_key),
        RemoteAuthWaiterKind::MultiStep { .. } => return None,
    };
    Some((entry.remove(), preshared_key))
}

fn take_multi_step_remote_mfa_waiter(
    waiters: &RemoteAuthWaiters,
    token: &str,
    step_attempt_id: &str,
) -> Option<RemoteAuthWaiter> {
    let hash = hash_token(token);
    let mut waiters = waiters
        .write()
        .expect("Failed to write-lock ClientMfaServer::remote_mfa_responses");
    let Entry::Occupied(entry) = waiters.entry(hash) else {
        return None;
    };
    let matches_attempt = matches!(
        &entry.get().kind,
        RemoteAuthWaiterKind::MultiStep { step_attempt_id: current } if current == step_attempt_id
    );
    matches_attempt.then(|| entry.remove())
}

/// Sends a message to a waiting client. Closed receivers are normal; the message never contains the VPN key.
fn signal_remote_mfa_waiter(waiter: RemoteAuthWaiter, signal: RemoteAuthSignal) {
    if let Err(unsent) = waiter.signal_tx.send(signal) {
        debug!("Parked remote MFA waiter is gone, dropping signal {unsent:?}");
    }
}

impl From<ClientMfaServerError> for Status {
    fn from(value: ClientMfaServerError) -> Self {
        Self::new(Code::Internal, value.to_string())
    }
}

impl From<ClientMfaServerError> for proxy::CoreError {
    fn from(value: ClientMfaServerError) -> Self {
        Status::from(value).into()
    }
}

impl From<AuthorizeError> for Status {
    fn from(err: AuthorizeError) -> Self {
        match err {
            AuthorizeError::Db(_) | AuthorizeError::Gateway(_) => {
                Self::internal("unexpected error")
            }
            AuthorizeError::Event(e) => Self::from(e),
        }
    }
}

impl From<InitiateError> for Status {
    fn from(err: InitiateError) -> Self {
        match err {
            InitiateError::EmailCode(_) => Self::internal("MFA code"),
            InitiateError::Database(_) => Self::internal("database error"),
            InitiateError::Mail(_) => Self::internal("unexpected error"),
            InitiateError::BiometricNotConfigured => {
                Self::invalid_argument("Select MFA method is not available for the device.")
            }
            InitiateError::InvalidPublicKey(_) => Self::invalid_argument("Invalid public key"),
            InitiateError::UnsupportedMethod => {
                Self::unimplemented("Selected MFA method is not supported")
            }
            InitiateError::TooManyRequests => Self::failed_precondition(err.to_string()),
            InitiateError::Fido2NotConfigured => Self::failed_precondition(
                "No security key is registered for VPN MFA. Register one in the XGuard client.",
            ),
            InitiateError::Fido2(_) => Self::internal("unexpected error"),
        }
    }
}

// The engine's domain types carry no proto, so the conversions live here rather than in
// `mfa_engine`.
impl From<FinishOutcome> for MfaStepResult {
    fn from(value: FinishOutcome) -> Self {
        let outcome = match value {
            FinishOutcome::Advanced { next_step } => {
                mfa_step_result::Outcome::Advanced(MfaAdvanced { next_step })
            }
            FinishOutcome::Completed { preshared_key } => {
                mfa_step_result::Outcome::Completed(MfaCompleted {
                    preshared_key: preshared_key.expose_secret().to_owned(),
                })
            }
            FinishOutcome::AwaitingExternal => {
                mfa_step_result::Outcome::AwaitingExternal(MfaAwaitingExternal {})
            }
        };
        Self {
            outcome: Some(outcome),
        }
    }
}

fn parse_mfa_method(method: i32) -> Result<VpnClientMfaMethod, Status> {
    MfaMethod::try_from(method)
        .map(VpnClientMfaMethod::from)
        .map_err(|err| {
            error!("Invalid MFA method selected ({method}): {err}");
            Status::invalid_argument("invalid MFA method selected")
        })
}

fn encode_step_started(
    method: VpnClientMfaMethod,
    step_attempt_id: String,
    challenge: Option<String>,
    credential_ids: Vec<String>,
) -> Result<MfaStepStarted, Status> {
    let challenge = match method {
        VpnClientMfaMethod::Fido2 => {
            let Some(challenge) = challenge else {
                error!("FIDO2 MFA step is missing its challenge");
                return Err(Status::internal("unexpected error"));
            };
            Some(mfa_step_started::Challenge::Fido2(MfaFido2Challenge {
                challenge,
                credential_ids,
            }))
        }
        method @ (VpnClientMfaMethod::Biometric | VpnClientMfaMethod::MobileApprove) => {
            let Some(challenge) = challenge else {
                error!("{method:?} MFA step is missing its challenge");
                return Err(Status::internal("unexpected error"));
            };
            Some(mfa_step_started::Challenge::Signature(
                MfaSignatureChallenge { challenge },
            ))
        }
        VpnClientMfaMethod::Totp | VpnClientMfaMethod::Email | VpnClientMfaMethod::Oidc => None,
    };

    Ok(MfaStepStarted {
        step_attempt_id,
        challenge,
    })
}

fn into_step_proof(request: MfaFlowStepFinishRequest) -> (String, StepProof) {
    let credential = request.submission.map(|submission| match submission {
        mfa_flow_step_finish_request::Submission::Code(MfaCodeCredential { code }) => {
            StepCredential::Code(code)
        }
        mfa_flow_step_finish_request::Submission::Biometric(MfaBiometricSignature {
            signature,
        }) => StepCredential::BiometricSignature(signature),
        mfa_flow_step_finish_request::Submission::Fido2(MfaFido2Assertion {
            rp_id_hash,
            authenticator_data,
            signature,
            credential_id,
        }) => StepCredential::Fido2(Fido2Assertion {
            rp_id_hash,
            authenticator_data,
            signature,
            credential_id,
        }),
    });
    (
        request.token,
        StepProof {
            step_attempt_id: request.step_attempt_id,
            credential,
        },
    )
}

impl From<StartRejectionReason> for MfaStartRejectionReason {
    fn from(value: StartRejectionReason) -> Self {
        match value {
            StartRejectionReason::MethodNotInStep => Self::MfaStartRejectionMethodNotInStep,
            StartRejectionReason::StepEmptyAfterLicense => {
                Self::MfaStartRejectionStepEmptyAfterLicense
            }
            StartRejectionReason::StepUnavailable => Self::MfaStartRejectionStepUnavailable,
        }
    }
}

impl From<StepRejection> for MfaStepRejection {
    fn from(value: StepRejection) -> Self {
        Self {
            step: value.step,
            reason: MfaStartRejectionReason::from(value.reason) as i32,
        }
    }
}

// The status message always comes from the variant's `Display` (the `#[error(...)]` attribute in
// `mfa_engine::error`), so each client-visible string exists in exactly one place and the only
// decision made here is the gRPC code. Editing a `Display` string changes the client contract.

impl From<StartError> for Status {
    fn from(err: StartError) -> Self {
        let code = match err {
            StartError::MultiStepNotAvailable | StartError::AttemptLimit => {
                Code::FailedPrecondition
            }
            StartError::PlanLengthMismatch
            | StartError::MethodNotInStep
            | StartError::MethodNotAvailable
            | StartError::BiometricNotConfigured => Code::InvalidArgument,
            StartError::Internal => Code::Internal,
            StartError::Initiate(e) => return Self::from(e),
        };
        Self::new(code, err.to_string())
    }
}

impl From<StepError> for Status {
    fn from(err: StepError) -> Self {
        let code = match err {
            StepError::SessionNotFound | StepError::MethodNotInStep => Code::InvalidArgument,
            StepError::MethodNotConfigured => Code::FailedPrecondition,
            StepError::Internal => Code::Internal,
            StepError::Initiate(e) => return Self::from(e),
        };
        Self::new(code, err.to_string())
    }
}

impl From<FinishError> for Status {
    fn from(err: FinishError) -> Self {
        let code = match err {
            FinishError::SessionNotFound
            | FinishError::UninitializedStep
            | FinishError::StaleAttempt
            | FinishError::MissingChallenge
            | FinishError::MalformedProof { .. } => Code::InvalidArgument,
            FinishError::OidcNotCompleted => Code::FailedPrecondition,
            FinishError::Unauthorized => Code::Unauthenticated,
            FinishError::MissingBiometricChallenge | FinishError::Internal => Code::Internal,
            FinishError::Event(e) => return Self::from(e),
            FinishError::PostureRejected(failed) => return posture_rejected_status(&failed),
        };
        Self::new(code, err.to_string())
    }
}

impl From<StepFinishError> for Status {
    fn from(err: StepFinishError) -> Self {
        let code = match err {
            StepFinishError::SessionNotFound
            | StepFinishError::UninitializedStep
            | StepFinishError::StaleAttempt
            | StepFinishError::MissingChallenge
            | StepFinishError::MalformedProof { .. } => Code::InvalidArgument,
            StepFinishError::Unauthorized => Code::Unauthenticated,
            StepFinishError::AttemptLimit => Code::PermissionDenied,
            StepFinishError::MissingBiometricChallenge | StepFinishError::Internal => {
                Code::Internal
            }
            StepFinishError::Event(e) => return Status::from(e),
            StepFinishError::PostureRejected(failed) => return posture_rejected_status(&failed),
        };
        Status::new(code, err.to_string())
    }
}

/// Sent when the location needs a protocol this client cannot speak - almost
/// always multi-step MFA, which landed in 2.2.
const LEGACY_CLIENT_MESSAGE: &str =
    "XGuard client version is too old to connect to this location. Please update your client.";
/// Sent to the legacy mobile app and its waiting 2.2 desktop as `FailedPrecondition` (HTTP 428).
pub const LEGACY_MOBILE_CLIENT_MESSAGE: &str = "XGuard mobile app version is too old to approve this connection. Please update the mobile app.";

/// Sent when the location can only be passed with a security key, which the CLI
/// cannot drive at any version.
const FIDO2_ONLY_MESSAGE: &str = "This location requires a security key (FIDO2), which this client \
     cannot use. Connect with the desktop client.";

impl ClientMfaServer {
    #[must_use]
    pub fn new(
        pool: PgPool,
        gateway_tx: UnboundedSender<GatewayCommand>,
        bidi_event_tx: UnboundedSender<BidiStreamEvent>,
        remote_mfa_responses: RemoteAuthWaiters,
    ) -> Self {
        let engine = MfaEngine::new(pool.clone(), gateway_tx.clone(), bidi_event_tx.clone());
        Self {
            pool,
            channels: EventChannels::new(gateway_tx, bidi_event_tx),
            remote_mfa_responses,
            engine,
        }
    }

    pub(crate) fn emit_event(&self, event: BidiStreamEvent) -> Result<(), ClientMfaServerError> {
        self.channels.emit_event(event)
    }

    /// Acquire a pooled connection, mapping a pool error to an internal status.
    pub(crate) async fn acquire_conn(&self) -> Result<PoolConnection<Postgres>, Status> {
        acquire_connection(&self.pool).await
    }

    /// Allows Edge to verify if token is valid and active.
    #[instrument(skip_all)]
    pub async fn validate_mfa_token(
        &self,
        request: ClientMfaTokenValidationRequest,
    ) -> Result<ClientMfaTokenValidationResponse, Status> {
        let token_valid =
            VpnClientMfaSession::<Id>::find_active_by_token(&self.pool, &request.token)
                .await
                .map_err(|err| {
                    error!("Failed to validate MFA token: {err}");
                    Status::internal("unexpected error")
                })?
                .is_some();
        Ok(ClientMfaTokenValidationResponse { token_valid })
    }

    #[instrument(skip_all)]
    pub async fn legacy_mfa_start(
        &self,
        request: ClientMfaStartRequest,
        info: Option<proxy::DeviceInfo>,
    ) -> Result<ClientMfaStartResponse, MfaStartRejection> {
        debug!("Starting desktop client login: {request:?}");
        let selected_client_method = parse_mfa_method(request.method)?;
        if selected_client_method == VpnClientMfaMethod::Fido2 {
            return Err(Status::from(InitiateError::UnsupportedMethod).into());
        }

        let ClientMfaStartContext {
            location,
            device,
            user,
            ip,
        } = self
            .prepare_client_mfa_start(
                request.location_id,
                &request.pubkey,
                request.posture.as_ref(),
                info,
            )
            .await?;

        let (flow_id, step_methods) = self.resolve_legacy_mfa_flow(&location, &user).await?;
        let start_outcome = self
            .engine
            .start_legacy(
                &location,
                &device,
                &user,
                flow_id,
                step_methods,
                selected_client_method,
            )
            .await
            .map_err(Status::from)?;

        Ok(self.finish_start(start_outcome, &user, ip, &device, &location)?)
    }

    #[instrument(skip_all)]
    pub async fn mfa_flow_start(
        &self,
        request: MfaFlowStartRequest,
        info: Option<proxy::DeviceInfo>,
    ) -> Result<MfaFlowStartResponse, MfaStartRejection> {
        debug!("Starting multi-step desktop client login: {request:?}");
        if request.selected_methods.is_empty() {
            return Err(Status::invalid_argument("MFA plan must not be empty").into());
        }
        let selected_methods = request
            .selected_methods
            .iter()
            .map(|&method| parse_mfa_method(method))
            .collect::<Result<Vec<_>, _>>()?;
        let Some(&first_method) = selected_methods.first() else {
            return Err(Status::invalid_argument("MFA plan must not be empty").into());
        };

        let ClientMfaStartContext {
            location,
            device,
            user,
            ip,
        } = self
            .prepare_client_mfa_start(
                request.location_id,
                &request.pubkey,
                request.posture.as_ref(),
                info,
            )
            .await?;

        let (flow, steps) = self
            .resolve_mfa_flow(
                &location,
                &user,
                "no MFA flow applies to this user and location",
            )
            .await?;
        let step_methods = steps.into_iter().map(|step| step.methods).collect();

        match self
            .engine
            .start_multi_step(
                &location,
                &device,
                &user,
                flow.id,
                step_methods,
                selected_methods,
            )
            .await
            .map_err(Status::from)?
        {
            StartResult::Accepted(start_outcome) => {
                let MultiStepStartOutcome {
                    token,
                    step_attempt_id,
                    challenge,
                    credential_ids,
                    superseded_token_hash,
                } = start_outcome;
                self.finish_start_side_effects(
                    superseded_token_hash.as_deref(),
                    &user,
                    ip,
                    &device,
                    &location,
                )?;
                let first_step =
                    encode_step_started(first_method, step_attempt_id, challenge, credential_ids)?;
                Ok(MfaFlowStartResponse {
                    outcome: Some(mfa_flow_start_response::Outcome::Accepted(
                        MfaFlowStartAccepted {
                            token,
                            first_step: Some(first_step),
                        },
                    )),
                })
            }
            StartResult::Rejected(rejections) => {
                info!(
                    "MFA plan rejected for user {} at location {}: {rejections:?}",
                    user.username, location.name
                );
                Ok(MfaFlowStartResponse {
                    outcome: Some(mfa_flow_start_response::Outcome::Rejected(
                        MfaFlowStartRejected {
                            rejections: rejections.into_iter().map(Into::into).collect(),
                        },
                    )),
                })
            }
        }
    }

    fn finish_start(
        &self,
        start_outcome: LegacyStartOutcome,
        user: &User<Id>,
        ip: IpAddr,
        device: &Device<Id>,
        location: &WireguardNetwork<Id>,
    ) -> Result<ClientMfaStartResponse, Status> {
        self.finish_start_side_effects(
            start_outcome.superseded_token_hash.as_deref(),
            user,
            ip,
            device,
            location,
        )?;

        info!(
            "Desktop client MFA login started for {} at location {}",
            user.username, location.name
        );

        Ok(ClientMfaStartResponse {
            token: start_outcome.token,
            challenge: start_outcome.challenge,
        })
    }

    fn finish_start_side_effects(
        &self,
        superseded_token_hash: Option<&str>,
        user: &User<Id>,
        ip: IpAddr,
        device: &Device<Id>,
        location: &WireguardNetwork<Id>,
    ) -> Result<(), Status> {
        if let Some(superseded_token_hash) = superseded_token_hash {
            if let Some(waiter) =
                take_remote_mfa_waiter_by_hash(&self.remote_mfa_responses, superseded_token_hash)
            {
                signal_remote_mfa_waiter(waiter, RemoteAuthSignal::Superseded);
            }

            let context =
                BidiRequestContext::new(user.id, user.username.clone(), ip, device.name.clone());
            self.emit_event(BidiStreamEvent {
                context,
                event: BidiStreamEventType::DesktopClientMfa(Box::new(
                    DesktopClientMfaEvent::MfaLoginSuperseded {
                        location: location.clone(),
                        device: device.clone(),
                    },
                )),
            })?;
        }
        Ok(())
    }

    async fn prepare_client_mfa_start(
        &self,
        location_id: Id,
        pubkey: &str,
        posture: Option<&DevicePostureFacts>,
        info: Option<proxy::DeviceInfo>,
    ) -> Result<ClientMfaStartContext, Status> {
        let location = WireguardNetwork::find_by_id(&self.pool, location_id)
            .await
            .map_err(|err| {
                error!(
                    location_id,
                    error = ?err,
                    "Failed to query location"
                );
                Status::internal("unexpected error")
            })?
            .ok_or_else(|| {
                error!("Location does not exist");
                Status::invalid_argument("location not found")
            })?;

        if !location.mfa_enabled {
            error!("MFA is not enabled for location {location}");
            return Err(Status::invalid_argument("MFA not enabled for location"));
        }

        let Ok(Some(device)) = Device::find_by_pubkey(&self.pool, pubkey).await else {
            error!("Failed to find device with pubkey {pubkey}");
            return Err(Status::invalid_argument("device not found"));
        };

        let Ok(Some(mut user)) = User::find_by_id(&self.pool, device.user_id).await else {
            error!("Failed to find user with ID {}", device.user_id);
            return Err(Status::invalid_argument("user not found"));
        };
        // `password_management_disabled` is irrelevant here (internal access validation,
        // not an API response), so the OIDC flag is not loaded.
        let user_info = UserInfo::from_user(&self.pool, user.clone(), false)
            .await
            .map_err(|err| {
                error!(
                    username = %user.username,
                    error = ?err,
                    "Failed to fetch user info"
                );
                Status::internal("unexpected error")
            })?;

        Self::validate_location_access(&self.pool, &location, &device, &user_info).await?;

        let (ip, _user_agent) = parse_client_ip_agent(&info).map_err(Status::internal)?;

        // Fail fast, before the user is asked for a code. The stored snapshot is checked again
        // when the session is authorized.
        self.check_posture(&location, &device, &user, ip, posture)
            .await?;

        user.verify_mfa_state(&self.pool).await.map_err(|err| {
            error!(
                "Failed to verify MFA state for user {}: {err}",
                user.username
            );
            Status::internal("unexpected error")
        })?;

        Ok(ClientMfaStartContext {
            location,
            device,
            user,
            ip,
        })
    }

    /// Evaluates the posture of `device` for `location` (when the location has posture
    /// policies), records the snapshot and the audit event, and refuses a non-compliant device.
    ///
    /// A refused device also loses its active sessions in the location.
    async fn check_posture(
        &self,
        location: &WireguardNetwork<Id>,
        device: &Device<Id>,
        user: &User<Id>,
        ip: IpAddr,
        posture: Option<&DevicePostureFacts>,
    ) -> Result<(), Status> {
        let mut conn = self.acquire_conn().await?;
        let Some(check) = posture::check_connection(&mut conn, location.id, device.id, posture)
            .await
            .map_err(|err| {
                error!("Failed to evaluate posture of device {device} for {location}: {err}");
                Status::internal("unexpected error")
            })?
        else {
            return Ok(());
        };
        drop(conn);

        let context =
            BidiRequestContext::new(user.id, user.username.clone(), ip, device.name.clone());
        let PostureCheck { result, facts } = check;
        match result {
            PostureResult::Pass => {
                info!("Device {device} passed the posture check for location {location}");
                if let Err(err) = self.emit_event(BidiStreamEvent {
                    context,
                    event: BidiStreamEventType::DesktopClientMfa(Box::new(
                        DesktopClientMfaEvent::PostureCheckPassed {
                            device: device.clone(),
                            location: location.clone(),
                            facts,
                        },
                    )),
                }) {
                    error!("Failed to emit posture event: {err}");
                }
                Ok(())
            }
            PostureResult::Fail(failed_checks) => {
                warn!(
                    "Device {device} of {} failed the posture check for location {location}: {}",
                    user.username,
                    failed_checks.join("; ")
                );
                if let Err(err) = self.emit_event(BidiStreamEvent {
                    context,
                    event: BidiStreamEventType::DesktopClientMfa(Box::new(
                        DesktopClientMfaEvent::PostureCheckFailed {
                            device: device.clone(),
                            location: location.clone(),
                            facts,
                            failed_checks: failed_checks.clone(),
                        },
                    )),
                }) {
                    error!("Failed to emit posture event: {err}");
                }
                self.revoke_sessions(location, user, device).await?;
                Err(posture_rejected_status(&failed_checks))
            }
        }
    }

    /// Disconnects the active sessions of a device in a location.
    async fn revoke_sessions(
        &self,
        location: &WireguardNetwork<Id>,
        user: &User<Id>,
        device: &Device<Id>,
    ) -> Result<(), Status> {
        let internal = |err: &dyn std::fmt::Display| {
            error!("Failed to revoke sessions of {device} in {location}: {err}");
            Status::internal("unexpected error")
        };
        let mut transaction = self.pool.begin().await.map_err(|err| internal(&err))?;
        let sessions = VpnClientSession::get_all_active_device_sessions_in_location(
            &mut *transaction,
            location.id,
            device.id,
        )
        .await
        .map_err(|err| internal(&err))?;
        for session in sessions {
            disconnect_session(
                &self.channels,
                &mut transaction,
                session,
                location,
                user,
                device,
                SessionDisconnectReason::Disconnected,
            )
            .await
            .map_err(|err| internal(&err))?;
        }
        transaction.commit().await.map_err(|err| internal(&err))?;
        Ok(())
    }

    /// Posture-only connection: a location with posture policies but without MFA.
    ///
    /// The caller proves it holds the device's enrollment with the device's polling token
    /// (compared in constant time). On success a session with a fresh preshared key is
    /// authorized, exactly as at the end of MFA.
    #[instrument(skip_all)]
    pub async fn posture_connect(
        &self,
        request: PostureConnectRequest,
        info: Option<proxy::DeviceInfo>,
    ) -> Result<PostureConnectResponse, Status> {
        // Authenticate before anything else, so the errors below cannot be used to probe which
        // locations or keys exist.
        if request.token.is_empty() || request.token.len() > 256 {
            return Err(Status::unauthenticated("unauthorized"));
        }
        let device = match Device::find_by_pubkey(&self.pool, &request.pubkey).await {
            Ok(Some(device)) => device,
            Ok(None) => {
                warn!("Posture connect for an unknown public key");
                return Err(Status::unauthenticated("unauthorized"));
            }
            Err(err) => {
                error!("Posture connect: failed to load device: {err}");
                return Err(Status::internal("unexpected error"));
            }
        };
        // Stored tokens are digests; compare the digest of the presented one.
        let presented = polling_token_digest(&request.token);
        let tokens: Vec<String> =
            sqlx::query_scalar("SELECT token FROM pollingtoken WHERE device_id = $1")
                .bind(device.id)
                .fetch_all(&self.pool)
                .await
                .map_err(|err| {
                    error!("Posture connect: failed to load polling token: {err}");
                    Status::internal("unexpected error")
                })?;
        if !tokens
            .iter()
            .any(|digest| constant_time_eq(digest.as_bytes(), presented.as_bytes()))
        {
            warn!("Posture connect for device {device} with a wrong token");
            return Err(Status::unauthenticated("unauthorized"));
        }

        let location = WireguardNetwork::find_by_id(&self.pool, request.location_id)
            .await
            .map_err(|err| {
                error!("Posture connect: failed to load location: {err}");
                Status::internal("unexpected error")
            })?
            .ok_or_else(|| Status::invalid_argument("location not found"))?;
        if location.mfa_enabled {
            return Err(Status::invalid_argument(
                "location requires MFA; posture is checked during MFA",
            ));
        }
        let user = User::find_by_id(&self.pool, device.user_id)
            .await
            .map_err(|err| {
                error!("Posture connect: failed to load user: {err}");
                Status::internal("unexpected error")
            })?
            .ok_or_else(|| Status::internal("unexpected error"))?;
        if !user.is_active {
            return Err(Status::permission_denied("user is inactive"));
        }
        let user_info = UserInfo::from_user(&self.pool, user.clone(), false)
            .await
            .map_err(|err| {
                error!("Posture connect: failed to load user info: {err}");
                Status::internal("unexpected error")
            })?;
        Self::validate_location_access(&self.pool, &location, &device, &user_info).await?;
        let (ip, _user_agent) = parse_client_ip_agent(&info).map_err(Status::internal)?;

        let has_postures = location.has_postures(&self.pool).await.map_err(|err| {
            error!("Posture connect: failed to load policies: {err}");
            Status::internal("unexpected error")
        })?;
        if !has_postures {
            // The policies were removed after the client fetched its configuration. Its peer is
            // configured without a preshared key now, so an empty key lets it connect.
            info!("Posture connect to {location}, which has no posture policies any more");
            return Ok(PostureConnectResponse {
                preshared_key: String::new(),
            });
        }

        self.check_posture(&location, &device, &user, ip, request.posture.as_ref())
            .await?;

        let key = WireguardKey::generate();
        let preshared_key = SecretStringWrapper::from(key.public());
        let internal = |err: &dyn std::fmt::Display| {
            error!("Posture connect: failed to authorize a session for {device}: {err}");
            Status::internal("unexpected error")
        };
        let mut transaction = self.pool.begin().await.map_err(|err| internal(&err))?;
        let network_device =
            WireguardNetworkDevice::find(&mut *transaction, device.id, location.id)
                .await
                .map_err(|err| internal(&err))?
                .ok_or_else(|| Status::internal("unexpected error"))?;
        create_new_session(
            &self.channels,
            &mut transaction,
            &location,
            &user,
            &device,
            false,
            preshared_key.clone(),
        )
        .await
        .map_err(|err| internal(&err))?;
        transaction.commit().await.map_err(|err| internal(&err))?;

        let gateway_network_info =
            build_authorized_gateway_network_info(network_device, preshared_key);
        self.channels
            .gateway_tx
            .send(GatewayCommand::VpnSessionAuthorized(
                location.id,
                device.clone(),
                gateway_network_info,
            ))
            .map_err(|err| internal(&err))?;
        info!(
            "Device {device} of {} authorized in location {location} after a posture check",
            user.username
        );
        Ok(PostureConnectResponse {
            preshared_key: key.public(),
        })
    }

    /// Resolve a flow that can be represented by the legacy single-step contract.
    async fn resolve_legacy_mfa_flow(
        &self,
        location: &WireguardNetwork<Id>,
        user: &User<Id>,
    ) -> Result<(Id, HashSet<VpnClientMfaMethod>), Status> {
        if MfaFlow::derive_legacy_mode(&self.pool, location.id)
            .await
            .map_err(|err| {
                error!("Failed to derive legacy MFA mode: {err}");
                Status::internal("unexpected error")
            })?
            .is_none()
        {
            error!(
                "Location {location} has an MFA flow configuration that cannot be enforced by \
                this client"
            );
            // FIDO2-only flows get a specific error because legacy clients cannot use security keys.
            let (_, steps) = self
                .resolve_mfa_flow(location, user, LEGACY_CLIENT_MESSAGE)
                .await?;
            let needs_method_this_client_lacks = match steps.as_slice() {
                [step] => step
                    .methods
                    .iter()
                    .all(|method| *method == VpnClientMfaMethod::Fido2),
                _ => false,
            };
            return Err(Status::failed_precondition(
                if needs_method_this_client_lacks {
                    FIDO2_ONLY_MESSAGE
                } else {
                    LEGACY_CLIENT_MESSAGE
                },
            ));
        }

        let (flow, steps) = self
            .resolve_mfa_flow(
                location,
                user,
                "location MFA configuration is not supported by this client",
            )
            .await?;
        let Some(first_step) = steps.first() else {
            error!("Resolved MFA flow has no steps");
            return Err(Status::internal("unexpected error"));
        };

        Ok((flow.id, first_step.methods.clone()))
    }

    /// Resolve the MFA flow applying to `user` at `location`. The two start paths differ only in
    /// the message reported when no flow applies, hence `no_flow_message`.
    async fn resolve_mfa_flow(
        &self,
        location: &WireguardNetwork<Id>,
        user: &User<Id>,
        no_flow_message: &'static str,
    ) -> Result<(MfaFlow<Id>, Vec<MfaFlowStep<Id>>), Status> {
        let mut conn = self.acquire_conn().await?;
        match MfaFlow::resolve_for_user(&mut conn, location.id, user.id).await {
            Ok(Some((flow, steps))) => Ok((flow, steps)),
            Ok(None) => {
                error!(
                    "Location {location} has no MFA flow that applies to user {}",
                    user.username
                );
                Err(Status::failed_precondition(no_flow_message))
            }
            Err(err) => {
                error!("Failed to resolve MFA flow: {err}");
                Err(Status::internal("unexpected error"))
            }
        }
    }

    /// Checks whether the user and device are allowed to access a location.
    async fn validate_location_access(
        pool: &PgPool,
        location: &WireguardNetwork<Id>,
        device: &Device<Id>,
        user_info: &UserInfo,
    ) -> Result<(), Status> {
        // acquire connection
        let mut conn = acquire_connection(pool).await?;

        // fetch allowed group names for a given location
        let allowed_groups = location
            .get_allowed_groups(&mut conn)
            .await
            .map_err(|err| {
                error!("Failed to fetch allowed groups for location {location}: {err}");
                Status::internal("unexpected error")
            })?;
        // If not all groups are allowed, check if user belongs to one of the allowed groups.
        if !location.allow_all_groups
            && !allowed_groups
                .iter()
                .any(|allowed_group| user_info.groups.contains(allowed_group))
        {
            error!(
                "User {} is not allowed to connect to location {location} because he/she doesn't \
                belong to any of the allowed groups. User groups: {:?}, allowed groups: \
                {allowed_groups:?}",
                user_info.username, user_info.groups
            );
            return Err(Status::unauthenticated("unauthorized"));
        }

        let assignment = WireguardNetworkDevice::find(&mut *conn, device.id, location.id)
            .await
            .map_err(|err| {
                error!(
                    "Failed to validate assignment for device {device} in location {location}: \
                    {err}"
                );
                Status::internal("unexpected error")
            })?;
        if assignment.is_none() {
            error!("Device {device} is not assigned to location {location}");
            return Err(Status::permission_denied(
                "device is not assigned to location",
            ));
        }

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn mfa_flow_remote(
        &self,
        request: MfaFlowRemoteRequest,
        response_tx: UnboundedSender<CoreResponse>,
        request_id: u64,
        info: Option<proxy::DeviceInfo>,
    ) -> Result<(), Status> {
        self.mfa_flow_remote_with_timeout(
            request,
            response_tx,
            request_id,
            info,
            REMOTE_AUTH_TIMEOUT,
        )
        .await
    }

    async fn mfa_flow_remote_with_timeout(
        &self,
        request: MfaFlowRemoteRequest,
        response_tx: UnboundedSender<CoreResponse>,
        request_id: u64,
        info: Option<proxy::DeviceInfo>,
        timeout: Duration,
    ) -> Result<(), Status> {
        debug!("Awaiting multi-step remote MFA finish for request_id {request_id}");
        let (ip, _user_agent) = parse_client_ip_agent(&info).map_err(Status::internal)?;
        let token = request.token;
        let step_attempt_id = request.step_attempt_id;
        let Some(session) = self
            .engine
            .find_active_session_for_flow(&token, VpnMfaFlowKind::MultiStep)
            .await
            .map_err(|err| {
                error!("Failed to find MFA session: {err}");
                Status::internal("unexpected error")
            })?
        else {
            return Err(Status::invalid_argument("login session not found"));
        };
        let Some(ephemeral) = session.ephemeral_state.as_ref() else {
            return Err(Status::invalid_argument("no MFA attempt in progress"));
        };
        if ephemeral.selected_method != VpnClientMfaMethod::MobileApprove {
            return Err(Status::invalid_argument("MFA method is not MobileApprove"));
        }
        if ephemeral.step_attempt_id != step_attempt_id {
            return Err(Status::from(StepFinishError::StaleAttempt));
        }

        let hash = hash_token(&token);
        let (signal_tx, rx) = oneshot::channel();
        let waiter_identity = Arc::new(());
        let replaced_waiter = {
            self.remote_mfa_responses
                .write()
                .expect("Failed to write-lock ClientMfaServer::remote_mfa_responses")
                .insert(
                    hash.clone(),
                    RemoteAuthWaiter {
                        waiter_identity: waiter_identity.clone(),
                        signal_tx,
                        kind: RemoteAuthWaiterKind::MultiStep {
                            step_attempt_id: step_attempt_id.clone(),
                        },
                    },
                )
        };
        if let Some(waiter) = replaced_waiter {
            signal_remote_mfa_waiter(waiter, RemoteAuthSignal::Superseded);
        }

        let waiters = self.remote_mfa_responses.clone();
        let engine = self.engine.clone();
        tokio::spawn(async move {
            let first = engine
                .finish_step(
                    token.clone(),
                    StepProof {
                        step_attempt_id: step_attempt_id.clone(),
                        credential: None,
                    },
                    ip,
                )
                .await;
            let result = match first {
                Ok(FinishOutcome::AwaitingExternal) => match time::timeout(timeout, rx).await {
                    Ok(Ok(RemoteAuthSignal::Approved)) => {
                        engine
                            .finish_step(
                                token.clone(),
                                StepProof {
                                    step_attempt_id: step_attempt_id.clone(),
                                    credential: None,
                                },
                                ip,
                            )
                            .await
                    }
                    Ok(Ok(RemoteAuthSignal::MobileClientOutdated)) => {
                        remove_remote_mfa_waiter(&waiters, &hash, &waiter_identity);
                        let _ = response_tx.send(CoreResponse {
                            id: request_id,
                            payload: Some(Payload::MfaFlowRemote(MfaFlowRemoteResponse {
                                outcome: Some(mfa_flow_remote_response::Outcome::Rejected(
                                    MfaFlowRemoteRejected {
                                        reason: MfaRemoteRejectionReason::MfaRemoteRejectionMobileClientOutdated
                                            .into(),
                                    },
                                )),
                            })),
                        });
                        return;
                    }
                    Ok(Ok(RemoteAuthSignal::Superseded)) => {
                        remove_waiter_and_send_error(
                            &waiters,
                            &hash,
                            &waiter_identity,
                            &response_tx,
                            request_id,
                            Status::aborted("remote MFA wait superseded"),
                        );
                        return;
                    }
                    Ok(Err(err)) => {
                        debug!("Multi-step remote MFA response channel closed: {err:?}");
                        remove_waiter_and_send_error(
                            &waiters,
                            &hash,
                            &waiter_identity,
                            &response_tx,
                            request_id,
                            Status::internal("remote MFA signal channel closed"),
                        );
                        return;
                    }
                    Err(_) => {
                        warn!(
                            "Multi-step remote MFA process with request_id {request_id} timed out"
                        );
                        remove_waiter_and_send_error(
                            &waiters,
                            &hash,
                            &waiter_identity,
                            &response_tx,
                            request_id,
                            Status::deadline_exceeded("remote MFA wait timed out"),
                        );
                        return;
                    }
                },
                result => result,
            };

            remove_remote_mfa_waiter(&waiters, &hash, &waiter_identity);
            let payload = match result {
                Ok(FinishOutcome::AwaitingExternal) => {
                    Payload::CoreError(Status::internal("mobile approval did not complete").into())
                }
                Ok(outcome) => Payload::MfaFlowRemote(MfaFlowRemoteResponse {
                    outcome: Some(mfa_flow_remote_response::Outcome::Result(outcome.into())),
                }),
                Err(error) => Payload::CoreError(Status::from(error).into()),
            };
            let _ = response_tx.send(CoreResponse {
                id: request_id,
                payload: Some(payload),
            });
        });

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn legacy_mfa_remote(
        &self,
        request: AwaitRemoteMfaFinishRequest,
        response_tx: UnboundedSender<CoreResponse>,
        request_id: u64,
        _info: Option<proxy::DeviceInfo>,
    ) -> Result<(), Status> {
        self.legacy_mfa_remote_with_timeout(request, response_tx, request_id, REMOTE_AUTH_TIMEOUT)
            .await
    }

    async fn legacy_mfa_remote_with_timeout(
        &self,
        request: AwaitRemoteMfaFinishRequest,
        response_tx: UnboundedSender<CoreResponse>,
        request_id: u64,
        timeout: Duration,
    ) -> Result<(), Status> {
        debug!("Awaiting remote MFA finish for request_id {request_id}");

        // Register a waiter only for a token that maps to a live in-progress session, so an
        // unauthenticated caller cannot grow the waiter map without bound.
        let Some(_session) = self
            .engine
            .find_active_session_for_flow(&request.token, VpnMfaFlowKind::Legacy)
            .await
            .map_err(|err| {
                error!("Failed to find MFA session: {err}");
                Status::internal("unexpected error")
            })?
        else {
            error!("Client login session not found");
            return Err(Status::invalid_argument("login session not found"));
        };

        let hash = hash_token(&request.token);
        let (signal_tx, rx) = oneshot::channel();
        let legacy_preshared_key = Arc::new(Mutex::new(None));
        let waiter_identity = Arc::new(());
        let replaced_waiter = {
            self.remote_mfa_responses
                .write()
                .expect("Failed to write-lock ClientMfaServer::remote_mfa_responses")
                .insert(
                    hash.clone(),
                    RemoteAuthWaiter {
                        waiter_identity: waiter_identity.clone(),
                        signal_tx,
                        kind: RemoteAuthWaiterKind::Legacy {
                            preshared_key: legacy_preshared_key.clone(),
                        },
                    },
                )
        };
        if let Some(waiter) = replaced_waiter {
            signal_remote_mfa_waiter(waiter, RemoteAuthSignal::Superseded);
        }

        let waiters = self.remote_mfa_responses.clone();
        // Legacy keys stay with the waiting client, not in the message.
        tokio::spawn(async move {
            match time::timeout(timeout, rx).await {
                Ok(Ok(RemoteAuthSignal::Superseded)) => {
                    remove_waiter_and_send_error(
                        &waiters,
                        &hash,
                        &waiter_identity,
                        &response_tx,
                        request_id,
                        Status::aborted("remote MFA wait superseded"),
                    );
                }
                Ok(Ok(RemoteAuthSignal::MobileClientOutdated)) => {
                    unreachable!("MobileClientOutdated can only be sent to MultiStep waiters");
                }
                Ok(Ok(RemoteAuthSignal::Approved)) => {
                    if let Some(preshared_key) = legacy_preshared_key
                        .lock()
                        .expect("Failed to lock legacy remote MFA preshared key")
                        .take()
                    {
                        let req = CoreResponse {
                            id: request_id,
                            payload: Some(Payload::AwaitRemoteMfaFinish(
                                AwaitRemoteMfaFinishResponse { preshared_key },
                            )),
                        };
                        let _ = response_tx.send(req);
                        return;
                    }

                    let _ = response_tx.send(CoreResponse {
                        id: request_id,
                        payload: Some(Payload::CoreError(
                            Status::internal("unexpected error").into(),
                        )),
                    });
                }
                Ok(Err(err)) => {
                    debug!("Remote MFA response channel closed: {err:?}");
                    remove_waiter_and_send_error(
                        &waiters,
                        &hash,
                        &waiter_identity,
                        &response_tx,
                        request_id,
                        Status::internal("remote MFA signal channel closed"),
                    );
                }
                Err(_) => {
                    warn!("Remote MFA process with request_id {request_id} timed out");
                    remove_waiter_and_send_error(
                        &waiters,
                        &hash,
                        &waiter_identity,
                        &response_tx,
                        request_id,
                        Status::deadline_exceeded("remote MFA wait timed out"),
                    );
                }
            }
        });

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn legacy_mfa_finish(
        &self,
        request: ClientMfaFinishRequest,
        info: Option<proxy::DeviceInfo>,
    ) -> Result<ClientMfaFinishResponse, Status> {
        debug!("Finishing desktop client login");

        let token = request.token.clone();
        let legacy_proof = LegacyProof {
            code: request.code.clone(),
            auth_pub_key: request.auth_pub_key.clone(),
        };
        let (ip, _user_agent) = parse_client_ip_agent(&info).map_err(Status::internal)?;
        let (outcome, method) = match self
            .engine
            .finish_legacy(token.clone(), legacy_proof, ip)
            .await
        {
            Ok(result) => result,
            Err(error @ FinishError::SessionNotFound) => {
                let Some(proof) = self
                    .engine
                    .check_legacy_mobile_proof(
                        &token,
                        request.code.as_deref().unwrap_or_default(),
                        request.auth_pub_key.as_deref().unwrap_or_default(),
                    )
                    .await?
                else {
                    return Err(Status::from(error));
                };

                warn!(
                    "Legacy mobile app tried to approve multi-step MFA for user {} on device {} at location {}",
                    proof.username, proof.device_id, proof.location_name
                );
                if let Some(waiter) = take_multi_step_remote_mfa_waiter(
                    &self.remote_mfa_responses,
                    &token,
                    &proof.step_attempt_id,
                ) {
                    signal_remote_mfa_waiter(waiter, RemoteAuthSignal::MobileClientOutdated);
                }
                return Err(Status::failed_precondition(LEGACY_MOBILE_CLIENT_MESSAGE));
            }
            Err(error) => return Err(Status::from(error)),
        };

        let is_mobile_signature = method == VpnClientMfaMethod::MobileApprove;
        let preshared_key = match &outcome {
            LegacyFinishOutcome::Completed { preshared_key } => {
                if is_mobile_signature {
                    if let Some((waiter, waiter_key)) =
                        take_legacy_remote_mfa_waiter(&self.remote_mfa_responses, &token)
                    {
                        *waiter_key
                            .lock()
                            .expect("Failed to lock legacy remote MFA preshared key") =
                            Some(preshared_key.expose_secret().to_owned());
                        signal_remote_mfa_waiter(waiter, RemoteAuthSignal::Approved);
                    }
                    String::new()
                } else {
                    preshared_key.expose_secret().to_owned()
                }
            }
            LegacyFinishOutcome::AwaitingExternal => String::new(),
        };

        Ok(ClientMfaFinishResponse {
            preshared_key,
            token: is_mobile_signature.then_some(token),
        })
    }

    #[instrument(skip_all)]
    pub async fn mfa_flow_step_start(
        &self,
        request: MfaFlowStepStartRequest,
    ) -> Result<MfaFlowStepStartResponse, Status> {
        debug!("Starting multi-step MFA step");
        let method = parse_mfa_method(request.method)?;
        let step_started = self.engine.step_start(request.token, method).await?;
        let started = encode_step_started(
            method,
            step_started.step_attempt_id,
            step_started.challenge,
            step_started.credential_ids,
        )?;
        Ok(MfaFlowStepStartResponse {
            started: Some(started),
        })
    }

    #[instrument(skip_all)]
    pub async fn mfa_flow_step_finish(
        &self,
        request: MfaFlowStepFinishRequest,
        info: Option<proxy::DeviceInfo>,
    ) -> Result<MfaFlowStepFinishResponse, Status> {
        debug!("Finishing multi-step MFA step");
        let (token, proof) = into_step_proof(request);
        let (ip, _user_agent) = parse_client_ip_agent(&info).map_err(Status::internal)?;
        let result = self.engine.finish_step(token, proof, ip).await?;
        Ok(MfaFlowStepFinishResponse {
            result: Some(result.into()),
        })
    }

    async fn approve_and_wake_mobile_step(
        &self,
        token: String,
        proof: MobileApprovalProof,
        ip: IpAddr,
    ) -> Result<(), Status> {
        let step_attempt_id = proof.step_attempt_id.clone();
        self.engine
            .approve_mobile_step(token.clone(), proof, ip)
            .await?;

        if let Some(waiter) =
            take_multi_step_remote_mfa_waiter(&self.remote_mfa_responses, &token, &step_attempt_id)
        {
            signal_remote_mfa_waiter(waiter, RemoteAuthSignal::Approved);
        }
        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn mfa_flow_approve(
        &self,
        request: MfaFlowApproveRequest,
        info: Option<proxy::DeviceInfo>,
    ) -> Result<(), Status> {
        debug!("Approving multi-step MFA step");
        let proof = request
            .proof
            .ok_or_else(|| Status::invalid_argument("missing mobile approval proof"))?;
        let (ip, _user_agent) = parse_client_ip_agent(&info).map_err(Status::internal)?;
        self.approve_and_wake_mobile_step(
            request.token,
            MobileApprovalProof {
                signature: proof.signature,
                auth_pub_key: proof.auth_pub_key,
                step_attempt_id: request.step_attempt_id,
            },
            ip,
        )
        .await
    }
}

/// The OpenID step of VPN MFA, completed in the browser through Edge.
impl ClientMfaServer {
    /// The VPN MFA attempt an Edge sign-in is for; `None` when no VPN MFA session has `token`.
    pub async fn oidc_begin(
        &self,
        token: &str,
        attempt_id: Option<&str>,
    ) -> Result<Option<VpnMfaTarget>, CoreError> {
        Ok(self.engine.begin_oidc(token, attempt_id).await?)
    }

    /// Completes the attempt once the provider confirmed the device owner's identity.
    pub async fn oidc_complete(
        &self,
        target: &VpnMfaTarget,
        identity: &Identity,
        ip: IpAddr,
    ) -> Result<(), CoreError> {
        Ok(self.engine.complete_oidc(target, identity, ip).await?)
    }

    /// Audits a sign-in for this attempt that could not be verified.
    pub async fn oidc_failed(&self, target: &VpnMfaTarget, ip: IpAddr, reason: &str) {
        if let Err(err) = self
            .engine
            .oidc_verification_failed(target, ip, reason)
            .await
        {
            error!("Failed to record a failed OpenID MFA sign-in: {err}");
        }
    }
}

impl From<OidcMfaError> for CoreError {
    fn from(error: OidcMfaError) -> Self {
        match error {
            OidcMfaError::SessionExpired => CoreError::unauthenticated(error.to_string())
                .with_code(CoreErrorCode::MfaSessionExpired),
            OidcMfaError::Unavailable => {
                CoreError::from(Status::permission_denied(error.to_string()))
            }
            OidcMfaError::AccountMismatch => CoreError::unauthenticated("unauthorized")
                .with_code(CoreErrorCode::OidcAccountMismatch),
            OidcMfaError::Internal | OidcMfaError::Event(_) => {
                CoreError::internal("unexpected error")
            }
        }
    }
}

#[derive(Debug)]
pub enum MfaStartRejection {
    Status(Status),
}

impl From<Status> for MfaStartRejection {
    fn from(status: Status) -> Self {
        Self::Status(status)
    }
}

#[cfg(test)]
mod tests;
