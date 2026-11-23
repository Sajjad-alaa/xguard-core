//! Connect-time MFA engine for legacy and multi-step flows.
//!
//! The engine owns the step cursor and attempt lifecycle over the durable
//! [`VpnClientMfaSession`](xguard_common::db::models::vpn_client_mfa_session::VpnClientMfaSession)
//! store. The gRPC handlers in `grpc::proxy::client_mfa` are thin adapters converting proto
//! messages to and from the domain types here; the engine never sees a proto message.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use chrono::Utc;
use sqlx::{PgConnection, PgPool};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, warn};
use xguard_common::{
    db::{
        Id,
        models::{
            Device, ThrottleScope, User, WireguardNetwork,
            device::WireguardNetworkDevice,
            mfa_flow::MfaFlow,
            vpn_client_mfa_session::{
                EphemeralState, MFA_FAILED_ATTEMPT_CAP, MfaAttribution, MfaSessionContext,
                StepOutcome, StepsSnapshot, VPN_MFA_SESSION_TIMEOUT, VpnClientMfaSession,
                VpnMfaFlowKind,
            },
            vpn_client_session::{VpnClientMfaMethod, VpnClientSession, VpnClientSessionState},
        },
        wireguard_key::WireguardKey,
    },
    secret::SecretStringWrapper,
};

use crate::{
    events::{BidiRequestContext, BidiStreamEvent, BidiStreamEventType, DesktopClientMfaEvent},
    features::is_mfa_method_supported,
    grpc::GatewayCommand,
    mfa_engine::{
        authorize::{EventChannels, build_authorized_gateway_network_info, create_new_session},
        error::{FinishCoreError, StartError},
        method::{InitiateError, initiate},
        types::{FinishOutcome, StartedSession},
    },
};

pub mod authorize;
pub mod error;
pub mod fido2;
pub mod legacy;
pub mod method;
pub mod multi_step;
pub mod oidc;
pub mod types;

/// Whether this method uses the device/location code-attempt throttle.
fn is_code_method(method: VpnClientMfaMethod) -> bool {
    matches!(method, VpnClientMfaMethod::Totp | VpnClientMfaMethod::Email)
}

/// Keyed by location and device, so a new MFA session keeps the count of the session it replaces.
fn throttle_key(location_id: Id, device_id: Id) -> String {
    format!("{location_id}:{device_id}")
}

const POLL_LIMIT: u32 = 120;
const POLL_WINDOW: Duration = Duration::from_mins(1);

/// Kept in memory, so that a poll costs no database write.
static POLLS: LazyLock<Mutex<PollWindows>> =
    LazyLock::new(|| Mutex::new(PollWindows::new(Instant::now())));

struct PollWindows {
    windows: HashMap<String, (Instant, u32)>,
    pruned_at: Instant,
}

impl PollWindows {
    fn new(now: Instant) -> Self {
        Self {
            windows: HashMap::new(),
            pruned_at: now,
        }
    }

    fn hit(&mut self, key: &str, now: Instant) -> bool {
        if now.duration_since(self.pruned_at) >= POLL_WINDOW {
            self.windows
                .retain(|_, (started, _)| now.duration_since(*started) < POLL_WINDOW);
            self.pruned_at = now;
        }
        let (started, polls) = self.windows.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(*started) >= POLL_WINDOW {
            *started = now;
            *polls = 0;
        }
        *polls += 1;
        *polls <= POLL_LIMIT
    }
}

fn poll_allowed(token_hash: &str) -> bool {
    POLLS
        .lock()
        .expect("Failed to lock the MFA poll counts")
        .hit(token_hash, Instant::now())
}

/// Owns connect-time MFA session state and final authorization.
///
/// It mints sessions, verifies proofs, advances the step cursor, and authorizes the peer at the
/// final step.
#[derive(Clone)]
pub struct MfaEngine {
    pool: PgPool,
    channels: EventChannels,
}

pub(crate) fn filter_supported_mfa_methods(
    methods: &HashSet<VpnClientMfaMethod>,
) -> HashSet<VpnClientMfaMethod> {
    let supported: HashSet<_> = methods
        .iter()
        .copied()
        .filter(|method| is_mfa_method_supported(*method))
        .collect();
    if supported.len() < methods.len() {
        let removed: Vec<_> = VpnClientMfaMethod::ALL
            .into_iter()
            .filter(|method| methods.contains(method) && !supported.contains(method))
            .collect();
        debug!("Unsupported MFA methods {removed:?} were removed from this step");
    }
    supported
}

/// The side effects of a completed flow, built inside the transaction but dispatched by the
/// caller **after** it commits.
///
/// Neither the gateway authorization nor the success event can be rolled back. Dispatched inside
/// the transaction, a failed commit would leave the gateway holding an authorized peer with no
/// session row to show for it. Dispatched after, a failure surfaces as an error rather than as
/// silent access.
struct CompletedFlow {
    outcome: FinishOutcome,
    gateway_command: GatewayCommand,
    posture_event: Option<BidiStreamEvent>,
    event: BidiStreamEvent,
}

enum CompleteFlowOutcome {
    Completed(Box<CompletedFlow>),
    PostureRejected {
        failed_checks: Vec<String>,
        gateway_command: Option<Box<GatewayCommand>>,
        events: Vec<BidiStreamEvent>,
    },
}

pub(in crate::mfa_engine) struct LoadedFinishContext {
    pub(in crate::mfa_engine) session: VpnClientMfaSession<Id>,
    pub(in crate::mfa_engine) ctx: MfaSessionContext,
    pub(in crate::mfa_engine) ephemeral: EphemeralState,
    pub(in crate::mfa_engine) context: BidiRequestContext,
}

impl MfaEngine {
    #[must_use]
    pub fn new(
        pool: PgPool,
        gateway_tx: UnboundedSender<GatewayCommand>,
        bidi_event_tx: UnboundedSender<BidiStreamEvent>,
    ) -> Self {
        Self {
            pool,
            channels: EventChannels::new(gateway_tx, bidi_event_tx),
        }
    }

    /// Create and persist the initial MFA session and attempt, carrying optional posture facts
    /// to commit only once authentication succeeds.
    #[allow(clippy::too_many_arguments)]
    async fn start_session_with_posture(
        &self,
        location: &WireguardNetwork<Id>,
        device: &Device<Id>,
        user: &User<Id>,
        flow_id: Id,
        steps: Vec<HashSet<VpnClientMfaMethod>>,
        flow_kind: VpnMfaFlowKind,
        method: VpnClientMfaMethod,
        posture_facts: Option<serde_json::Value>,
    ) -> Result<StartedSession, StartError> {
        // Refuse before `initiate` so that a locked device receives no further email code.
        if is_code_method(method)
            && ThrottleScope::VpnMfaCode
                .is_blocked(&self.pool, &throttle_key(location.id, device.id))
                .await
                .map_err(|err| {
                    error!("Failed to read the MFA code throttle: {err}");
                    StartError::Internal
                })?
        {
            warn!(
                "User {} has no MFA code attempts left for device {} at location {}",
                user.username, device.id, location.name
            );
            return Err(StartError::AttemptLimit);
        }

        let ctx = MfaSessionContext {
            location: location.clone(),
            device: device.clone(),
            user: user.clone(),
        };
        let initiated = initiate(&self.pool, &ctx, method).await.map_err(|err| {
            log_initiate_error(&err, &ctx);
            StartError::from(err)
        })?;
        let response_challenge = initiated.challenge();
        let credential_ids = initiated.credential_ids();

        // The FIDO2 challenge state is written in the same transaction as the session, so the
        // session is never visible with an attempt that lacks it.
        let mut transaction = self.pool.begin().await.map_err(|err| {
            error!("Failed to begin transaction: {err}");
            StartError::Internal
        })?;
        let step_methods = steps.iter().map(VpnClientMfaMethod::ordered_set).collect();
        let (session, outcome) = VpnClientMfaSession::<Id>::start_with_posture(
            &mut transaction,
            location.id,
            device.id,
            user.id,
            flow_id,
            step_methods,
            flow_kind,
            method,
            initiated.signature,
            posture_facts,
            VPN_MFA_SESSION_TIMEOUT,
        )
        .await
        .map_err(|err| {
            error!("Failed to start MFA session: {err}");
            StartError::Internal
        })?;
        if let Some(issued) = &initiated.fido2
            && !session
                .set_fido2_state(&mut transaction, &outcome.step_attempt_id, &issued.state)
                .await
                .map_err(|err| {
                    error!("Failed to store the FIDO2 challenge: {err}");
                    StartError::Internal
                })?
        {
            error!("The new MFA session lost its first attempt before the FIDO2 challenge");
            return Err(StartError::Internal);
        }
        transaction.commit().await.map_err(|err| {
            error!("Failed to commit the new MFA session: {err}");
            StartError::Internal
        })?;

        Ok(StartedSession {
            token: outcome.token,
            step_attempt_id: outcome.step_attempt_id,
            challenge: response_challenge,
            credential_ids,
            superseded_token_hash: outcome.superseded_token_hash,
        })
    }

    /// Whether OpenID MFA can run: a provider is enabled and Edge has a public URL for the
    /// browser round trip.
    async fn oidc_available(&self) -> sqlx::Result<bool> {
        crate::sso::edge::available(&self.pool).await
    }

    /// See [`Self::oidc_available`].
    async fn oidc_provider_configured(&self) -> sqlx::Result<bool> {
        self.oidc_available().await
    }

    /// Load an active session only when it belongs to the contract selected by the caller.
    ///
    /// A mismatched flow is indistinguishable from an expired or unknown token. Keeping this
    /// check here protects engine callers that do not have an adapter-level route boundary.
    pub(crate) async fn find_active_session_for_flow(
        &self,
        token: &str,
        expected_flow_kind: VpnMfaFlowKind,
    ) -> sqlx::Result<Option<VpnClientMfaSession<Id>>> {
        Ok(
            VpnClientMfaSession::<Id>::find_active_by_token(&self.pool, token)
                .await?
                .filter(|session| session.flow_kind == expected_flow_kind),
        )
    }

    pub(in crate::mfa_engine) async fn load_finish_context(
        &self,
        token: &str,
        expected_flow_kind: VpnMfaFlowKind,
        ip: IpAddr,
    ) -> Result<LoadedFinishContext, FinishCoreError> {
        let Some(session) = self
            .find_active_session_for_flow(token, expected_flow_kind)
            .await
            .map_err(|err| {
                error!("Failed to find MFA session: {err}");
                FinishCoreError::Internal
            })?
        else {
            debug!("Client login session not found");
            return Err(FinishCoreError::SessionNotFound);
        };

        let Some(ctx) = session.load_context(&self.pool).await.map_err(|err| {
            error!("Failed to load MFA session context: {err}");
            FinishCoreError::Internal
        })?
        else {
            error!("MFA session references a missing location, device, or user");
            return Err(FinishCoreError::Internal);
        };

        let Some(ephemeral_state) = session.ephemeral_state.as_ref() else {
            debug!("No MFA attempt in progress");
            return Err(FinishCoreError::UninitializedStep);
        };

        let ephemeral = ephemeral_state.0.clone();
        let context = BidiRequestContext::new(
            ctx.user.id,
            ctx.user.username.clone(),
            ip,
            format!("{}", ctx.device),
        );
        Ok(LoadedFinishContext {
            session,
            ctx,
            ephemeral,
            context,
        })
    }

    pub(in crate::mfa_engine) async fn advance_and_complete(
        &self,
        session: VpnClientMfaSession<Id>,
        ctx: &MfaSessionContext,
        context: BidiRequestContext,
        attempt_id: Option<&str>,
        method: VpnClientMfaMethod,
        mobile_auth_device_name: Option<&str>,
    ) -> Result<FinishOutcome, FinishCoreError> {
        let mut transaction = self.pool.begin().await.map_err(|err| {
            error!("Failed to begin transaction: {err}");
            FinishCoreError::Internal
        })?;

        let Some((advance, snapshot)) = session
            .advance(
                &mut transaction,
                session.current_step,
                attempt_id,
                method,
                mobile_auth_device_name,
            )
            .await
            .map_err(|err| {
                error!("Failed to advance MFA session: {err}");
                FinishCoreError::Internal
            })?
        else {
            error!("Stale MFA attempt: the step was already advanced or the attempt is superseded");
            return Err(FinishCoreError::StaleAttempt);
        };

        if let StepOutcome::Advanced { next_step } = advance {
            transaction.commit().await.map_err(|err| {
                error!("Failed to commit transaction while advancing MFA flow: {err}");
                FinishCoreError::Internal
            })?;
            return Ok(FinishOutcome::Advanced {
                next_step: next_step as u32,
            });
        }

        let outcome = self
            .complete_flow(&mut transaction, session, snapshot, ctx, context)
            .await?;
        transaction.commit().await.map_err(|err| {
            error!("Failed to commit transaction while finishing desktop client login: {err}");
            FinishCoreError::Internal
        })?;

        match outcome {
            CompleteFlowOutcome::Completed(completed) => {
                debug!("Sending `peer_create` message to gateway");
                self.channels
                    .gateway_tx
                    .send(completed.gateway_command)
                    .map_err(|err| {
                        error!("Error sending WireGuard event: {err}");
                        FinishCoreError::Internal
                    })?;
                if let Some(posture_event) = completed.posture_event {
                    self.channels.emit_event(posture_event)?;
                }
                self.channels.emit_event(completed.event)?;
                Ok(completed.outcome)
            }
            CompleteFlowOutcome::PostureRejected {
                failed_checks,
                gateway_command,
                events,
            } => {
                if let Some(cmd) = gateway_command
                    && let Err(err) = self.channels.gateway_tx.send(*cmd)
                {
                    error!("Failed to send gateway deauthorization after posture failure: {err}");
                }
                for event in events {
                    if let Err(err) = self.channels.emit_event(event) {
                        error!("Failed to emit posture event: {err}");
                    }
                }
                Err(FinishCoreError::PostureRejected(failed_checks))
            }
        }
    }

    /// Completes the flow by creating the preshared key and VPN session, then removing the MFA
    /// session. Database changes happen together; [`CompleteFlowOutcome`] carries events for
    /// dispatch after the commit.
    async fn complete_flow(
        &self,
        transaction: &mut PgConnection,
        session: VpnClientMfaSession<Id>,
        snapshot: StepsSnapshot,
        ctx: &MfaSessionContext,
        context: BidiRequestContext,
    ) -> Result<CompleteFlowOutcome, FinishCoreError> {
        let Ok(Some(network_device)) =
            WireguardNetworkDevice::find(&mut *transaction, ctx.device.id, ctx.location.id).await
        else {
            error!(
                "Failed to fetch network config for device {} and location {}",
                ctx.device, ctx.location
            );
            return Err(FinishCoreError::Internal);
        };

        // Authorization point: evaluate/commit any deferred MFA-start posture facts or verify the
        // stored posture snapshot against the location's current policies.
        let (posture_result, posture_facts, emit_passed) =
            if let Some(facts_json) = &snapshot.posture_facts {
                match crate::posture::commit_and_check_facts(
                    &mut *transaction,
                    ctx.location.id,
                    ctx.device.id,
                    facts_json,
                    session.created_at,
                )
                .await
                .map_err(|err| {
                    error!("Failed to check the posture of {}: {err}", ctx.device);
                    FinishCoreError::Internal
                })? {
                    Some(check) => (check.result, check.facts, true),
                    None => (crate::posture::PostureResult::Pass, None, false),
                }
            } else {
                let result = crate::posture::check_stored_snapshot(
                    &mut *transaction,
                    ctx.location.id,
                    ctx.device.id,
                )
                .await
                .map_err(|err| {
                    error!("Failed to check the posture of {}: {err}", ctx.device);
                    FinishCoreError::Internal
                })?;
                (result, None, false)
            };
        let posture_event = match posture_result {
            crate::posture::PostureResult::Pass => emit_passed.then(|| BidiStreamEvent {
                context: context.clone(),
                event: BidiStreamEventType::DesktopClientMfa(Box::new(
                    DesktopClientMfaEvent::PostureCheckPassed {
                        device: ctx.device.clone(),
                        location: ctx.location.clone(),
                        facts: posture_facts,
                    },
                )),
            }),
            crate::posture::PostureResult::Fail(failed_checks) => {
                warn!(
                    "Refusing to authorize {} in {}: {}",
                    ctx.device,
                    ctx.location,
                    failed_checks.join("; ")
                );
                session.delete(&mut *transaction).await.map_err(|err| {
                    error!("Failed to delete rejected MFA session: {err}");
                    FinishCoreError::Internal
                })?;

                let active_sessions = VpnClientSession::get_all_active_device_sessions_in_location(
                    &mut *transaction,
                    ctx.location.id,
                    ctx.device.id,
                )
                .await
                .map_err(|err| {
                    error!(
                        "Failed to fetch active VPN sessions for device {} in location {}: {err}",
                        ctx.device, ctx.location
                    );
                    FinishCoreError::Internal
                })?;

                let mut events = Vec::new();
                let disconnect_timestamp = Utc::now().naive_utc();
                let gateway_command = if active_sessions.is_empty() {
                    None
                } else {
                    for mut active in active_sessions {
                        let was_connected = active.state == VpnClientSessionState::Connected;
                        let is_mfa_session = active.is_mfa_session;
                        active.disconnected_at = Some(disconnect_timestamp);
                        active.state = VpnClientSessionState::Disconnected;
                        active.save(&mut *transaction).await.map_err(|err| {
                            error!("Failed to revoke VPN session {}: {err}", active.id);
                            FinishCoreError::Internal
                        })?;
                        if was_connected {
                            events.push(BidiStreamEvent {
                                context: BidiRequestContext {
                                    timestamp: disconnect_timestamp,
                                    user_id: ctx.user.id,
                                    username: ctx.user.username.clone(),
                                    ip: None,
                                    device_name: format!("{}", ctx.device),
                                },
                                event: BidiStreamEventType::DesktopClientMfa(Box::new(
                                    DesktopClientMfaEvent::Disconnected {
                                        location: ctx.location.clone(),
                                        device: ctx.device.clone(),
                                        is_mfa_session,
                                    },
                                )),
                            });
                        }
                    }
                    Some(Box::new(GatewayCommand::VpnSessionDeauthorized(
                        ctx.location.id,
                        ctx.device.clone(),
                    )))
                };

                events.push(BidiStreamEvent {
                    context: context.clone(),
                    event: BidiStreamEventType::DesktopClientMfa(Box::new(
                        DesktopClientMfaEvent::PostureCheckFailed {
                            device: ctx.device.clone(),
                            location: ctx.location.clone(),
                            facts: posture_facts,
                            failed_checks: failed_checks.clone(),
                        },
                    )),
                });

                return Ok(CompleteFlowOutcome::PostureRejected {
                    failed_checks,
                    gateway_command,
                    events,
                });
            }
        };

        let flow_name = MfaFlow::find_by_id(&mut *transaction, snapshot.flow_id)
            .await
            .map_err(|err| {
                error!("Failed to resolve MFA flow for attribution: {err}");
                FinishCoreError::Internal
            })?
            .map(|flow| flow.title);

        let key = WireguardKey::generate();
        let preshared_key = SecretStringWrapper::from(key.public());

        let vpn_client_session = create_new_session(
            &self.channels,
            &mut *transaction,
            &ctx.location,
            &ctx.user,
            &ctx.device,
            true,
            preshared_key.clone(),
        )
        .await
        .map_err(|err| match err {
            authorize::AuthorizeError::ConnectionLimitReached(limit) => {
                FinishCoreError::ConnectionLimitReached(limit)
            }
            other => {
                error!(
                    "Failed to create new VPN client session for device {} in location {}: {other}",
                    ctx.device, ctx.location
                );
                FinishCoreError::Internal
            }
        })?;
        debug!(
            "Created new VPN client session with id {}",
            vpn_client_session.id
        );

        let gateway_network_info =
            build_authorized_gateway_network_info(network_device, preshared_key.clone());

        let gateway_command = GatewayCommand::VpnSessionAuthorized(
            ctx.location.id,
            ctx.device.clone(),
            gateway_network_info,
        );

        // Use the last mobile approval's name; do not fall back to an earlier one.
        let mobile_auth_device_name = snapshot
            .steps
            .iter()
            .rev()
            .find(|step| step.satisfied == Some(VpnClientMfaMethod::MobileApprove))
            .and_then(|step| step.mobile_auth_device_name.clone());

        let event = BidiStreamEvent {
            context,
            event: BidiStreamEventType::DesktopClientMfa(Box::new(
                DesktopClientMfaEvent::Success {
                    location: ctx.location.clone(),
                    device: ctx.device.clone(),
                    attribution: MfaAttribution {
                        snapshot,
                        flow_name,
                    },
                    mobile_auth_device_name,
                },
            )),
        };

        session.delete(&mut *transaction).await.map_err(|err| {
            error!("Failed to delete MFA session: {err}");
            FinishCoreError::Internal
        })?;

        Ok(CompleteFlowOutcome::Completed(Box::new(CompletedFlow {
            outcome: FinishOutcome::Completed { preshared_key },
            gateway_command,
            posture_event,
            event,
        })))
    }

    /// Record a proof-verification failure, deleting the session once the per-step cap is reached
    /// so a subsequent finish fails closed.
    async fn record_failure(
        &self,
        session: VpnClientMfaSession<Id>,
        ctx: &MfaSessionContext,
        ip: IpAddr,
    ) -> Result<bool, FinishCoreError> {
        let mut transaction = self.pool.begin().await.map_err(|err| {
            error!("Failed to begin transaction while recording MFA failure: {err}");
            FinishCoreError::Internal
        })?;
        let at_cap = session
            .increment_failed_attempts(&mut transaction)
            .await
            .map_err(|err| {
                error!("Failed to record MFA failure: {err}");
                FinishCoreError::Internal
            })?;
        let abort_event = if at_cap {
            let flow_name = MfaFlow::find_by_id(&mut *transaction, session.steps_snapshot.flow_id)
                .await
                .map_err(|err| {
                    error!("Failed to resolve MFA flow for abort attribution: {err}");
                    FinishCoreError::Internal
                })?
                .map(|flow| flow.title);
            Some(BidiStreamEvent {
                context: BidiRequestContext::new(
                    ctx.user.id,
                    ctx.user.username.clone(),
                    ip,
                    format!("{}", ctx.device),
                ),
                event: BidiStreamEventType::DesktopClientMfa(Box::new(
                    DesktopClientMfaEvent::Aborted {
                        location: ctx.location.clone(),
                        device: ctx.device.clone(),
                        attribution: MfaAttribution {
                            snapshot: session.steps_snapshot.0.clone(),
                            flow_name,
                        },
                    },
                )),
            })
        } else {
            None
        };
        if at_cap {
            warn!(
                "MFA session {} hit the failed-attempt cap of {MFA_FAILED_ATTEMPT_CAP}; deleting it",
                session.id
            );
            session.delete(&mut *transaction).await.map_err(|err| {
                error!("Failed to delete MFA session: {err}");
                FinishCoreError::Internal
            })?;
        }
        transaction.commit().await.map_err(|err| {
            error!("Failed to commit MFA failure record: {err}");
            FinishCoreError::Internal
        })?;
        if let Some(event) = abort_event {
            self.channels.emit_event(event)?;
        }
        Ok(at_cap)
    }
}

/// Log an [`InitiateError`] with the context it needs, so both start methods can wrap it into their
/// own error type without duplicating the logging.
fn log_initiate_error(err: &InitiateError, ctx: &MfaSessionContext) {
    let username = &ctx.user.username;
    match err {
        InitiateError::EmailCode(e) => error!("Failed to generate email MFA code: {e}"),
        InitiateError::Database(e) => error!("Database error: {e}"),
        InitiateError::Mail(e) => {
            error!("Failed to send email MFA code for user {username}: {e}");
        }
        InitiateError::BiometricNotConfigured => {}
        InitiateError::InvalidPublicKey(e) => {
            error!("Start biometric MFA failed. Challenge creation failed. Reason: {e}");
        }
        InitiateError::UnsupportedMethod => {
            error!("MFA start for user {username} selected a method Core does not support");
        }
        InitiateError::TooManyRequests => warn!(
            "User {username} has no MFA step initiations left for device {} at location {}",
            ctx.device.id, ctx.location.name
        ),
        InitiateError::Fido2NotConfigured => {
            warn!("User {username} selected FIDO2 MFA with no security key registered for VPN MFA");
        }
        InitiateError::Fido2(e) => error!("Failed to issue a FIDO2 challenge: {e}"),
    }
}

#[cfg(test)]
mod tests;
