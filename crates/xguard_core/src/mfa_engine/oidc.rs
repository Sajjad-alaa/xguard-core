//! The OpenID step of a VPN MFA login, completed in the browser through Edge.
//!
//! The desktop client starts an attempt with the `Oidc` method and opens Edge's OpenID MFA page
//! with the session token (and, for multi-step flows, the attempt ID). [`MfaEngine::begin_oidc`]
//! binds the browser sign-in to that exact attempt; [`MfaEngine::complete_oidc`] checks that the
//! provider's subject is the one linked to the device owner and marks the attempt complete. The
//! client's next poll then finishes the step like any other method.
//!
//! - **Bound to one attempt:** a re-issued or advanced step makes the sign-in stale.
//! - **No account linking:** only the subject already linked to the device owner is accepted; an
//!   MFA sign-in never links or creates accounts.
//! - **Fail closed:** a sign-in as anyone else ends the MFA session and is audited.

use std::net::IpAddr;

use chrono::Utc;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use xguard_common::db::{
    Id,
    models::{
        vpn_client_mfa_session::{VpnClientMfaSession, VpnMfaFlowKind},
        vpn_client_session::VpnClientMfaMethod,
    },
};

use super::{MfaEngine, authorize::ClientMfaServerError};
use crate::{
    events::{BidiRequestContext, BidiStreamEvent, BidiStreamEventType, DesktopClientMfaEvent},
    sso::{
        edge::{VpnMfaTarget, same_secret, subject_matches},
        flow::Identity,
    },
};

/// Why an OpenID MFA step could not start or complete.
#[derive(Debug, Error)]
pub enum OidcMfaError {
    /// Unknown or expired session, a stale attempt, or an attempt that is not an OpenID step.
    #[error("MFA session not found or expired")]
    SessionExpired,
    /// The device owner has no linked identity, or is disabled.
    #[error("OpenID MFA is not available for this account")]
    Unavailable,
    /// The provider signed in someone other than the device owner.
    #[error("unauthorized")]
    AccountMismatch,
    #[error("unexpected error")]
    Internal,
    #[error(transparent)]
    Event(#[from] ClientMfaServerError),
}

fn internal(context: &str) -> impl Fn(sqlx::Error) -> OidcMfaError + '_ {
    move |err| {
        error!("{context}: {err}");
        OidcMfaError::Internal
    }
}

impl MfaEngine {
    /// Resolves the OpenID attempt a browser sign-in is for.
    ///
    /// `attempt_id` comes from the client's link; multi-step sessions must name their attempt,
    /// legacy sessions (one step, no attempt IDs on the wire) use their only attempt.
    pub async fn begin_oidc(
        &self,
        token: &str,
        attempt_id: Option<&str>,
    ) -> Result<Option<VpnMfaTarget>, OidcMfaError> {
        let Some(session) = VpnClientMfaSession::<Id>::find_active_by_token(&self.pool, token)
            .await
            .map_err(internal("Failed to find MFA session"))?
        else {
            return Ok(None);
        };
        let Some(ephemeral) = session.ephemeral_state.as_ref().map(|state| &state.0) else {
            debug!(
                "OpenID MFA requested for session {} with no attempt",
                session.id
            );
            return Err(OidcMfaError::SessionExpired);
        };
        if ephemeral.selected_method != VpnClientMfaMethod::Oidc {
            debug!(
                "OpenID MFA requested for session {}, whose attempt uses {:?}",
                session.id, ephemeral.selected_method
            );
            return Err(OidcMfaError::SessionExpired);
        }
        match (session.flow_kind, attempt_id) {
            (_, Some(attempt_id)) if !same_secret(&ephemeral.step_attempt_id, attempt_id) => {
                debug!(
                    "OpenID MFA requested for a stale attempt of session {}",
                    session.id
                );
                return Err(OidcMfaError::SessionExpired);
            }
            (VpnMfaFlowKind::MultiStep, None) => {
                debug!(
                    "OpenID MFA requested for multi-step session {} without an attempt",
                    session.id
                );
                return Err(OidcMfaError::SessionExpired);
            }
            _ => {}
        }
        let ctx = session
            .load_context(&self.pool)
            .await
            .map_err(internal("Failed to load MFA session context"))?
            .ok_or(OidcMfaError::SessionExpired)?;
        if !ctx.user.is_active || ctx.user.openid_sub.is_none() {
            warn!(
                "User {} cannot use OpenID MFA: disabled or not linked to the provider",
                ctx.user.username
            );
            return Err(OidcMfaError::Unavailable);
        }
        Ok(Some(VpnMfaTarget {
            session_id: session.id,
            token_hash: session.token_hash.clone(),
            attempt_id: ephemeral.step_attempt_id.clone(),
            user_id: ctx.user.id,
        }))
    }

    /// Completes the OpenID attempt with a verified identity.
    pub async fn complete_oidc(
        &self,
        target: &VpnMfaTarget,
        identity: &Identity,
        ip: IpAddr,
    ) -> Result<(), OidcMfaError> {
        // Load again: the session may have advanced, been superseded or expired meanwhile.
        let session = VpnClientMfaSession::<Id>::find_by_id(&self.pool, target.session_id)
            .await
            .map_err(internal("Failed to find MFA session"))?
            .filter(|session| {
                session.token_hash == target.token_hash
                    && session.user_id == target.user_id
                    && session.expires_at > Utc::now().naive_utc()
            })
            .ok_or(OidcMfaError::SessionExpired)?;
        let current = session.ephemeral_state.as_ref().is_some_and(|state| {
            state.0.selected_method == VpnClientMfaMethod::Oidc
                && same_secret(&state.0.step_attempt_id, &target.attempt_id)
        });
        if !current {
            debug!(
                "OpenID MFA callback for a stale attempt of session {}",
                session.id
            );
            return Err(OidcMfaError::SessionExpired);
        }
        let ctx = session
            .load_context(&self.pool)
            .await
            .map_err(internal("Failed to load MFA session context"))?
            .ok_or(OidcMfaError::SessionExpired)?;
        let context = BidiRequestContext::new(
            ctx.user.id,
            ctx.user.username.clone(),
            ip,
            format!("{}", ctx.device),
        );

        // Compare with the link as it is now, so an unlinked or disabled account cannot finish.
        if !ctx.user.is_active || !subject_matches(ctx.user.openid_sub.as_deref(), identity) {
            warn!(
                "OpenID MFA for user {} at location {} was completed by another identity; \
                 ending the MFA session",
                ctx.user.username, ctx.location.name
            );
            session
                .delete(&self.pool)
                .await
                .map_err(internal("Failed to delete MFA session"))?;
            self.channels.emit_event(BidiStreamEvent {
                context,
                event: BidiStreamEventType::DesktopClientMfa(Box::new(
                    DesktopClientMfaEvent::Failed {
                        location: ctx.location.clone(),
                        device: ctx.device.clone(),
                        method: VpnClientMfaMethod::Oidc.into(),
                        message: "Signed in to the identity provider as another account".into(),
                    },
                )),
            })?;
            return Err(OidcMfaError::AccountMismatch);
        }

        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(internal("Failed to acquire a connection"))?;
        if !session
            .mark_oidc_completed(&mut conn, &target.attempt_id)
            .await
            .map_err(internal("Failed to mark the OpenID MFA attempt"))?
        {
            return Err(OidcMfaError::SessionExpired);
        }
        info!(
            "User {} completed OpenID MFA for device {} at location {}",
            ctx.user.username, ctx.device.name, ctx.location.name
        );
        Ok(())
    }

    /// Audits an OpenID MFA sign-in that the provider or Core could not verify.
    pub async fn oidc_verification_failed(
        &self,
        target: &VpnMfaTarget,
        ip: IpAddr,
        reason: &str,
    ) -> Result<(), OidcMfaError> {
        let Some(session) = VpnClientMfaSession::<Id>::find_by_id(&self.pool, target.session_id)
            .await
            .map_err(internal("Failed to find MFA session"))?
            .filter(|session| session.token_hash == target.token_hash)
        else {
            return Ok(());
        };
        let Some(ctx) = session
            .load_context(&self.pool)
            .await
            .map_err(internal("Failed to load MFA session context"))?
        else {
            return Ok(());
        };
        self.channels.emit_event(BidiStreamEvent {
            context: BidiRequestContext::new(
                ctx.user.id,
                ctx.user.username.clone(),
                ip,
                format!("{}", ctx.device),
            ),
            event: BidiStreamEventType::DesktopClientMfa(Box::new(DesktopClientMfaEvent::Failed {
                location: ctx.location,
                device: ctx.device,
                method: VpnClientMfaMethod::Oidc.into(),
                message: format!("OpenID sign-in could not be verified: {reason}"),
            })),
        })?;
        Ok(())
    }
}
