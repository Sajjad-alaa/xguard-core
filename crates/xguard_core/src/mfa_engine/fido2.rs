//! The FIDO2 step of a VPN MFA login.
//!
//! The challenge is issued with the attempt (see [`super::method::initiate`]) and stored on it.
//! [`MfaEngine::verify_fido2`] removes it from the attempt before verifying, so each challenge
//! is answered at most once, by the attempt it was issued for, within
//! [`crate::fido2::CHALLENGE_TTL`].

use tracing::{error, info};
use xguard_common::db::{
    Id,
    models::vpn_client_mfa_session::{MfaSessionContext, VpnClientMfaSession},
};

use super::{MfaEngine, method::Verdict};
use crate::fido2::{self, Fido2Assertion, Fido2Error};

/// Why a FIDO2 proof could not be judged.
#[derive(Debug)]
pub(super) enum Fido2StepError {
    /// The assertion has the wrong shape; nothing was consumed.
    Malformed(&'static str),
    /// No challenge is pending for the attempt: already answered, expired or never issued.
    NoChallenge,
    Internal,
}

impl MfaEngine {
    /// Verifies a FIDO2 assertion for the attempt `attempt_id` of `session`.
    pub(super) async fn verify_fido2(
        &self,
        session: &VpnClientMfaSession<Id>,
        ctx: &MfaSessionContext,
        attempt_id: &str,
        assertion: &Fido2Assertion,
    ) -> Result<Verdict, Fido2StepError> {
        // Shape first, so a malformed request does not use the challenge up.
        if let Err(err) = assertion.validate() {
            return Err(match err {
                Fido2Error::Malformed(message) => Fido2StepError::Malformed(message),
                _ => Fido2StepError::Internal,
            });
        }
        let mut conn = self.pool.acquire().await.map_err(|err| {
            error!("Failed to acquire a connection: {err}");
            Fido2StepError::Internal
        })?;
        let Some(state) = session
            .take_fido2_state(&mut conn, attempt_id)
            .await
            .map_err(|err| {
                error!("Failed to take the FIDO2 challenge: {err}");
                Fido2StepError::Internal
            })?
        else {
            return Err(Fido2StepError::NoChallenge);
        };
        drop(conn);

        match fido2::verify_assertion(&self.pool, ctx.user.id, &state, assertion).await {
            Ok(key) => {
                info!(
                    "User {} answered FIDO2 MFA with security key \"{}\" for device {} at \
                     location {}",
                    ctx.user.username, key.name, ctx.device.name, ctx.location.name
                );
                Ok(Verdict::Proved)
            }
            Err(Fido2Error::Expired) => Err(Fido2StepError::NoChallenge),
            Err(Fido2Error::Rejected(message)) => Ok(Verdict::Failed { message }),
            Err(Fido2Error::NotConfigured) => Ok(Verdict::Failed {
                message: "Security key is not registered for VPN MFA",
            }),
            Err(Fido2Error::Malformed(message)) => Err(Fido2StepError::Malformed(message)),
            Err(err) => {
                error!("Failed to verify a FIDO2 assertion: {err}");
                Err(Fido2StepError::Internal)
            }
        }
    }
}
