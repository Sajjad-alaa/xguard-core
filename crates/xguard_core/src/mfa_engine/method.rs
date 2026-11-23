use sqlx::PgPool;
use thiserror::Error;
use xguard_common::db::models::{
    ThrottleScope,
    biometric_auth::{BiometricAuth, BiometricAuthError, BiometricChallenge},
    user::UserError,
    vpn_client_mfa_session::{EphemeralState, MfaSessionContext},
    vpn_client_session::VpnClientMfaMethod,
};

use super::types::VerificationProof;
use crate::{
    fido2::{self, Fido2Error, IssuedChallenge},
    mail::templates::{TemplateError, mfa_code_mail},
};

/// Outcome of proof verification.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// The proof is valid; the step may advance.
    Proved,
    /// An out-of-band step has not resolved yet (OIDC consent not yet granted). Never counted
    /// against the attempt cap.
    NotYet,
    /// The proof was rejected. `message` is the audit message; the caller maps this to
    /// `unauthenticated` and records the failure.
    Failed { message: &'static str },
}

/// Credential submitted to a legacy finish operation.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum LegacyCredential {
    Code(String),
    BiometricSignature(String),
}

/// Errors produced by method verifiers shared by the legacy and multi-step contracts.
#[derive(Debug, Error)]
pub(crate) enum CommonVerifyError {
    /// A required credential is absent or has the wrong shape. `event` is the audit message to emit.
    #[error("{message}")]
    MalformedProof {
        message: &'static str,
        event: Option<&'static str>,
    },
    /// The session's ephemeral state holds no challenge for a method that requires one.
    #[error("session holds no challenge for this method")]
    MissingChallenge,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// An error surfaced by [`verify`] that is not a proof rejection.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// A required credential is absent or has the wrong shape. Maps to `invalid_argument` and skips
    /// the counter. `event` is the audit message to emit, `None` when the method does not audit this
    /// case.
    #[error("{message}")]
    MalformedProof {
        message: &'static str,
        event: Option<&'static str>,
    },
    /// The session's ephemeral state holds no challenge for a method that requires one.
    #[error("session holds no challenge for this method")]
    MissingChallenge,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("Can't build RP ID - incorrect XGuard URL")]
    MissingRPID,
    #[error("MFA method requires a contract-specific verifier")]
    UnsupportedMethod,
}

impl From<CommonVerifyError> for VerifyError {
    fn from(error: CommonVerifyError) -> Self {
        match error {
            CommonVerifyError::MalformedProof { message, event } => {
                Self::MalformedProof { message, event }
            }
            CommonVerifyError::MissingChallenge => Self::MissingChallenge,
            CommonVerifyError::Db(error) => Self::Db(error),
        }
    }
}

/// An error surfaced by [`initiate`].
#[derive(Debug, Error)]
pub enum InitiateError {
    #[error("failed to generate email MFA code")]
    EmailCode(#[from] UserError),
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("failed to send email MFA code")]
    Mail(#[from] TemplateError),
    #[error("biometric auth is not configured for this device")]
    BiometricNotConfigured,
    #[error("invalid biometric public key")]
    InvalidPublicKey(#[from] BiometricAuthError),
    #[error("MFA method is not supported")]
    UnsupportedMethod,
    #[error("Too many MFA requests. Try again later.")]
    TooManyRequests,
    /// The user has no security key enabled for VPN MFA.
    #[error("no security key is registered for VPN MFA")]
    Fido2NotConfigured,
    #[error("failed to issue a security key challenge: {0}")]
    Fido2(Fido2Error),
}

/// What [`initiate`] produced for the new attempt.
#[derive(Debug, Default)]
pub struct Initiated {
    /// Biometric and mobile-approve: the challenge to sign.
    pub signature: Option<BiometricChallenge>,
    /// FIDO2: the WebAuthn challenge and its server-side state.
    pub fido2: Option<IssuedChallenge>,
}

impl Initiated {
    /// The challenge string sent to the client, if the method has one.
    #[must_use]
    pub fn challenge(&self) -> Option<String> {
        self.fido2
            .as_ref()
            .map(|issued| issued.challenge.clone())
            .or_else(|| {
                self.signature
                    .as_ref()
                    .map(|challenge| challenge.challenge.clone())
            })
    }

    /// FIDO2 only: the credential IDs offered to the security key.
    #[must_use]
    pub fn credential_ids(&self) -> Vec<String> {
        self.fido2
            .as_ref()
            .map(|issued| issued.credential_ids.clone())
            .unwrap_or_default()
    }
}

/// Initiate a step: send the email code or mint the biometric / mobile-approve / FIDO2 challenge.
///
/// Methods that need no challenge return an empty [`Initiated`]. The caller binds the returned
/// challenge to a fresh attempt.
pub async fn initiate(
    pool: &PgPool,
    ctx: &MfaSessionContext,
    method: VpnClientMfaMethod,
) -> Result<Initiated, InitiateError> {
    if !ThrottleScope::VpnMfaInitiate
        .hit(pool, &super::throttle_key(ctx.location.id, ctx.device.id))
        .await?
    {
        return Err(InitiateError::TooManyRequests);
    }
    match method {
        VpnClientMfaMethod::Totp | VpnClientMfaMethod::Oidc | VpnClientMfaMethod::Radius => {
            Ok(Initiated::default())
        }
        VpnClientMfaMethod::Email => {
            let code = ctx.user.generate_email_mfa_code()?;
            let mut transaction = pool.begin().await?;
            mfa_code_mail(
                &ctx.user.email,
                &mut transaction,
                &ctx.user.first_name,
                &code,
                None,
                true,
            )
            .await?;
            Ok(Initiated::default())
        }
        VpnClientMfaMethod::Biometric => {
            let Some(auth) = BiometricAuth::find_by_device_id(pool, ctx.device.id).await? else {
                return Err(InitiateError::BiometricNotConfigured);
            };
            Ok(Initiated {
                signature: Some(BiometricChallenge::with_pubkey(auth.pub_key())?),
                fido2: None,
            })
        }
        VpnClientMfaMethod::MobileApprove => Ok(Initiated {
            signature: Some(BiometricChallenge::new()),
            fido2: None,
        }),
        VpnClientMfaMethod::Fido2 => match fido2::issue_challenge(pool, ctx.user.id).await {
            Ok(issued) => Ok(Initiated {
                signature: None,
                fido2: Some(issued),
            }),
            Err(Fido2Error::NotConfigured) => Err(InitiateError::Fido2NotConfigured),
            Err(Fido2Error::Db(err)) => Err(InitiateError::Database(err)),
            Err(err) => Err(InitiateError::Fido2(err)),
        },
    }
}

pub(crate) fn credential_method_mismatch() -> CommonVerifyError {
    CommonVerifyError::MalformedProof {
        message: "MFA credential does not match the selected method",
        event: None,
    }
}

fn verify_totp(ctx: &MfaSessionContext, code: Option<&str>) -> Result<Verdict, CommonVerifyError> {
    let Some(code) = code else {
        return Err(CommonVerifyError::MalformedProof {
            message: "TOTP code not provided",
            event: Some("TOTP code not provided in request"),
        });
    };
    Ok(if ctx.user.verify_totp_code(code) {
        Verdict::Proved
    } else {
        Verdict::Failed {
            message: "invalid TOTP code",
        }
    })
}

fn verify_email(ctx: &MfaSessionContext, code: Option<&str>) -> Result<Verdict, CommonVerifyError> {
    let Some(code) = code else {
        return Err(CommonVerifyError::MalformedProof {
            message: "email MFA code not provided",
            event: Some("email MFA code not provided in request"),
        });
    };
    Ok(if ctx.user.verify_email_mfa_code(code) {
        Verdict::Proved
    } else {
        Verdict::Failed {
            message: "invalid email MFA code",
        }
    })
}

fn verify_biometric(
    ephemeral: &EphemeralState,
    signature: Option<&str>,
) -> Result<Verdict, CommonVerifyError> {
    let challenge = ephemeral
        .biometric_challenge
        .as_ref()
        .ok_or(CommonVerifyError::MissingChallenge)?;
    let Some(signature) = signature else {
        return Err(CommonVerifyError::MalformedProof {
            message: "Challenge not found in request",
            event: None,
        });
    };
    Ok(match challenge.verify(signature) {
        Ok(()) => Verdict::Proved,
        Err(_) => Verdict::Failed {
            message: "Signed challenge rejected",
        },
    })
}

fn verify_oidc(ephemeral: &EphemeralState) -> Verdict {
    if ephemeral.openid_auth_completed {
        Verdict::Proved
    } else {
        Verdict::NotYet
    }
}

/// Verify a proof against the current step's selected method.
///
/// Read-only: never mutates the session. The caller owns every mutation (failure accounting,
/// advance, delete).
pub(super) async fn verify(
    _pool: &PgPool,
    ctx: &MfaSessionContext,
    ephemeral: &EphemeralState,
    proof: Option<&VerificationProof>,
) -> Result<Verdict, VerifyError> {
    match (ephemeral.selected_method, proof) {
        (VpnClientMfaMethod::Totp, Some(VerificationProof::Code(code))) => {
            verify_totp(ctx, Some(code)).map_err(Into::into)
        }
        (VpnClientMfaMethod::Totp, None) => verify_totp(ctx, None).map_err(Into::into),
        (VpnClientMfaMethod::Totp, Some(_)) => Err(credential_method_mismatch().into()),
        (VpnClientMfaMethod::Email, Some(VerificationProof::Code(code))) => {
            verify_email(ctx, Some(code)).map_err(Into::into)
        }
        (VpnClientMfaMethod::Email, None) => verify_email(ctx, None).map_err(Into::into),
        (VpnClientMfaMethod::Email, Some(_)) => Err(credential_method_mismatch().into()),
        (VpnClientMfaMethod::Biometric, Some(VerificationProof::BiometricSignature(signature))) => {
            verify_biometric(ephemeral, Some(signature)).map_err(Into::into)
        }
        (VpnClientMfaMethod::Biometric, None) => {
            verify_biometric(ephemeral, None).map_err(Into::into)
        }
        (VpnClientMfaMethod::Biometric, Some(_)) => Err(credential_method_mismatch().into()),
        (VpnClientMfaMethod::Oidc, None) => Ok(verify_oidc(ephemeral)),
        (VpnClientMfaMethod::Oidc, Some(_)) => Err(credential_method_mismatch().into()),
        // Mobile approval, FIDO2, and RADIUS have their own verifiers: they mutate challenge
        // state, and this verifier is read-only.
        (
            VpnClientMfaMethod::MobileApprove
            | VpnClientMfaMethod::Fido2
            | VpnClientMfaMethod::Radius,
            _,
        ) => Err(VerifyError::UnsupportedMethod),
    }
}

/// Verify a legacy credential using only the method selected in the persisted session.
pub(super) fn verify_legacy(
    ctx: &MfaSessionContext,
    ephemeral: &EphemeralState,
    proof: Option<&LegacyCredential>,
) -> Result<Verdict, CommonVerifyError> {
    match (ephemeral.selected_method, proof) {
        (VpnClientMfaMethod::Totp, Some(LegacyCredential::Code(code))) => {
            verify_totp(ctx, Some(code))
        }
        (VpnClientMfaMethod::Totp, None) => verify_totp(ctx, None),
        (VpnClientMfaMethod::Totp, Some(_)) => Err(credential_method_mismatch()),
        (VpnClientMfaMethod::Email, Some(LegacyCredential::Code(code))) => {
            verify_email(ctx, Some(code))
        }
        (VpnClientMfaMethod::Email, None) => verify_email(ctx, None),
        (VpnClientMfaMethod::Email, Some(_)) => Err(credential_method_mismatch()),
        (VpnClientMfaMethod::Biometric, Some(LegacyCredential::BiometricSignature(signature))) => {
            verify_biometric(ephemeral, Some(signature))
        }
        (VpnClientMfaMethod::Biometric, None) => verify_biometric(ephemeral, None),
        (VpnClientMfaMethod::Biometric, Some(_)) => Err(credential_method_mismatch()),
        (VpnClientMfaMethod::Oidc, None) => Ok(verify_oidc(ephemeral)),
        (VpnClientMfaMethod::Oidc, Some(_)) => Err(credential_method_mismatch()),
        (
            VpnClientMfaMethod::MobileApprove
            | VpnClientMfaMethod::Fido2
            | VpnClientMfaMethod::Radius,
            _,
        ) => Err(CommonVerifyError::MalformedProof {
            message: "MFA method requires a contract-specific verifier",
            event: None,
        }),
    }
}

/// Verify a signed MobileApprove challenge.
///
/// This entry point requires both signature fields and never reads the durable approval mark.
pub(super) async fn verify_mobile_signature(
    pool: &PgPool,
    ctx: &MfaSessionContext,
    ephemeral: &EphemeralState,
    signature: &str,
    auth_device_pub_key: &str,
) -> Result<Verdict, CommonVerifyError> {
    let challenge = ephemeral
        .biometric_challenge
        .as_ref()
        .ok_or(CommonVerifyError::MissingChallenge)?;
    if !BiometricAuth::verify_owner(pool, ctx.user.id, auth_device_pub_key).await? {
        // A signing device not owned by the user is indistinguishable from a wrong signature.
        return Ok(Verdict::Failed {
            message: "Signed challenge rejected",
        });
    }
    match challenge.verify_for_owner(signature, auth_device_pub_key) {
        Ok(()) => Ok(Verdict::Proved),
        Err(_) => Ok(Verdict::Failed {
            message: "Signed challenge rejected",
        }),
    }
}

/// Read the durable MobileApprove mark for the attempt-bound polling path.
#[must_use]
pub fn check_mobile_approval(ephemeral: &EphemeralState) -> Verdict {
    if ephemeral.mobile_approved {
        Verdict::Proved
    } else {
        Verdict::NotYet
    }
}
