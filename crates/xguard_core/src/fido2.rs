//! FIDO2 security keys as a VPN MFA factor.
//!
//! Server side of the ceremonies the desktop client runs with a security key:
//!
//! - **Registration** ([`start_registration`], [`finish_registration`]): a WebAuthn passkey
//!   ceremony with user verification (PIN) required. The credential is stored in the shared
//!   `webauthn` table and enabled for VPN MFA in `webauthn_vpn_mfa`.
//! - **Assertion** ([`issue_challenge`], [`verify_assertion`]): a challenge bound by the caller to
//!   one MFA attempt, answered once, within [`CHALLENGE_TTL`]. Verification is `webauthn-rs`'s:
//!   challenge, origin, RP ID hash, user presence and verification, signature against the stored
//!   key, and the signature counter (a counter that does not increase is refused as a possible
//!   clone).
//!
//! The desktop client talks CTAP2 to the key, which signs `authenticatorData || clientDataHash`.
//! The client data is not sent over the wire: both sides build the same canonical JSON with
//! [`client_data_json`] (type, the issued challenge and the Core origin), so the signature covers
//! the challenge and origin without a protocol change.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{TimeDelta, Utc};
use sqlx::{PgExecutor, PgPool};
use thiserror::Error;
use tracing::{debug, warn};
use webauthn_rs::{
    Webauthn,
    prelude::{
        Base64UrlSafeData, Passkey, PasskeyAuthentication, PasskeyRegistration,
        PublicKeyCredential, RegisterPublicKeyCredential, Uuid, WebauthnError,
    },
};
use webauthn_rs_proto::AuthenticatorAssertionResponseRaw;
use xguard_common::db::{
    Id,
    models::{
        Settings, User,
        vpn_client_mfa_session::Fido2AttemptState,
        webauthn::{VpnSecurityKey, WebAuthn},
    },
};

#[cfg(any(test, feature = "test-support"))]
pub mod test_authenticator;
#[cfg(test)]
mod tests;

/// How long an issued assertion challenge can be answered.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(120);
/// The WebAuthn limit for a credential ID.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;
/// Assertion authenticator data carries no attested credential, only extensions.
pub const MAX_AUTHENTICATOR_DATA_LEN: usize = 1024;
/// A DER ECDSA P-256 signature is at most 72 bytes; RSA-4096 is 512.
pub const MAX_SIGNATURE_LEN: usize = 512;
/// A registration response with a full attestation chain stays well below this.
pub const MAX_ATTESTATION_LEN: usize = 64 * 1024;
/// Longest security key name, in characters.
pub const MAX_KEY_NAME_LEN: usize = 64;
/// RP ID hash (32), flags (1) and signature counter (4).
const MIN_AUTHENTICATOR_DATA_LEN: usize = 37;

/// Why a FIDO2 ceremony failed.
#[derive(Debug, Error)]
pub enum Fido2Error {
    /// The user has no security key enabled for VPN MFA.
    #[error("no security key is enabled for VPN MFA")]
    NotConfigured,
    /// A field is missing, too large or has the wrong shape.
    #[error("{0}")]
    Malformed(&'static str),
    /// The key's answer was verified and refused. The message goes to the activity log.
    #[error("{0}")]
    Rejected(&'static str),
    /// The challenge outlived [`CHALLENGE_TTL`].
    #[error("security key challenge expired")]
    Expired,
    /// The XGuard URL cannot serve as a WebAuthn relying party.
    #[error("WebAuthn configuration error: {0}")]
    Config(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error("{0}")]
    Internal(String),
}

/// Which ceremony client data is for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientDataType {
    /// Registration (`webauthn.create`).
    Create,
    /// Assertion (`webauthn.get`).
    Get,
}

impl ClientDataType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "webauthn.create",
            Self::Get => "webauthn.get",
        }
    }
}

/// The canonical client data the desktop client hashes for the key.
///
/// The XGuard desktop client builds byte-for-byte the same JSON, so this must not change without
/// changing the client. Strings are JSON-escaped, although challenges are base64url and origins
/// are ASCII serializations.
#[must_use]
pub fn client_data_json(kind: ClientDataType, challenge: &str, origin: &str) -> Vec<u8> {
    let quote = |value: &str| serde_json::Value::from(value).to_string();
    format!(
        "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":false}}",
        quote(kind.as_str()),
        quote(challenge),
        quote(origin),
    )
    .into_bytes()
}

/// The WebAuthn relying party of this XGuard instance, from the current settings.
struct RelyingParty {
    webauthn: Webauthn,
    origin: String,
}

fn relying_party() -> Result<RelyingParty, Fido2Error> {
    let settings = Settings::get_current_settings();
    let webauthn = settings
        .build_webauthn()
        .map_err(|err| Fido2Error::Config(err.to_string()))?;
    let origin = url::Url::parse(&settings.xguard_url)
        .map_err(|err| Fido2Error::Config(err.to_string()))?
        .origin()
        .ascii_serialization();
    Ok(RelyingParty { webauthn, origin })
}

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// A challenge for one MFA attempt.
#[derive(Debug)]
pub struct IssuedChallenge {
    /// Sent to the client.
    pub challenge: String,
    /// Base64url IDs of the user's VPN security keys, sent to the client.
    pub credential_ids: Vec<String>,
    /// Kept server side, bound to the attempt by the caller.
    pub state: Fido2AttemptState,
}

/// Issues an assertion challenge for the user's security keys enabled for VPN MFA.
pub async fn issue_challenge<'e, E>(executor: E, user_id: Id) -> Result<IssuedChallenge, Fido2Error>
where
    E: PgExecutor<'e>,
{
    let keys = WebAuthn::vpn_keys_for_user(executor, user_id).await?;
    if keys.is_empty() {
        return Err(Fido2Error::NotConfigured);
    }
    let passkeys: Vec<Passkey> = keys.iter().map(|key| key.passkey.clone()).collect();
    let rp = relying_party()?;
    let (rcr, authentication) = rp
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|err| Fido2Error::Internal(format!("failed to start authentication: {err}")))?;
    let challenge = b64(rcr.public_key.challenge.as_slice());
    let authentication = serde_json::to_value(&authentication)
        .map_err(|err| Fido2Error::Internal(format!("failed to store the challenge: {err}")))?;
    Ok(IssuedChallenge {
        credential_ids: passkeys.iter().map(|key| b64(key.cred_id())).collect(),
        state: Fido2AttemptState {
            challenge: challenge.clone(),
            authentication,
            issued_at: Utc::now().naive_utc(),
        },
        challenge,
    })
}

/// A CTAP2 assertion as the client submits it.
#[derive(Debug, Eq, PartialEq)]
pub struct Fido2Assertion {
    /// Must equal the first 32 bytes of `authenticator_data` when present.
    pub rp_id_hash: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub credential_id: Vec<u8>,
}

impl Fido2Assertion {
    /// Checks shape and size before any cryptography.
    pub fn validate(&self) -> Result<(), Fido2Error> {
        if self.credential_id.is_empty() || self.credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            return Err(Fido2Error::Malformed("invalid security key credential ID"));
        }
        if self.authenticator_data.len() < MIN_AUTHENTICATOR_DATA_LEN
            || self.authenticator_data.len() > MAX_AUTHENTICATOR_DATA_LEN
        {
            return Err(Fido2Error::Malformed(
                "invalid security key authenticator data",
            ));
        }
        if self.signature.is_empty() || self.signature.len() > MAX_SIGNATURE_LEN {
            return Err(Fido2Error::Malformed("invalid security key signature"));
        }
        if !self.rp_id_hash.is_empty() && self.rp_id_hash != self.authenticator_data[..32] {
            return Err(Fido2Error::Malformed(
                "RP ID hash does not match the authenticator data",
            ));
        }
        Ok(())
    }
}

/// The key that answered a challenge.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedKey {
    pub id: Id,
    pub name: String,
}

fn expired(state: &Fido2AttemptState) -> bool {
    let ttl = TimeDelta::from_std(CHALLENGE_TTL).unwrap_or(TimeDelta::MAX);
    state.issued_at + ttl < Utc::now().naive_utc()
}

/// Whether the credential may be synchronized between devices (a "synced passkey").
fn backup_eligible(passkey: &Passkey) -> bool {
    serde_json::to_value(passkey)
        .ok()
        .and_then(|value| value.pointer("/cred/backup_eligible")?.as_bool())
        .unwrap_or(false)
}

/// Verifies an assertion against a challenge taken from an attempt, and records the key's new
/// signature counter.
///
/// The caller must have removed `state` from its attempt before calling, so the challenge cannot
/// be answered again whatever the outcome.
pub async fn verify_assertion(
    pool: &PgPool,
    user_id: Id,
    state: &Fido2AttemptState,
    assertion: &Fido2Assertion,
) -> Result<VerifiedKey, Fido2Error> {
    if expired(state) {
        return Err(Fido2Error::Expired);
    }
    assertion.validate()?;

    // Ownership: only the user's keys enabled for VPN MFA right now. A key removed or disabled
    // after the challenge was issued no longer counts.
    let keys = WebAuthn::vpn_keys_for_user(pool, user_id).await?;
    let Some(key) = keys
        .into_iter()
        .find(|key| key.passkey.cred_id().as_slice() == assertion.credential_id.as_slice())
    else {
        return Err(Fido2Error::Rejected(
            "Security key is not registered for VPN MFA",
        ));
    };

    let authentication: PasskeyAuthentication =
        serde_json::from_value(state.authentication.clone()).map_err(|err| {
            Fido2Error::Internal(format!("failed to read the stored challenge: {err}"))
        })?;
    let rp = relying_party()?;
    let credential = PublicKeyCredential {
        id: b64(&assertion.credential_id),
        raw_id: Base64UrlSafeData::from(assertion.credential_id.clone()),
        response: AuthenticatorAssertionResponseRaw {
            authenticator_data: Base64UrlSafeData::from(assertion.authenticator_data.clone()),
            client_data_json: Base64UrlSafeData::from(client_data_json(
                ClientDataType::Get,
                &state.challenge,
                &rp.origin,
            )),
            signature: Base64UrlSafeData::from(assertion.signature.clone()),
            user_handle: None,
        },
        extensions: Default::default(),
        type_: "public-key".to_owned(),
    };
    let result = match rp
        .webauthn
        .finish_passkey_authentication(&credential, &authentication)
    {
        Ok(result) => result,
        Err(WebauthnError::CredentialPossibleCompromise) => {
            warn!(
                "Security key {} of user {user_id} did not increase its signature counter; it may \
                 be cloned",
                key.id
            );
            return Err(Fido2Error::Rejected(
                "Possible cloned security key: the signature counter did not increase",
            ));
        }
        Err(err) => {
            debug!("Security key assertion of user {user_id} rejected: {err}");
            return Err(Fido2Error::Rejected("Security key assertion rejected"));
        }
    };
    if result.backup_eligible() {
        return Err(Fido2Error::Rejected(
            "Synced passkeys cannot be used for VPN MFA",
        ));
    }

    let VpnSecurityKey {
        id,
        name,
        mut passkey,
        stored,
    } = key;
    let changed = passkey.update_credential(&result) == Some(true);
    if !WebAuthn::record_vpn_use(pool, id, &stored, changed.then_some(&passkey)).await? {
        // Another sign-in with this key stored a newer state meanwhile: the same signature
        // counter was presented twice.
        warn!("Security key {id} of user {user_id} was used by two sign-ins at once");
        return Err(Fido2Error::Rejected(
            "Security key was used by two sign-ins at once",
        ));
    }
    Ok(VerifiedKey { id, name })
}

/// Validates a security key name: trimmed, 1 to [`MAX_KEY_NAME_LEN`] characters, no control
/// characters.
pub fn validate_key_name(name: &str) -> Result<String, Fido2Error> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_KEY_NAME_LEN
        || name.chars().any(char::is_control)
    {
        return Err(Fido2Error::Malformed(
            "security key name must have 1 to 64 printable characters",
        ));
    }
    Ok(name.to_owned())
}

/// Starts registering a security key for VPN MFA. Returns the WebAuthn creation options (JSON,
/// sent to the client) and the ceremony state (CBOR, kept server side).
///
/// User verification is required, so the key must have a PIN. Keys already enabled for VPN MFA
/// are excluded, so the same key is not registered twice.
pub async fn start_registration(
    pool: &PgPool,
    user: &User<Id>,
) -> Result<(String, Vec<u8>), Fido2Error> {
    let exclude = WebAuthn::vpn_keys_for_user(pool, user.id)
        .await?
        .into_iter()
        .map(|key| key.passkey.cred_id().clone())
        .collect();
    let rp = relying_party()?;
    let display_name = format!("{} {}", user.first_name, user.last_name);
    let (ccr, registration) = rp
        .webauthn
        .start_passkey_registration(
            Uuid::new_v4(),
            &user.username,
            display_name.trim(),
            Some(exclude),
        )
        .map_err(|err| Fido2Error::Internal(format!("failed to start registration: {err}")))?;
    let ccr = serde_json::to_string(&ccr)
        .map_err(|err| Fido2Error::Internal(format!("failed to encode the challenge: {err}")))?;
    let state = serde_cbor::to_vec(&registration)
        .map_err(|err| Fido2Error::Internal(format!("failed to store the challenge: {err}")))?;
    Ok((ccr, state))
}

/// Finishes a registration started with [`start_registration`].
pub fn finish_registration(state: &[u8], attestation: &str) -> Result<Passkey, Fido2Error> {
    if attestation.len() > MAX_ATTESTATION_LEN {
        return Err(Fido2Error::Malformed("security key response is too large"));
    }
    let registration: PasskeyRegistration = serde_cbor::from_slice(state)
        .map_err(|_| Fido2Error::Malformed("no security key registration in progress"))?;
    let credential: RegisterPublicKeyCredential = serde_json::from_str(attestation)
        .map_err(|_| Fido2Error::Malformed("malformed security key response"))?;
    let rp = relying_party()?;
    let passkey = rp
        .webauthn
        .finish_passkey_registration(&credential, &registration)
        .map_err(|err| {
            debug!("Security key registration rejected: {err}");
            Fido2Error::Rejected("Security key registration rejected")
        })?;
    if backup_eligible(&passkey) {
        return Err(Fido2Error::Rejected(
            "Synced passkeys cannot be used for VPN MFA; use a hardware security key",
        ));
    }
    Ok(passkey)
}
