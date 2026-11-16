//! Sign-in with an external OpenID Connect provider (Google, Microsoft, Okta, Keycloak, …).
//! New code, AGPL-3.0.
//!
//! - [`provider`]: the provider settings (one at a time).
//! - [`flow`]: the authorization code flow with PKCE and full ID token verification.
//! - [`resolve_user`]: which XGuard account the verified identity belongs to.
//!
//! Account linking is deliberately strict:
//! - An identity is linked by its subject identifier.
//! - An account is linked by email only when the provider says the email is verified, and only
//!   if the account is not already linked to another identity.
//! - New accounts are created only when the "create accounts" setting is on.
//! - XGuard's own MFA still applies after an external sign-in.

pub mod flow;
pub mod provider;
#[cfg(test)]
mod tests;

use sqlx::PgPool;
use xguard_common::db::{
    Id,
    models::{Settings, User},
};

use self::flow::Identity;
use crate::handlers::user::{MAX_USERNAME_CHARS, check_username};

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error(
        "No XGuard account matches this identity, and new accounts are not created automatically"
    )]
    NoAccount,
    #[error(
        "The provider did not confirm this email address, so it cannot be linked to an account"
    )]
    UnverifiedEmail,
    #[error("This XGuard account is already linked to another identity")]
    LinkedElsewhere,
    #[error("The provider did not give an email address, which a new account needs")]
    NoEmail,
    #[error("No free username could be derived from this identity")]
    NoUsername,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// Compares secrets without leaking where they differ through timing.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A username from `source`: lowercase, only letters, digits, `.`, `-` and `_`, starting with a
/// letter or digit.
fn username_base(source: &str) -> Option<String> {
    let local = source.split('@').next().unwrap_or_default();
    let cleaned: String = local
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
    let mut base: String = trimmed.chars().take(MAX_USERNAME_CHARS - 5).collect();
    while base.ends_with(['.', '-', '_']) {
        base.pop();
    }
    (!base.is_empty()).then_some(base)
}

async fn free_username(pool: &PgPool, identity: &Identity) -> Result<String, LinkError> {
    let base = identity
        .preferred_username
        .as_deref()
        .and_then(username_base)
        .or_else(|| identity.email.as_deref().and_then(username_base))
        .ok_or(LinkError::NoUsername)?;
    for n in 0..100 {
        let candidate = if n == 0 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        if check_username(&candidate).is_ok()
            && User::find_by_username(pool, &candidate).await?.is_none()
        {
            return Ok(candidate);
        }
    }
    Err(LinkError::NoUsername)
}

/// Finds, links or creates the XGuard account for a verified identity.
pub async fn resolve_user(pool: &PgPool, identity: &Identity) -> Result<User<Id>, LinkError> {
    let linked: Option<Id> = sqlx::query_scalar(r#"SELECT id FROM "user" WHERE openid_sub = $1"#)
        .bind(&identity.subject)
        .fetch_optional(pool)
        .await?;
    if let Some(id) = linked
        && let Some(user) = User::find_by_id(pool, id).await?
    {
        return Ok(user);
    }

    if let Some(email) = identity.email.as_deref()
        && let Some(mut user) = User::find_by_email(pool, email).await?
    {
        if !identity.email_verified {
            return Err(LinkError::UnverifiedEmail);
        }
        if user.openid_sub.is_some() {
            return Err(LinkError::LinkedElsewhere);
        }
        user.openid_sub = Some(identity.subject.clone());
        user.save(pool).await?;
        info!("Linked {} to their OpenID identity", user.username);
        return Ok(user);
    }

    if !Settings::get_current_settings().openid_create_account {
        return Err(LinkError::NoAccount);
    }
    let email = identity.email.clone().ok_or(LinkError::NoEmail)?;
    if !identity.email_verified {
        return Err(LinkError::UnverifiedEmail);
    }
    let username = free_username(pool, identity).await?;
    let mut user = User::new(
        username.clone(),
        None,
        identity
            .last_name
            .clone()
            .unwrap_or_else(|| username.clone()),
        identity.first_name.clone().unwrap_or_default(),
        email,
        identity.phone.clone(),
    );
    user.openid_sub = Some(identity.subject.clone());
    let user = user.save(pool).await?;
    info!("Added {} through OpenID sign-in", user.username);
    Ok(user)
}
