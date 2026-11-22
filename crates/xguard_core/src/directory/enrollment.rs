//! Secure remote enrollment of directory users. New code, AGPL-3.0.
//!
//! Users synced from the directory (LDAP / Active Directory) can enroll remotely, from the
//! enrollment portal on Edge or with the desktop client, and set up MFA there:
//!
//! - **Directory password on Edge:** [`authenticate`] checks the user's directory password
//!   (the same check as the directory sign-in, see [`super::login`]); the proxy manager then
//!   issues a fresh enrollment token and Edge starts enrollment with it.
//! - **Token in a directory attribute:** [`store_tokens`] writes a fresh enrollment token to
//!   the configured attribute, so another system (an IdM portal, a script, a mailer) can
//!   deliver it. The value keeps the old contract, JSON with `enrollmentToken` and
//!   `enrollmentUrl`. When the user finishes enrollment, [`super::push`] removes it again.
//! - **Invitations:** [`send_invites`] mails users that a sync has just added.
//!
//! An enrollment token is a credential, so it is written only over LDAPS, StartTLS or to a
//! server on this machine, never to an attribute that holds a password, the entry's identity or
//! anything the sync manages, and it expires like any other enrollment token.

use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::mpsc::UnboundedSender;
use url::Url;
use xguard_common::db::{
    Id,
    models::{
        Settings, User,
        settings::{FORBIDDEN_LDAP_ENROLLMENT_TOKEN_ATTRS, is_valid_ldap_attribute_name},
    },
};

use super::{
    DirectoryClient, DirectoryConfig, DirectoryError,
    login::{LoginOutcome, is_linked},
};
use crate::{
    auth::login_throttle::{charge_login_attempt, login_key, refund_login_attempt},
    enrollment_management::{send_enrollment_invitation, start_user_enrollment},
    error::WebError,
    events::LdapSyncEventType,
};

/// Longest username or email accepted from the enrollment portal.
const MAX_USERNAME_LEN: usize = 256;
/// Longest password accepted from the enrollment portal.
const MAX_PASSWORD_LEN: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("Remote enrollment with directory credentials is disabled")]
    Disabled,
    #[error("Invalid username or password")]
    Rejected,
    #[error("Too many failed attempts, try again later")]
    Throttled,
    #[error("The account is disabled")]
    UserDisabled,
    #[error("The account has already finished enrollment")]
    AlreadyEnrolled,
    #[error(transparent)]
    Directory(#[from] DirectoryError),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl From<WebError> for EnrollmentError {
    fn from(err: WebError) -> Self {
        match err {
            WebError::TooManyLoginAttempts => Self::Throttled,
            WebError::DbError(message) => Self::Database(sqlx::Error::Protocol(message)),
            other => Self::Database(sqlx::Error::Protocol(other.to_string())),
        }
    }
}

/// The result of a directory password check on the enrollment portal.
pub struct Authenticated {
    pub user: User<Id>,
}

/// Checks a directory user's password for remote enrollment.
///
/// - The feature must be on ([`Settings::directory_enrollment_enabled`]).
/// - Failed attempts count against the same per-account limit as web sign-ins.
/// - The account must be linked to the directory entry (see [`super::login`]), active, and not
///   yet enrolled; enrolled users add devices through the desktop client or the web UI.
///
/// `known_user` is set when the name belongs to an XGuard account, also on failure, so callers
/// can write a failed attempt to the activity log.
pub async fn authenticate(
    pool: &PgPool,
    username: &str,
    password: &str,
    known_user: &mut Option<User<Id>>,
) -> Result<Authenticated, EnrollmentError> {
    let settings = Settings::get_current_settings();
    if !settings.directory_enrollment_enabled() {
        return Err(EnrollmentError::Disabled);
    }
    let username = username.trim();
    if username.is_empty()
        || username.len() > MAX_USERNAME_LEN
        || password.is_empty()
        || password.len() > MAX_PASSWORD_LEN
    {
        return Err(EnrollmentError::Rejected);
    }

    let mut conn = pool.acquire().await?;
    let local = User::find_by_username_or_email(&mut conn, username).await?;
    known_user.clone_from(&local);
    let throttle_key = login_key(local.as_ref(), username);
    charge_login_attempt(&mut *conn, &throttle_key).await?;

    let user = match super::login::authenticate(pool, username, password, local.as_ref()).await {
        Ok(LoginOutcome::Authenticated(user)) => *user,
        Ok(LoginOutcome::Rejected) => return Err(EnrollmentError::Rejected),
        Err(err) => {
            warn!("Directory enrollment sign-in of {username} failed: {err}");
            return Err(err.into());
        }
    };
    refund_login_attempt(&mut *conn, &throttle_key).await?;
    *known_user = Some(user.clone());

    if !user.is_active {
        return Err(EnrollmentError::UserDisabled);
    }
    // Only directory accounts enroll this way; a local account linked to an entry already has
    // an XGuard password and enrolls with a token from an admin.
    if !user.from_ldap {
        return Err(EnrollmentError::Rejected);
    }
    if user.is_enrolled() {
        return Err(EnrollmentError::AlreadyEnrolled);
    }
    Ok(Authenticated { user })
}

/// The attribute enrollment tokens are written to, checked again here (the settings check it
/// when saved, but older rows were saved without the stricter rules).
pub fn token_attribute(
    settings: &Settings,
    config: &DirectoryConfig,
) -> Result<String, DirectoryError> {
    let attribute = settings
        .ldap_enrollment_token_attribute()
        .map(str::trim)
        .filter(|attribute| !attribute.is_empty())
        .ok_or(DirectoryError::NotConfigured("enrollment token attribute"))?;
    let in_use = [
        &config.username_attr,
        &config.rdn_attr,
        &config.member_attr,
        &config.group_member_attr,
    ];
    if !is_valid_ldap_attribute_name(attribute)
        || FORBIDDEN_LDAP_ENROLLMENT_TOKEN_ATTRS
            .iter()
            .any(|forbidden| forbidden.eq_ignore_ascii_case(attribute))
        || in_use
            .iter()
            .any(|used| used.eq_ignore_ascii_case(attribute))
    {
        return Err(DirectoryError::Invalid(format!(
            "attribute \"{attribute}\" cannot hold enrollment tokens"
        )));
    }
    Ok(attribute.to_owned())
}

/// What is written to the token attribute: the contract other systems read.
#[derive(Serialize)]
struct TokenValue<'a> {
    #[serde(rename = "enrollmentToken")]
    token: &'a str,
    #[serde(rename = "enrollmentUrl")]
    url: &'a str,
}

#[must_use]
pub fn token_value(token: &str, enrollment_url: &Url) -> String {
    serde_json::to_string(&TokenValue {
        token,
        url: enrollment_url.as_str(),
    })
    .unwrap_or_default()
}

/// The users whose token could not be written.
#[derive(Debug, Default)]
pub struct StoreReport {
    pub failed: Vec<(Id, String)>,
}

/// Writes each user's enrollment token to the configured attribute of their directory entry,
/// over one connection. A user whose entry is missing or not linked to the account fails
/// without stopping the rest.
///
/// Fails as a whole when the integration is off or misconfigured, the attribute is not set or
/// not allowed, or the connection is not protected (the token is a credential).
pub async fn store_tokens(
    tokens: &[(User<Id>, String)],
    enrollment_url: &Url,
) -> Result<StoreReport, DirectoryError> {
    let settings = Settings::get_current_settings();
    let config = super::enabled_config()?;
    let attribute = token_attribute(&settings, &config)?;
    if !config.is_protected() {
        return Err(DirectoryError::Insecure);
    }
    let mut client = DirectoryClient::connect(config).await?;
    let mut report = StoreReport::default();
    for (user, token) in tokens {
        let result = async {
            let Some(remote) = client.find_user(&user.username).await? else {
                return Err(DirectoryError::Refused("no directory entry".into()));
            };
            if !is_linked(user, &remote) {
                return Err(DirectoryError::Refused(
                    "the directory entry is not linked to this account".into(),
                ));
            }
            client
                .write_secret_attribute(
                    &remote.dn,
                    &attribute,
                    Some(&token_value(token, enrollment_url)),
                )
                .await
        }
        .await;
        if let Err(err) = result {
            warn!(
                "Failed to store the enrollment token of {} in the directory: {err}",
                user.username
            );
            report.failed.push((user.id, err.to_string()));
        }
    }
    client.close().await;
    Ok(report)
}

/// Removes a stored enrollment token from `username`'s entry, once it is no longer needed.
/// Does nothing when no token attribute is configured.
pub async fn clear_token(username: &str) -> Result<(), DirectoryError> {
    let settings = Settings::get_current_settings();
    if settings.ldap_enrollment_token_attribute().is_none() {
        return Ok(());
    }
    let config = super::enabled_config()?;
    let attribute = token_attribute(&settings, &config)?;
    let mut client = DirectoryClient::connect(config).await?;
    let result = async {
        if let Some(remote) = client.find_user(username).await? {
            client
                .write_secret_attribute(&remote.dn, &attribute, None)
                .await?;
        }
        Ok(())
    }
    .await;
    client.close().await;
    result
}

/// Whether invitations go out for users a sync adds.
#[must_use]
pub fn invites_enabled(settings: &Settings) -> bool {
    settings.ldap_enabled
        && settings.ldap_remote_enrollment_enabled
        && settings.ldap_remote_enrollment_send_invite
        && settings.smtp_configured()
}

/// Mails an enrollment invitation to each of `users`, newly added by a sync. Inactive users and
/// users without an email address are skipped. Tokens are created in one transaction; the mails
/// go out after it commits. Returns how many invitations were sent.
pub async fn send_invites(
    pool: &PgPool,
    users: Vec<User<Id>>,
    events: &UnboundedSender<LdapSyncEventType>,
) -> usize {
    let settings = Settings::get_current_settings();
    if !invites_enabled(&settings) || users.is_empty() {
        return 0;
    }
    match send_invites_inner(pool, &settings, users, events).await {
        Ok(sent) => sent,
        Err(err) => {
            error!("Failed to send directory enrollment invitations: {err}");
            0
        }
    }
}

async fn send_invites_inner(
    pool: &PgPool,
    settings: &Settings,
    users: Vec<User<Id>>,
    events: &UnboundedSender<LdapSyncEventType>,
) -> Result<usize, EnrollmentError> {
    let url = settings
        .proxy_public_url()
        .map_err(|err| DirectoryError::Invalid(format!("public Edge URL: {err}")))?;
    // The desktop client shows who invited the user; automatic invitations name the default
    // admin, or the first active one.
    let admin = match settings.default_admin_id {
        Some(id) => User::find_by_id(pool, id)
            .await?
            .filter(|admin| admin.is_active),
        None => None,
    };
    let admin = match admin {
        Some(admin) => admin,
        None => match User::find_admins(pool).await?.into_iter().next() {
            Some(admin) => admin,
            None => {
                warn!("No active admin found; not sending directory enrollment invitations");
                return Ok(0);
            }
        },
    };
    let timeout = settings.enrollment_token_timeout().as_secs();
    let mut issued = Vec::with_capacity(users.len());
    let mut tx = pool.begin().await?;
    for mut user in users {
        if !user.is_active || user.email.trim().is_empty() || user.is_enrolled() {
            continue;
        }
        let email = user.email.clone();
        match start_user_enrollment(
            &mut user,
            &mut tx,
            &admin,
            Some(email.clone()),
            timeout,
            url.clone(),
            false,
        )
        .await
        {
            Ok(token) => issued.push((user, email, token)),
            Err(err) => warn!(
                "Failed to create an enrollment token for {}: {err}",
                user.username
            ),
        }
    }
    tx.commit().await?;
    let sent = issued.len();
    for (user, email, token) in issued {
        send_enrollment_invitation(&token, &email, pool, url.clone()).await;
        let _ = events.send(LdapSyncEventType::EnrollmentInviteSent { user });
    }
    if sent > 0 {
        info!("Sent {sent} directory enrollment invitation(s)");
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::config::test_config;

    #[test]
    fn token_value_keeps_the_old_contract() {
        let url = Url::parse("https://edge.example.com/").unwrap();
        assert_eq!(
            token_value("abc", &url),
            r#"{"enrollmentToken":"abc","enrollmentUrl":"https://edge.example.com/"}"#
        );
    }

    #[test]
    fn token_attribute_is_checked() {
        let config = test_config();
        let mut settings = Settings::default();
        assert!(matches!(
            token_attribute(&settings, &config),
            Err(DirectoryError::NotConfigured(_))
        ));
        for bad in [
            "userPassword",
            "uid",
            "uniqueMember",
            "memberOf",
            "a b",
            "x)(y",
        ] {
            settings.ldap_enrollment_token_attr = Some(bad.into());
            assert!(token_attribute(&settings, &config).is_err(), "{bad}");
        }
        settings.ldap_enrollment_token_attr = Some(" description ".into());
        assert_eq!(token_attribute(&settings, &config).unwrap(), "description");
    }
}
