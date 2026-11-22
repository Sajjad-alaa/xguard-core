use reqwest::Url;
use sqlx::{PgConnection, PgExecutor, PgPool};
use xguard_common::db::{Id, models::user::User};

use crate::{
    db::models::enrollment::{ENROLLMENT_TOKEN_TYPE, Token, TokenError},
    mail::templates::{desktop_start_mail, new_account_mail},
};

/// Start user enrollment process
/// This creates a new enrollment token valid for the duration specified by `token_timeout_seconds`
/// and optionally sends enrollment email notification to user
pub async fn start_user_enrollment(
    user: &mut User<Id>,
    conn: &mut PgConnection,
    admin: &User<Id>,
    email: Option<String>,
    token_timeout_seconds: u64,
    enrollment_service_url: Url,
    send_user_notification: bool,
) -> Result<String, TokenError> {
    start_user_enrollment_inner(
        user,
        conn,
        Some(admin),
        email,
        token_timeout_seconds,
        enrollment_service_url,
        send_user_notification,
    )
    .await
}

/// Start user enrollment without stamping an admin override onto the token.
pub async fn start_directory_user_enrollment(
    user: &mut User<Id>,
    conn: &mut PgConnection,
    email: Option<String>,
    token_timeout_seconds: u64,
    enrollment_service_url: Url,
) -> Result<String, TokenError> {
    start_user_enrollment_inner(
        user,
        conn,
        None,
        email,
        token_timeout_seconds,
        enrollment_service_url,
        false,
    )
    .await
}

async fn start_user_enrollment_inner(
    user: &mut User<Id>,
    conn: &mut PgConnection,
    admin: Option<&User<Id>>,
    email: Option<String>,
    token_timeout_seconds: u64,
    enrollment_service_url: Url,
    send_user_notification: bool,
) -> Result<String, TokenError> {
    if let Some(admin) = admin {
        info!("User {admin} started a new enrollment process for user {user}.");
    } else {
        info!("System started a new enrollment process for user {user}.");
    }
    debug!("Notify user by mail about the enrollment process: {send_user_notification}");
    debug!("Verify that {user} is an active user.");
    if !user.is_active {
        warn!("Can't create enrollment token for disabled user {user}");
        return Err(TokenError::UserDisabled);
    }

    clear_unused_enrollment_tokens(user, &mut *conn).await?;

    debug!("Create a new enrollment token for user {user}.");
    let enrollment = Token::new(
        user.id,
        admin.map(|admin| admin.id),
        email.clone(),
        token_timeout_seconds,
        Some(ENROLLMENT_TOKEN_TYPE.to_owned()),
    );
    debug!("Saving a new enrollment token for user {user}");
    enrollment.save(&mut *conn).await?;
    debug!("Saved a new enrollment token for user {user}.");

    // Mark the user with enrollment-pending flag.
    // https://github.com/Sajjad-alaa/xguard-client/issues/647
    user.enrollment_pending = true;
    user.save(&mut *conn).await?;

    if send_user_notification && let Some(email) = email {
        debug!("Sending an enrollment mail for user {user} to {email}.");
        let base_message_context = enrollment.get_welcome_message_context(&mut *conn).await?;
        let result = new_account_mail(
            &email,
            conn,
            base_message_context,
            enrollment_service_url,
            &enrollment.id,
            enrollment.validity_duration(),
        )
        .await;
        match result {
            Ok(()) => {
                info!("Sent enrollment start mail for user {user} to {email}");
            }
            Err(err) => {
                error!("Error sending mail: {err}");
            }
        }
    }
    info!("New enrollment token has been generated for {user}.");

    Ok(enrollment.id)
}

/// Start user remote desktop configuration process
/// This creates a new enrollment token valid for 24h
/// and optionally sends email notification to user
pub async fn start_desktop_configuration(
    user: &User<Id>,
    conn: &mut PgConnection,
    admin: &User<Id>,
    email: Option<String>,
    token_timeout_seconds: u64,
    enrollment_service_url: Url,
    send_user_notification: bool,
    // Whether to attach some device to the token. It allows for a partial initialization of
    // the device before the desktop configuration has taken place.
    device_id: Option<Id>,
) -> Result<String, TokenError> {
    info!(
        "User {} starting a new desktop activation for user {}",
        admin.username, user.username
    );
    debug!(
        "Notify {} by mail about the enrollment process: {}",
        user.username, send_user_notification
    );

    debug!("Verify that {} is an active user.", user.username);
    if !user.is_active {
        warn!(
            "Can't create desktop activation token for disabled user {}.",
            user.username
        );
        return Err(TokenError::UserDisabled);
    }

    clear_unused_enrollment_tokens(user, &mut *conn).await?;
    debug!("Cleared unused tokens for {}.", user.username);

    debug!(
        "Create a new desktop activation token for user {}.",
        user.username
    );
    let mut desktop_configuration = Token::new(
        user.id,
        Some(admin.id),
        email.clone(),
        token_timeout_seconds,
        Some(ENROLLMENT_TOKEN_TYPE.to_owned()),
    );
    if let Some(device_id) = device_id {
        desktop_configuration.device_id = Some(device_id);
    }
    debug!("Saving a new desktop configuration token...");
    desktop_configuration.save(&mut *conn).await?;
    debug!(
        "Saved a new desktop activation token for user {}.",
        user.username
    );

    if send_user_notification && let Some(email) = email {
        debug!(
            "Sending a desktop configuration mail for user {} to {email}",
            user.username
        );
        let base_message_context = desktop_configuration
            .get_welcome_message_context(&mut *conn)
            .await?;
        let result = desktop_start_mail(
            &email,
            conn,
            base_message_context,
            &enrollment_service_url,
            &desktop_configuration.id,
        )
        .await;
        if let Err(err) = result {
            debug!(
                "Cannot send an email to the user {} due to the error {err}.",
                user.username,
            );
        }
    }
    info!(
        "New desktop activation token has been generated for {}.",
        user.username
    );

    Ok(desktop_configuration.id)
}

/// Send an enrollment invitation email for a token that has already been committed to the DB.
/// Returns `true` if delivery succeeded; errors are logged without exposing the token ID.
pub async fn send_enrollment_invitation(
    token_id: &str,
    email: &str,
    pool: &PgPool,
    enrollment_service_url: Url,
) -> bool {
    let token = match Token::find_by_id(pool, token_id).await {
        Ok(t) => t,
        Err(err) => {
            error!("Failed to fetch enrollment token for notification: {err}");
            return false;
        }
    };
    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(err) => {
            error!("Failed to acquire DB connection for enrollment notification: {err}");
            return false;
        }
    };
    let base_message_context = match token.get_welcome_message_context(&mut conn).await {
        Ok(ctx) => ctx,
        Err(err) => {
            error!("Failed to build enrollment message context: {err}");
            return false;
        }
    };
    match new_account_mail(
        email,
        &mut conn,
        base_message_context,
        enrollment_service_url,
        token_id,
        token.validity_duration(),
    )
    .await
    {
        Ok(()) => {
            info!("Sent enrollment invitation to {email}");
            true
        }
        Err(err) => {
            error!("Failed to send enrollment invitation to {email}: {err}");
            false
        }
    }
}

// Remove unused tokens when triggering user enrollment
pub async fn clear_unused_enrollment_tokens<'e, E: PgExecutor<'e>>(
    user: &User<Id>,
    executor: E,
) -> Result<(), TokenError> {
    info!("Removing unused tokens for user {}.", user.username);
    Token::delete_unused_user_tokens(executor, user.id).await
}
