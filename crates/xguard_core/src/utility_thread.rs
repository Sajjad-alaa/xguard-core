use std::time::Duration;

use chrono::{NaiveDateTime, TimeDelta, Utc};
use sqlx::{PgConnection, PgPool};
use tokio::{
    sync::{broadcast, mpsc},
    time::{Instant, sleep},
};
use tracing::Instrument;
use xguard_common::{
    db::models::{
        Certificates, CoreCertSource, ProxyCertSource, User, throttle, vpn_client_mfa_session,
    },
    types::proxy::ProxyControlMessage,
};

use crate::{
    cert_settings::{refresh_core_self_signed_cert, refresh_proxy_self_signed_cert},
    grpc::GatewayCommand,
    letsencrypt::do_letsencrypt_refresh,
    mail::templates,
    updates::do_new_version_check,
};

// Times in seconds
const UTILITY_THREAD_MAIN_SLEEP_TIME: Duration = Duration::from_secs(5);
const UPDATES_CHECK_INTERVAL: u64 = 60 * 60 * 6;
const EXPIRED_ROWS_REAP_INTERVAL: u64 = 60 * 5;
const LETSENCRYPT_EXPIRY_CHECK_INTERVAL: u64 = 60 * 60 * 24;
const CERTIFICATE_EXPIRY_CHECK_INTERVAL: u64 = 60 * 60 * 24; // 1 day
const SELF_SIGNED_REFRESH_THRESHOLD: TimeDelta = TimeDelta::days(14);

#[instrument(skip_all)]
pub async fn run_utility_thread(
    pool: &PgPool,
    _gateway_tx: mpsc::UnboundedSender<GatewayCommand>,
    proxy_control_tx: mpsc::Sender<ProxyControlMessage>,
    web_reload_tx: broadcast::Sender<()>,
) -> Result<(), anyhow::Error> {
    let mut last_updates_check = Instant::now();
    let mut last_letsencrypt_expiry_check = Instant::now();
    let mut last_certificate_check = Instant::now();
    let mut last_expired_rows_reap = Instant::now();

    let updates_check_task = || async {
        if let Err(e) = do_new_version_check()
            .instrument(info_span!("updates_check_task"))
            .await
        {
            error!("There was an error while checking for new XGuard version: {e:?}");
        }
    };

    let expired_rows_reap_task = || async {
        if let Err(err) = vpn_client_mfa_session::reap_expired(pool)
            .instrument(info_span!("mfa_session_reap_task"))
            .await
        {
            error!("Failed to reap expired MFA sessions: {err}");
        }
        if let Err(err) = throttle::reap_expired(pool)
            .instrument(info_span!("throttle_reap_task"))
            .await
        {
            error!("Failed to reap expired throttle windows: {err}");
        }
    };

    let letsencrypt_refresh_task = || async {
        if let Err(e) = do_letsencrypt_refresh(pool, proxy_control_tx.clone())
            .instrument(info_span!("letsencrypt_refresh_task"))
            .await
        {
            error!("There was an error while performing letsencrypt refresh task: {e}");
        }
    };

    updates_check_task().await;
    expired_rows_reap_task().await;
    letsencrypt_refresh_task().await;
    check_certificates(pool, &proxy_control_tx, &web_reload_tx).await;

    loop {
        sleep(UTILITY_THREAD_MAIN_SLEEP_TIME).await;

        // Check for new XGuard version
        if last_updates_check.elapsed().as_secs() >= UPDATES_CHECK_INTERVAL {
            updates_check_task().await;
            last_updates_check = Instant::now();
        }

        // Reap expired in-progress MFA sessions and throttle windows
        if last_expired_rows_reap.elapsed().as_secs() >= EXPIRED_ROWS_REAP_INTERVAL {
            expired_rows_reap_task().await;
            last_expired_rows_reap = Instant::now();
        }

        // Check LE cert expiry dates and refresh if necessary
        if last_letsencrypt_expiry_check.elapsed().as_secs() >= LETSENCRYPT_EXPIRY_CHECK_INTERVAL {
            letsencrypt_refresh_task().await;
            last_letsencrypt_expiry_check = Instant::now();
        }

        // Check certificates.
        if last_certificate_check.elapsed().as_secs() >= CERTIFICATE_EXPIRY_CHECK_INTERVAL {
            check_certificates(pool, &proxy_control_tx, &web_reload_tx)
                .instrument(info_span!("check_certificates"))
                .await;
            last_certificate_check = Instant::now();
        }
    }
}

/// Check if certificate is about to expire, or got expired. Send mail accordingly.
async fn expiry_check(conn: &mut PgConnection, certificate_type: &str, expiry: NaiveDateTime) {
    const TIME_CHECK: &[TimeDelta] = &[
        TimeDelta::days(-14),
        TimeDelta::days(-7),
        TimeDelta::days(-3),
        TimeDelta::days(-1),
        TimeDelta::days(0),
    ];

    let now = Utc::now().naive_utc();
    let time_delta = now - expiry;
    for check in TIME_CHECK {
        if check.num_days() == time_delta.num_days() {
            // Send email to admins.
            if time_delta.num_days() >= 0 {
                debug!("Certificate {certificate_type} has expired; notifying admins");
            } else {
                debug!("Certificate {certificate_type} is about to expire; notifying admins");
            }
            let Ok(admin_users) = User::find_admins(&mut *conn).await else {
                error!("Failed to fetch admins from database");
                return;
            };
            for user in admin_users {
                let _ = if time_delta.num_days() >= 0 {
                    templates::certificate_expired_mail(
                        &user.email,
                        &mut *conn,
                        certificate_type,
                        expiry,
                    )
                    .await
                } else {
                    templates::certificate_expiration_mail(
                        &user.email,
                        &mut *conn,
                        certificate_type,
                        expiry,
                    )
                    .await
                };
            }
        }
    }
}

/// Check if any of the certificates are about to expire, or got expired.
async fn check_certificates(
    pool: &PgPool,
    proxy_control_tx: &mpsc::Sender<ProxyControlMessage>,
    web_reload_tx: &broadcast::Sender<()>,
) {
    let cert = match Certificates::get(pool).await {
        Ok(Some(cert)) => cert,
        Ok(None) => {
            debug!("No certificates in the database");
            return;
        }
        Err(err) => {
            error!("Failed to fetch certificates: {err}");
            return;
        }
    };

    let Ok(mut conn) = pool.begin().await else {
        error!("Failed to create database transaction");
        return;
    };

    // Email notifications for custom uploaded certs
    if let ProxyCertSource::Custom = cert.proxy_http_cert_source
        && let Some(proxy_http_cert_expiry) = cert.proxy_http_cert_expiry
    {
        expiry_check(&mut conn, "Edge HTTPS", proxy_http_cert_expiry).await;
    }

    if let CoreCertSource::Custom = cert.core_http_cert_source
        && let Some(core_http_cert_expiry) = cert.core_http_cert_expiry
    {
        expiry_check(&mut conn, "Core HTTPS", core_http_cert_expiry).await;
    }

    // Auto-refresh self-signed certs when close to expiry
    let now = Utc::now().naive_utc();

    if let CoreCertSource::SelfSigned = cert.core_http_cert_source
        && let Some(expiry) = cert.core_http_cert_expiry
    {
        let expire_in = expiry - now;
        if expire_in <= SELF_SIGNED_REFRESH_THRESHOLD {
            info!(
                "Core self-signed HTTPS certificate expires in {} days, refreshing",
                expire_in.num_days()
            );
            match refresh_core_self_signed_cert(pool).await {
                Ok((_, _, new_expiry)) => {
                    info!("Core self-signed HTTPS certificate refreshed, new expiry: {new_expiry}");
                    if let Err(err) = web_reload_tx.send(()) {
                        error!("Failed to trigger core web server reload: {err}");
                    }
                }
                Err(err) => {
                    error!("Failed to refresh Core self-signed HTTPS certificate: {err}");
                }
            }
        }
    }

    if let ProxyCertSource::SelfSigned = cert.proxy_http_cert_source
        && let Some(expiry) = cert.proxy_http_cert_expiry
    {
        let expire_in = expiry - now;
        if expire_in <= SELF_SIGNED_REFRESH_THRESHOLD {
            info!(
                "Proxy self-signed HTTPS certificate expires in {} days, refreshing",
                expire_in.num_days()
            );
            match refresh_proxy_self_signed_cert(pool).await {
                Ok((cert_pem, key_pem, new_expiry)) => {
                    info!(
                        "Proxy self-signed HTTPS certificate refreshed, new expiry: {new_expiry}"
                    );
                    if let Err(err) = proxy_control_tx
                        .send(ProxyControlMessage::BroadcastHttpsCerts { cert_pem, key_pem })
                        .await
                    {
                        error!("Failed to broadcast refreshed proxy HTTPS cert to proxies: {err}");
                    }
                }
                Err(err) => {
                    error!("Failed to refresh Proxy self-signed HTTPS certificate: {err}");
                }
            }
        }
    }
}
