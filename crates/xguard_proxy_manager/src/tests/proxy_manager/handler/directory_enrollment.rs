//! Remote enrollment of directory users with their directory password, over the real bidi
//! stream. The full flow runs against a real OpenLDAP server when `XGUARD_TEST_LDAP_URL` is set
//! (see `xguard_core/tests/integration/directory.rs`).

use std::sync::atomic::{AtomicU64, Ordering};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::time::timeout;
use tonic::Code;
use xguard_common::db::models::{Settings, User, settings::update_current_settings};
use xguard_core::{
    directory::{DirectoryClient, DirectoryConfig, client::UserAttributes},
    events::{BidiStreamEventType, EnrollmentEvent},
};
use xguard_proto::proxy::{
    CoreRequest, CoreResponse, DirectoryEnrollmentRequest, core_request, core_response,
};

use super::support::{
    assert_error_response, complete_proxy_handshake, make_device_info,
    send_activate_user_without_password, start_enrollment_session,
};
use crate::tests::common::{HandlerTestContext, TEST_TIMEOUT};

fn next_id() -> u64 {
    static ID: AtomicU64 = AtomicU64::new(80_000);
    ID.fetch_add(1, Ordering::Relaxed)
}

async fn send(context: &mut HandlerTestContext, username: &str, password: &str) -> CoreResponse {
    context.mock_proxy().send_request(CoreRequest {
        id: next_id(),
        device_info: Some(make_device_info()),
        payload: Some(core_request::Payload::DirectoryEnrollment(
            DirectoryEnrollmentRequest {
                username: username.into(),
                password: password.into(),
            },
        )),
    });
    context.mock_proxy_mut().recv_outbound().await
}

#[sqlx::test]
async fn test_directory_enrollment_disabled(_: PgPoolOptions, options: PgConnectOptions) {
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;
    let mut settings = Settings::get_current_settings();
    settings.ldap_enabled = false;
    settings.ldap_remote_enrollment_enabled = false;
    update_current_settings(&context.pool, settings)
        .await
        .unwrap();

    let response = send(&mut context, "jdoe", "secret").await;
    assert_eq!(assert_error_response(&response), Code::FailedPrecondition);
    context.finish().await.expect_server_finished().await;
}

#[sqlx::test]
async fn test_directory_enrollment_with_directory_password(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let Ok(url) = std::env::var("XGUARD_TEST_LDAP_URL") else {
        eprintln!("XGUARD_TEST_LDAP_URL is not set; skipping the directory enrollment test");
        return;
    };
    let mut context = HandlerTestContext::new(options).await;
    complete_proxy_handshake(&mut context).await;

    let mut settings = Settings::get_current_settings();
    settings.ldap_url = Some(url);
    settings.ldap_bind_username = Some("cn=admin,dc=example,dc=org".into());
    settings.ldap_bind_password = Some("pass123".into());
    settings.ldap_user_search_base = Some("ou=users,dc=example,dc=org".into());
    settings.ldap_user_obj_class = Some("inetOrgPerson".into());
    settings.ldap_user_auxiliary_obj_classes = Vec::new();
    settings.ldap_username_attr = Some("uid".into());
    settings.ldap_user_rdn_attr = Some("uid".into());
    settings.ldap_member_attr = Some("memberOf".into());
    settings.ldap_group_search_base = Some("ou=groups,dc=example,dc=org".into());
    settings.ldap_group_obj_class = Some("groupOfUniqueNames".into());
    settings.ldap_groupname_attr = Some("cn".into());
    settings.ldap_group_member_attr = Some("uniqueMember".into());
    settings.ldap_use_starttls = false;
    settings.ldap_uses_ad = false;
    settings.ldap_sync_groups = Vec::new();
    settings.ldap_enabled = true;
    settings.ldap_sync_enabled = false;
    settings.ldap_remote_enrollment_enabled = true;
    // The user keeps their directory password; the portal does not ask for a new one.
    settings.ldap_disable_password_management = true;
    update_current_settings(&context.pool, settings.clone())
        .await
        .unwrap();

    let config = DirectoryConfig::from_settings(&settings).unwrap();
    let mut ldap = DirectoryClient::connect(config).await.unwrap();
    if let Some(entry) = ldap.find_user("pm_dora").await.unwrap() {
        ldap.delete(&entry.dn).await.unwrap();
    }
    ldap.add_user(
        &UserAttributes {
            username: "pm_dora".into(),
            rdn: "pm_dora".into(),
            first_name: "Dora".into(),
            last_name: "Directory".into(),
            email: "pm_dora@example.org".into(),
            phone: None,
        },
        None,
        Some("DoraSecret123!"),
    )
    .await
    .unwrap();

    // A wrong password is refused without saying why.
    let response = send(&mut context, "pm_dora", "wrong").await;
    assert_eq!(assert_error_response(&response), Code::Unauthenticated);

    // The right one gives an enrollment token; the user is added on first sign-in.
    let response = send(&mut context, "pm_dora", "DoraSecret123!").await;
    let Some(core_response::Payload::DirectoryEnrollment(issued)) = response.payload else {
        panic!("expected a directory enrollment response");
    };
    let user = User::find_by_username(&context.pool, "pm_dora")
        .await
        .unwrap()
        .expect("user added on first sign-in");
    assert!(user.from_ldap);
    assert!(!user.is_enrolled());
    // The wrong attempt was for an account XGuard did not know yet: only the success is logged.
    let event = timeout(TEST_TIMEOUT, context.bidi_events_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.context.user_id, user.id);
    assert!(matches!(
        event.event,
        BidiStreamEventType::Enrollment(ref event)
            if matches!(**event, EnrollmentEvent::DirectoryEnrollmentStarted)
    ));

    // Enrollment continues with the token as usual, and finishing it marks the user enrolled.
    start_enrollment_session(&mut context, &issued.token).await;
    let _ = timeout(TEST_TIMEOUT, context.bidi_events_rx.recv()).await;
    let response = send_activate_user_without_password(&mut context, &issued.token, None).await;
    match &response.payload {
        Some(core_response::Payload::Empty(())) => {}
        Some(core_response::Payload::CoreError(err)) => {
            panic!("activation failed: {}", err.message)
        }
        _ => panic!("unexpected activation response"),
    }
    let user = User::find_by_id(&context.pool, user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(user.ldap_remote_enrollment_completed);
    assert!(user.is_enrolled());

    // Enrolled users cannot use the portal sign-in again; the refusal is logged for them.
    let response = send(&mut context, "pm_dora", "DoraSecret123!").await;
    assert_eq!(assert_error_response(&response), Code::Unauthenticated);
    loop {
        let event = timeout(TEST_TIMEOUT, context.bidi_events_rx.recv())
            .await
            .unwrap()
            .unwrap();
        if let BidiStreamEventType::Enrollment(event) = event.event
            && let EnrollmentEvent::DirectoryEnrollmentFailed { reason } = *event
        {
            assert!(reason.contains("already finished enrollment"), "{reason}");
            break;
        }
    }

    if let Some(entry) = ldap.find_user("pm_dora").await.unwrap() {
        ldap.delete(&entry.dn).await.unwrap();
    }
    ldap.close().await;
    context.finish().await.expect_server_finished().await;
}
