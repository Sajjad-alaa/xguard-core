//! Directory sync against a real OpenLDAP server.
//!
//! Runs only when `XGUARD_TEST_LDAP_URL` is set (for example `ldap://127.0.0.1:3389` with the
//! server from `docker-compose.ldap-test.yaml`). Settings are global, so run it on its own:
//! `cargo test -p xguard_core --test integration directory -- --test-threads=1`.

use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tokio::sync::mpsc::unbounded_channel;
use xguard_common::db::{
    Id,
    models::{Settings, User, group::Group, settings::update_current_settings},
    setup_pool,
};
use xguard_core::directory::{
    self, DirectoryClient, DirectoryConfig, SyncOptions,
    client::UserAttributes,
    login::{LoginOutcome, authenticate},
    push,
};

use crate::common::init_config;

fn ldap_url() -> Option<String> {
    std::env::var("XGUARD_TEST_LDAP_URL").ok()
}

async fn configure(
    pool: &PgPool,
    url: &str,
    directory_wins: bool,
    sync_group: &str,
) -> DirectoryConfig {
    let mut settings = Settings::get_current_settings();
    settings.ldap_url = Some(url.to_owned());
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
    settings.ldap_tls_verify_cert = false;
    settings.ldap_uses_ad = false;
    settings.ldap_enabled = true;
    settings.ldap_sync_enabled = true;
    settings.ldap_is_authoritative = directory_wins;
    settings.ldap_sync_account_status = false;
    settings.ldap_sync_groups = vec![sync_group.to_owned()];
    settings.ldap_sync_interval = 300;
    update_current_settings(pool, settings.clone())
        .await
        .expect("save directory settings");
    DirectoryConfig::from_settings(&settings).expect("valid directory settings")
}

fn attributes(username: &str) -> UserAttributes {
    UserAttributes {
        username: username.into(),
        rdn: username.into(),
        first_name: "Test".into(),
        last_name: username.into(),
        email: format!("{username}@example.org"),
        phone: None,
    }
}

async fn cleanup(client: &mut DirectoryClient, users: &[&str], groups: &[&str]) {
    for username in users {
        if let Ok(Some(user)) = client.find_user(username).await {
            client.delete(&user.dn).await.unwrap();
        }
    }
    for group in groups {
        let dn = client.config.group_dn(group);
        client.delete(&dn).await.unwrap();
    }
}

async fn sync(pool: &PgPool, config: &DirectoryConfig) -> directory::SyncReport {
    let (events, _events_rx) = unbounded_channel();
    let (gateway_tx, _gateway_rx) = unbounded_channel();
    let report = directory::sync::run(
        pool,
        config.clone(),
        SyncOptions::default(),
        &events,
        &gateway_tx,
    )
    .await
    .expect("sync");
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    report
}

async fn local_groups(pool: &PgPool, user: &User<Id>) -> Vec<String> {
    let mut groups = user.member_of_names(pool).await.unwrap();
    groups.sort();
    groups
}

#[sqlx::test]
async fn test_directory_sync(_: PgPoolOptions, options: PgConnectOptions) {
    let Some(url) = ldap_url() else {
        eprintln!("XGUARD_TEST_LDAP_URL is not set; skipping the directory test");
        return;
    };
    let pool = setup_pool(options).await;
    init_config(None, &pool).await;

    // --- The directory is authoritative: users and groups come into XGuard. ---
    let config = configure(&pool, &url, true, "dt_vpn").await;
    let mut client = DirectoryClient::connect(config.clone()).await.unwrap();
    cleanup(
        &mut client,
        &["dt_alice", "dt_bob", "dt_carol", "dt_carol2"],
        &["dt_vpn"],
    )
    .await;
    let alice_dn = client
        .add_user(&attributes("dt_alice"), None, Some("Secret123!"))
        .await
        .unwrap();
    let bob_dn = client
        .add_user(&attributes("dt_bob"), None, Some("Other123!"))
        .await
        .unwrap();
    let group_dn = client.create_group("dt_vpn", &alice_dn).await.unwrap();
    client.add_member(&group_dn, &bob_dn).await.unwrap();

    let (events, _events_rx) = unbounded_channel();
    let (gateway_tx, _gateway_rx) = unbounded_channel();
    let dry = directory::sync::run(
        &pool,
        config.clone(),
        SyncOptions {
            dry_run: true,
            confirm_deletions: false,
        },
        &events,
        &gateway_tx,
    )
    .await
    .unwrap();
    assert!(!dry.applied);
    assert_eq!(dry.plan.create_local, ["dt_alice", "dt_bob"]);
    assert_eq!(dry.plan.create_local_groups, ["dt_vpn"]);
    assert!(
        User::find_by_username(&pool, "dt_alice")
            .await
            .unwrap()
            .is_none()
    );

    sync(&pool, &config).await;
    let alice = User::find_by_username(&pool, "dt_alice")
        .await
        .unwrap()
        .unwrap();
    assert!(alice.from_ldap && !alice.has_password());
    assert_eq!(
        alice.ldap_user_path.as_deref(),
        Some("ou=users,dc=example,dc=org")
    );
    assert_eq!(local_groups(&pool, &alice).await, ["dt_vpn"]);
    assert_eq!(
        Settings::get_current_settings().ldap_sync_status,
        xguard_common::db::models::settings::LdapSyncStatus::InSync
    );
    // A second run has nothing to do.
    assert!(sync(&pool, &config).await.plan.is_empty());

    // Signing in checks the directory password; XGuard stores none.
    for (password, ok) in [("Secret123!", true), ("wrong", false), ("", false)] {
        let outcome = authenticate(&pool, "dt_alice", password, Some(&alice))
            .await
            .unwrap();
        assert_eq!(
            matches!(outcome, LoginOutcome::Authenticated(_)),
            ok,
            "{password}"
        );
    }
    // A local account that only shares a username is not linked and cannot use it.
    let mut impostor = alice.clone();
    impostor.from_ldap = false;
    impostor.ldap_user_path = None;
    assert!(matches!(
        authenticate(&pool, "dt_alice", "Secret123!", Some(&impostor))
            .await
            .unwrap(),
        LoginOutcome::Rejected
    ));

    // Directory changes flow in; leaving the sync group removes the XGuard account.
    let bob = client.find_user("dt_bob").await.unwrap().unwrap();
    client
        .update_user(
            &bob,
            &UserAttributes {
                email: "bob.new@example.org".into(),
                ..attributes("dt_bob")
            },
        )
        .await
        .unwrap();
    sync(&pool, &config).await;
    let bob_local = User::find_by_username(&pool, "dt_bob")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bob_local.email, "bob.new@example.org");
    // Leaving the sync group revokes the group in XGuard but keeps the account.
    client.remove_member(&group_dn, &bob_dn).await.unwrap();
    let report = sync(&pool, &config).await;
    assert_eq!(report.plan.remove_local_members.len(), 1);
    assert!(report.plan.delete_local.is_empty());
    assert!(local_groups(&pool, &bob_local).await.is_empty());
    client.add_member(&group_dn, &bob_dn).await.unwrap();
    sync(&pool, &config).await;
    assert_eq!(local_groups(&pool, &bob_local).await, ["dt_vpn"]);
    // Deleting the directory account removes the XGuard account.
    client.delete(&bob_dn).await.unwrap();
    let report = sync(&pool, &config).await;
    assert_eq!(report.plan.delete_local, ["dt_bob"]);
    assert!(
        User::find_by_username(&pool, "dt_bob")
            .await
            .unwrap()
            .is_none()
    );

    // --- XGuard is authoritative: users and groups go to the directory. ---
    let config = configure(&pool, &url, false, "dt_vpn").await;
    let mut carol = User::new(
        "dt_carol",
        Some("Start123!"),
        "Carol",
        "Test",
        "carol@example.org",
        None,
    )
    .save(&pool)
    .await
    .unwrap();
    let vpn = Group::find_by_name(&pool, "dt_vpn").await.unwrap().unwrap();
    carol.add_to_group(&pool, &vpn).await.unwrap();
    let report = sync(&pool, &config).await;
    assert_eq!(report.plan.create_remote, ["dt_carol"]);
    let remote = client.find_user("dt_carol").await.unwrap().unwrap();
    assert_eq!(remote.last_name, "Carol");
    let group = client.find_group("dt_vpn").await.unwrap().unwrap();
    assert!(
        group
            .members
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&remote.dn))
    );
    // The directory account got a random password, replaced by the real one when it is known.
    let carol_db = User::find_by_username(&pool, "dt_carol")
        .await
        .unwrap()
        .unwrap();
    assert!(carol_db.ldap_pass_randomized);
    assert!(
        !client
            .verify_password(&remote.dn, "Start123!")
            .await
            .unwrap()
    );
    push::set_password(&pool, &carol_db, "Changed123!")
        .await
        .unwrap();
    assert!(
        client
            .verify_password(&remote.dn, "Changed123!")
            .await
            .unwrap()
    );
    let carol_db = User::find_by_username(&pool, "dt_carol")
        .await
        .unwrap()
        .unwrap();
    assert!(!carol_db.ldap_pass_randomized);

    // Edits and renames are pushed.
    let (events, _events_rx) = unbounded_channel();
    carol = carol_db;
    carol.last_name = "Smith".into();
    carol.save(&pool).await.unwrap();
    push::push_user(&pool, carol.id, None, &events)
        .await
        .unwrap();
    assert_eq!(
        client
            .find_user("dt_carol")
            .await
            .unwrap()
            .unwrap()
            .last_name,
        "Smith"
    );
    carol.username = "dt_carol2".into();
    carol.save(&pool).await.unwrap();
    push::push_user(&pool, carol.id, Some("dt_carol"), &events)
        .await
        .unwrap();
    assert!(client.find_user("dt_carol").await.unwrap().is_none());
    let renamed = client.find_user("dt_carol2").await.unwrap().unwrap();
    assert!(renamed.dn.starts_with("uid=dt_carol2,"));
    assert!(
        client
            .verify_password(&renamed.dn, "Changed123!")
            .await
            .unwrap()
    );

    // XGuard as authority deletes directory accounts it does not know, within scope.
    let bob_dn = client
        .add_user(&attributes("dt_bob"), None, Some("Other123!"))
        .await
        .unwrap();
    client.add_member(&group_dn, &bob_dn).await.unwrap();
    let report = sync(&pool, &config).await;
    assert_eq!(report.plan.delete_remote, ["dt_bob"]);
    assert!(client.find_user("dt_bob").await.unwrap().is_none());

    push::delete_user("dt_carol2").await.unwrap();
    assert!(client.find_user("dt_carol2").await.unwrap().is_none());

    cleanup(&mut client, &["dt_alice"], &["dt_vpn"]).await;
    client.close().await;
}
