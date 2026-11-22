//! Directory sync tests: the API clients against mock directories that speak the real
//! protocols, the planner's rules, the settings checks, and full runs against the database.

pub(crate) mod mocks;

use std::{collections::BTreeSet, time::Duration};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::sync::mpsc::unbounded_channel;
use url::Url;
use xguard_common::db::{
    Id,
    models::{User, group::Group, settings::initialize_current_settings},
    setup_pool,
};

use self::mocks::{Fixture, Mock, Status};
use super::{
    Credentials, DirSyncError, DirectoryApi, DirectoryGroup, DirectorySnapshot, DirectoryUser,
    Pattern, Patterns, SyncConfig,
    google::GoogleCredentials,
    jumpcloud::JumpCloudCredentials,
    microsoft::MicrosoftCredentials,
    okta::OktaCredentials,
    plan::{LocalGroup, LocalUser, plan},
    settings::{DirectorySyncInput, DirectorySyncSecrets, MissingUserAction, SyncTarget, rsa_der},
    sync::{SyncOptions, load_local, run},
};
use crate::{
    events::DirectorySyncEventType,
    sso::provider::{ProviderConfig, ProviderInput, ProviderKind},
};

fn url(base: &str, path: &str) -> Url {
    Url::parse(&format!("{base}{path}")).unwrap()
}

fn config(kind: ProviderKind, credentials: Credentials) -> SyncConfig {
    SyncConfig {
        provider_id: 0,
        provider_name: format!("{kind:?}"),
        kind,
        enabled: true,
        interval: Duration::from_secs(600),
        target: SyncTarget::All,
        user_behavior: MissingUserAction::Keep,
        admin_behavior: MissingUserAction::Keep,
        prefetch_users: false,
        group_match: Patterns::default(),
        user_groups: Patterns::default(),
        credentials,
    }
}

fn google(mock: &Mock) -> SyncConfig {
    config(
        ProviderKind::Google,
        Credentials::Google(GoogleCredentials {
            service_account_email: mocks::GOOGLE_SERVICE_ACCOUNT.into(),
            private_key: rsa_der(&mocks::test_key()).unwrap(),
            admin_email: mocks::GOOGLE_ADMIN.into(),
            token_url: url(&mock.base, "/token"),
            api_base: url(&mock.base, "/admin/directory/v1/"),
        }),
    )
}

fn microsoft(mock: &Mock, secret: &str) -> SyncConfig {
    config(
        ProviderKind::Microsoft,
        Credentials::Microsoft(MicrosoftCredentials {
            tenant: mocks::MS_TENANT.into(),
            client_id: mocks::MS_CLIENT_ID.into(),
            client_secret: secret.into(),
            login_base: url(&mock.base, "/"),
            graph_base: url(&mock.base, "/v1.0/"),
        }),
    )
}

fn okta(mock: &Mock) -> SyncConfig {
    config(
        ProviderKind::Okta,
        Credentials::Okta(OktaCredentials {
            base: url(&mock.base, "/"),
            client_id: mocks::OKTA_CLIENT_ID.into(),
            private_key: rsa_der(&mocks::test_key()).unwrap(),
            key_id: Some(mocks::OKTA_KEY_ID.into()),
        }),
    )
}

fn jumpcloud(mock: &Mock, key: &str) -> SyncConfig {
    config(
        ProviderKind::JumpCloud,
        Credentials::JumpCloud(JumpCloudCredentials {
            api_key: key.into(),
            base: url(&mock.base, "/"),
        }),
    )
}

/// Five users (one suspended, one deprovisioned) in three groups.
fn fixture() -> Fixture {
    Fixture::default()
        .user("u1", "alice@example.org", Status::Active)
        .user("u2", "bob@example.org", Status::Suspended)
        .user("u3", "carol@example.org", Status::Active)
        .user("u4", "dave@example.org", Status::Deprovisioned)
        .user("u5", "erin@example.org", Status::Active)
        .group("g1", "Engineering", &["u1", "u2", "u3"])
        .group("g2", "Sales", &["u5"])
        .group("g3", "Support", &["u3", "u5"])
}

fn assert_snapshot(snapshot: &DirectorySnapshot) {
    let mut ids: Vec<&str> = snapshot.users.iter().map(|u| u.id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, ["u1", "u2", "u3", "u4", "u5"]);
    let active: BTreeSet<&str> = snapshot
        .users
        .iter()
        .filter(|u| u.active)
        .map(|u| u.id.as_str())
        .collect();
    assert_eq!(active, BTreeSet::from(["u1", "u3", "u5"]));
    let alice = snapshot.users.iter().find(|u| u.id == "u1").unwrap();
    assert_eq!(alice.email.as_deref(), Some("alice@example.org"));
    assert_eq!(alice.first_name.as_deref(), Some("First alice"));
    assert_eq!(snapshot.total_groups, 3);
    let engineering = snapshot
        .groups
        .iter()
        .find(|g| g.name == "Engineering")
        .unwrap();
    // Nested group entries are left out; paging gathered everyone.
    assert_eq!(engineering.members, ["u1", "u2", "u3"]);
}

fn other_key() -> Vec<u8> {
    let other = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
    rsa_der(&other).unwrap()
}

#[tokio::test]
async fn test_google_workspace_api() {
    let mock = mocks::start(fixture()).await;
    let config = google(&mock);
    let api = DirectoryApi::connect(&config).await.unwrap();
    assert_snapshot(&api.snapshot(&config).await.unwrap());
    assert!(mock.requested("google members g1 derived=true"));

    // The service account may only act for the admin it is delegated to.
    let mut wrong = google(&mock);
    if let Credentials::Google(credentials) = &mut wrong.credentials {
        credentials.admin_email = "someone@example.org".into();
    }
    assert!(matches!(
        DirectoryApi::connect(&wrong).await,
        Err(DirSyncError::Auth(message)) if message.contains("unauthorized")
    ));
    // A key the service account does not have is refused.
    let mut forged = google(&mock);
    if let Credentials::Google(credentials) = &mut forged.credentials {
        credentials.private_key = other_key();
    }
    assert!(matches!(
        DirectoryApi::connect(&forged).await,
        Err(DirSyncError::Auth(_))
    ));
}

#[tokio::test]
async fn test_microsoft_graph_api() {
    let mock = mocks::start(fixture()).await;
    let config = microsoft(&mock, mocks::MS_CLIENT_SECRET);
    let api = DirectoryApi::connect(&config).await.unwrap();
    assert_snapshot(&api.snapshot(&config).await.unwrap());

    // Paging links to another host are not followed (the token would go with them).
    mock.evil_links
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let err = api.users().await.unwrap_err();
    assert!(err.to_string().contains("attacker.example"), "{err}");
    mock.evil_links
        .store(false, std::sync::atomic::Ordering::SeqCst);

    assert!(matches!(
        DirectoryApi::connect(&microsoft(&mock, "wrong")).await,
        Err(DirSyncError::Auth(message)) if message.contains("AADSTS7000215")
    ));
}

#[tokio::test]
async fn test_okta_api() {
    let mock = mocks::start(fixture()).await;
    let config = okta(&mock);
    let api = DirectoryApi::connect(&config).await.unwrap();
    // The deprovisioned user comes from the second, filtered listing.
    assert_snapshot(&api.snapshot(&config).await.unwrap());

    mock.evil_links
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(api.groups().await.is_err());
    mock.evil_links
        .store(false, std::sync::atomic::Ordering::SeqCst);

    let mut forged = okta(&mock);
    if let Credentials::Okta(credentials) = &mut forged.credentials {
        credentials.private_key = other_key();
    }
    assert!(matches!(
        DirectoryApi::connect(&forged).await,
        Err(DirSyncError::Auth(_))
    ));
}

#[tokio::test]
async fn test_jumpcloud_api() {
    let mut fixture = fixture();
    // More than one page of 100.
    let mut many = Vec::new();
    for n in 0..150 {
        fixture = fixture.user(
            &format!("x{n:03}"),
            &format!("x{n}@example.org"),
            Status::Active,
        );
        many.push(format!("x{n:03}"));
    }
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let fixture = fixture.group("g4", "Everyone", &many);
    let mock = mocks::start(fixture).await;
    let config = jumpcloud(&mock, mocks::JUMPCLOUD_KEY);
    let api = DirectoryApi::connect(&config).await.unwrap();
    let snapshot = api.snapshot(&config).await.unwrap();
    assert_eq!(snapshot.users.len(), 155);
    assert_eq!(snapshot.groups.len(), 4);
    let everyone = snapshot.groups.iter().find(|g| g.id == "g4").unwrap();
    assert_eq!(everyone.members.len(), 150);
    let bob = snapshot.users.iter().find(|u| u.id == "u2").unwrap();
    assert!(!bob.active);

    assert!(matches!(
        DirectoryApi::connect(&jumpcloud(&mock, "wrong")).await,
        Err(DirSyncError::Auth(_))
    ));
}

#[test]
fn wildcard_patterns() {
    let pattern = Pattern::new("VPN-*");
    assert!(pattern.matches("vpn-users"));
    assert!(pattern.matches("VPN-"));
    assert!(!pattern.matches("all-vpn-users"));
    assert!(Pattern::new("*admin*").matches("Domain Admins"));
    assert!(Pattern::new("team-?").matches("Team-A"));
    assert!(!Pattern::new("team-?").matches("team-ab"));
    assert!(Pattern::new("a*b*c").matches("aXbYbZc"));
    assert!(!Pattern::new("a*b*c").matches("aXbYbZ"));
    assert!(Pattern::new("Engineering").matches("engineering"));
    assert!(!Pattern::new("Engineering").matches("engineering-2"));
}

// The planner

fn local(id: Id, username: &str, groups: &[&str]) -> LocalUser {
    LocalUser {
        id,
        username: username.into(),
        email: format!("{username}@example.org"),
        first_name: format!("First {username}"),
        last_name: format!("Last {username}"),
        is_active: true,
        is_admin: groups.contains(&"admin"),
        openid_sub: None,
        external_id: None,
        sync_disabled: false,
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
    }
}

fn remote(id: &str, username: &str, active: bool) -> DirectoryUser {
    DirectoryUser {
        id: id.into(),
        email: Some(format!("{username}@example.org")),
        first_name: Some(format!("First {username}")),
        last_name: Some(format!("Last {username}")),
        phone: None,
        active,
    }
}

fn snapshot(users: Vec<DirectoryUser>, groups: &[(&str, &[&str])]) -> DirectorySnapshot {
    DirectorySnapshot {
        users,
        groups: groups
            .iter()
            .enumerate()
            .map(|(n, (name, members))| DirectoryGroup {
                id: format!("g{n}"),
                name: (*name).into(),
                members: members.iter().map(|m| (*m).to_owned()).collect(),
            })
            .collect(),
        total_groups: groups.len(),
    }
}

fn groups(names: &[(&str, bool)]) -> Vec<LocalGroup> {
    names
        .iter()
        .map(|(name, is_admin)| LocalGroup {
            name: (*name).into(),
            is_admin: *is_admin,
        })
        .collect()
}

fn offline(kind: ProviderKind) -> SyncConfig {
    config(
        kind,
        Credentials::JumpCloud(JumpCloudCredentials {
            api_key: String::new(),
            base: url("http://127.0.0.1", "/"),
        }),
    )
}

fn names<T>(items: &[T], name: impl Fn(&T) -> &str) -> Vec<String> {
    items.iter().map(|item| name(item).to_owned()).collect()
}

#[test]
fn matching_links_accounts_strictly() {
    let mut by_id = local(1, "alice", &[]);
    by_id.external_id = Some("d1".into());
    by_id.email = "old-alice@example.org".into();
    let mut by_subject = local(2, "bob", &[]);
    by_subject.openid_sub = Some("d2".into());
    by_subject.email = "robert@example.org".into();
    let by_email = local(3, "carol", &[]);
    // Signed in as someone else who still exists in the directory.
    let mut taken = local(4, "dave", &[]);
    taken.openid_sub = Some("d1".into());
    let twin_a = local(5, "erin", &[]);
    let mut twin_b = local(6, "erin2", &[]);
    twin_b.email = "ERIN@example.org".into();
    let users = vec![by_id, by_subject, by_email, taken, twin_a, twin_b];
    let directory = snapshot(
        vec![
            remote("d1", "alice", true),
            remote("d2", "bob", true),
            remote("d3", "carol", true),
            remote("d4", "dave", true),
            remote("d5", "erin", true),
        ],
        &[],
    );

    let result = plan(&offline(ProviderKind::Google), &users, &[], &directory);
    let links: Vec<(String, String)> = result
        .link_users
        .iter()
        .map(|l| (l.username.clone(), l.external_id.clone()))
        .collect();
    assert_eq!(
        links,
        [
            ("bob".to_owned(), "d2".to_owned()),
            ("carol".to_owned(), "d3".to_owned())
        ]
    );
    assert_eq!(result.stats.matched_users, 3);
    assert!(
        result
            .skipped
            .iter()
            .any(|s| s.contains("dave is linked to another"))
    );
    assert!(
        result
            .skipped
            .iter()
            .any(|s| s.contains("several XGuard accounts"))
    );
    // The directory is the source of truth for the profile of linked accounts.
    assert_eq!(
        names(&result.update_users, |u| &u.username),
        ["alice", "bob"]
    );
    assert_eq!(result.update_users[0].email, "alice@example.org");

    // Microsoft subjects are not directory ids: bob is matched by email only, which differs.
    let result = plan(&offline(ProviderKind::Microsoft), &users, &[], &directory);
    assert!(!result.link_users.iter().any(|l| l.username == "bob"));
}

#[test]
fn account_status_follows_the_directory() {
    let mut disabled_by_sync = local(1, "alice", &[]);
    disabled_by_sync.is_active = false;
    disabled_by_sync.sync_disabled = true;
    let mut disabled_by_admin = local(2, "bob", &[]);
    disabled_by_admin.is_active = false;
    let suspended = local(3, "carol", &[]);
    let admin = local(4, "dave", &["admin"]);
    let other_admin = local(5, "erin", &["admin"]);
    let mut users = vec![
        disabled_by_sync,
        disabled_by_admin,
        suspended,
        admin,
        other_admin,
    ];
    for user in &mut users {
        user.external_id = Some(format!("d{}", user.id));
    }
    let directory = snapshot(
        vec![
            remote("d1", "alice", true),
            remote("d2", "bob", true),
            remote("d3", "carol", false),
            remote("d4", "dave", false),
            remote("d5", "erin", true),
        ],
        &[],
    );
    let admin_groups = groups(&[("admin", true)]);
    let mut config = offline(ProviderKind::Okta);
    let result = plan(&config, &users, &admin_groups, &directory);
    assert_eq!(names(&result.enable_users, |c| &c.username), ["alice"]);
    // Admins are kept by default, and admin-disabled accounts stay disabled.
    assert_eq!(names(&result.disable_users, |c| &c.username), ["carol"]);
    assert!(
        result
            .skipped
            .iter()
            .any(|s| s.contains("dave: disabled in the directory, but admins are kept"))
    );
    assert!(result.skipped.iter().any(|s| s.contains(
        "bob: active in the directory, but disabled in XGuard by an admin"
    )));

    config.admin_behavior = MissingUserAction::Disable;
    let result = plan(&config, &users, &admin_groups, &directory);
    assert_eq!(
        names(&result.disable_users, |c| &c.username),
        ["carol", "dave"]
    );

    // The last active admin stays.
    users[4].is_active = false;
    let result = plan(&config, &users, &admin_groups, &directory);
    assert_eq!(names(&result.disable_users, |c| &c.username), ["carol"]);
    assert!(
        result
            .skipped
            .iter()
            .any(|s| s
                .contains("dave: disabled in the directory, but this is the last active admin"))
    );
}

#[test]
fn missing_accounts_follow_the_behavior() {
    let mut users: Vec<LocalUser> = (1..=4)
        .map(|n| {
            let mut user = local(n, &format!("user{n}"), &[]);
            user.external_id = Some(format!("d{n}"));
            user
        })
        .collect();
    let mut admin = local(10, "boss", &["admin"]);
    admin.openid_sub = Some("gone".into());
    users.push(admin);
    let mut second_admin = local(11, "deputy", &["admin"]);
    second_admin.external_id = Some("d11".into());
    users.push(second_admin);
    // Created in XGuard and never linked: always left alone.
    users.push(local(20, "local", &[]));
    let directory = snapshot(
        vec![remote("d1", "user1", true), remote("d2", "user2", true)],
        &[("VPN", &["d1"])],
    );
    let admin_groups = groups(&[("admin", true)]);
    let mut config = offline(ProviderKind::Okta);
    config.target = SyncTarget::Users;

    let result = plan(&config, &users, &admin_groups, &directory);
    assert!(result.disable_users.is_empty() && result.delete_users.is_empty());

    config.user_behavior = MissingUserAction::Disable;
    let result = plan(&config, &users, &admin_groups, &directory);
    assert_eq!(
        names(&result.disable_users, |c| &c.username),
        ["user3", "user4"]
    );
    assert!(result.disable_users.iter().all(|c| c.missing));

    config.user_behavior = MissingUserAction::Delete;
    config.admin_behavior = MissingUserAction::Delete;
    let result = plan(&config, &users, &admin_groups, &directory);
    // Both admins are missing; only one of them goes, the other is the last active admin.
    assert_eq!(
        names(&result.delete_users, |c| &c.username),
        ["boss", "user3", "user4"]
    );
    assert!(result.skipped.iter().any(|s| {
        s.contains("deputy: missing from the directory, but this is the last active admin")
    }));

    // Only members of the user groups are in scope: user2 now counts as missing.
    config.user_groups = Patterns::new(&["vpn".into()]);
    config.admin_behavior = MissingUserAction::Keep;
    let result = plan(&config, &users, &admin_groups, &directory);
    assert_eq!(
        names(&result.delete_users, |c| &c.username),
        ["user2", "user3", "user4"]
    );
    assert_eq!(result.delete_users[0].reason, "outside the user groups");
    assert_eq!(result.stats.directory_users_in_scope, 1);
}

#[test]
fn mass_revocations_need_confirmation() {
    let users: Vec<LocalUser> = (1..=10)
        .map(|n| {
            let mut user = local(n, &format!("user{n}"), &[]);
            user.external_id = Some(format!("d{n}"));
            user
        })
        .collect();
    let mut config = offline(ProviderKind::Okta);
    config.user_behavior = MissingUserAction::Disable;
    let directory = |count: usize| {
        snapshot(
            (1..=count)
                .map(|n| remote(&format!("d{n}"), &format!("user{n}"), true))
                .collect(),
            &[],
        )
    };

    // Three of ten missing: fine.
    let result = plan(&config, &users, &[], &directory(7));
    assert_eq!(result.revocations(), 3);
    assert!(result.check_revocations(false).is_ok());

    // Six of ten: refused unless confirmed.
    let result = plan(&config, &users, &[], &directory(4));
    assert!(result.check_revocations(false).is_err());
    assert!(result.check_revocations(true).is_ok());

    // An empty directory read never revokes anything without confirmation.
    let result = plan(&config, &users[..2], &[], &directory(0));
    assert_eq!(result.revocations(), 2);
    assert!(
        result
            .check_revocations(false)
            .unwrap_err()
            .contains("no users in scope")
    );
}

#[test]
fn group_membership_follows_the_filter() {
    let mut alice = local(1, "alice", &["Engineering", "Local team"]);
    alice.external_id = Some("d1".into());
    let mut bob = local(2, "bob", &["admin", "Sales"]);
    bob.external_id = Some("d2".into());
    let mut carol = local(3, "carol", &["admin"]);
    carol.external_id = Some("d3".into());
    let users = vec![alice, bob, carol];
    let local_groups = groups(&[
        ("Engineering", false),
        ("Local team", false),
        ("Sales", false),
        ("admin", true),
    ]);
    let directory = snapshot(
        vec![
            remote("d1", "alice", true),
            remote("d2", "bob", true),
            remote("d3", "carol", true),
        ],
        &[
            ("engineering", &["d2"]),
            ("Sales", &["d1", "d2"]),
            ("Marketing", &["d1"]),
            ("admin", &["d1"]),
            ("Bad <name>", &["d1"]),
        ],
    );
    let mut config = offline(ProviderKind::Okta);
    let result = plan(&config, &users, &local_groups, &directory);
    let pairs = |m: &[super::plan::Membership]| -> Vec<String> {
        m.iter()
            .map(|m| format!("{}:{}", m.username, m.group))
            .collect()
    };
    // Names match ignoring case; the XGuard spelling is kept. "Local team" has no directory
    // counterpart and keeps its members. The admin group is skipped with an empty filter.
    assert_eq!(
        pairs(&result.add_members),
        ["alice:Marketing", "alice:Sales", "bob:Engineering"]
    );
    assert_eq!(pairs(&result.remove_members), ["alice:Engineering"]);
    assert_eq!(result.create_groups, ["Marketing"]);
    assert!(
        result
            .skipped
            .iter()
            .any(|s| s.contains("group admin: an XGuard admin group"))
    );
    assert!(
        result
            .skipped
            .iter()
            .any(|s| s.contains("group Bad <name>"))
    );
    assert_eq!(result.stats.synced_groups, 3);

    // Named in the filter, the admin group is synced: bob and carol would both lose it, but the
    // last active admin keeps it.
    config.group_match = Patterns::new(&["admin".into(), "sales".into()]);
    let result = plan(&config, &users, &local_groups, &directory);
    assert_eq!(pairs(&result.add_members), ["alice:admin", "alice:Sales"]);
    assert_eq!(pairs(&result.remove_members), ["bob:admin", "carol:admin"]);
    // With nobody joining it, the last active admin stays in the admin group.
    let mut lone = users.clone();
    lone[1].groups.remove("admin");
    lone[1].is_admin = false;
    let no_admins = snapshot(
        vec![
            remote("d1", "alice", true),
            remote("d2", "bob", true),
            remote("d3", "carol", true),
        ],
        &[("Sales", &["d1", "d2"]), ("admin", &[])],
    );
    let result = plan(&config, &lone, &local_groups, &no_admins);
    assert!(result.remove_members.is_empty());
    assert!(
        result
            .skipped
            .iter()
            .any(|s| s.contains("carol: not removed from admin group admin"))
    );

    // Users only: no membership changes.
    config.target = SyncTarget::Users;
    let result = plan(&config, &users, &local_groups, &directory);
    assert!(result.add_members.is_empty() && result.remove_members.is_empty());
}

#[test]
fn prefetch_creates_accounts() {
    let existing = local(1, "alice", &[]);
    let directory = snapshot(
        vec![
            remote("d1", "alice", true),
            remote("d2", "Alice", true),
            remote("d3", "frank", false),
            DirectoryUser {
                email: None,
                ..remote("d4", "nobody", true)
            },
            remote("d5", "grace", true),
        ],
        &[("Engineering", &["d5"])],
    );
    let mut config = offline(ProviderKind::Okta);
    config.prefetch_users = true;
    let result = plan(&config, &[existing], &[], &directory);
    // d2 shares alice's email (case differs), so neither is linked nor created; frank is
    // disabled; d4 has no email.
    assert_eq!(names(&result.create_users, |u| &u.username), ["grace"]);
    assert_eq!(result.create_users[0].external_id, "d5");
    assert!(result.link_users.is_empty());
    assert_eq!(result.create_groups, ["Engineering"]);
    assert_eq!(result.add_members[0].username, "grace");
    assert!(result.add_members[0].user_id.is_none());

    // A taken username gets a suffix.
    let mut grace = local(2, "grace", &[]);
    grace.email = "grace.local@example.org".into();
    let result = plan(&config, &[grace], &[], &directory);
    assert!(names(&result.create_users, |u| &u.username).contains(&"grace-1".to_owned()));
}

// Settings

#[test]
fn settings_are_checked() {
    let stored = DirectorySyncSecrets {
        google_service_account_key: Some("stored".into()),
        okta_private_jwk: Some("stored".into()),
        jumpcloud_api_key: Some("stored".into()),
    };
    let input = |enabled: bool| DirectorySyncInput {
        directory_sync_enabled: enabled,
        ..DirectorySyncInput::default()
    };

    let issuer = "https://accounts.google.com";
    let key = serde_json::json!({
        "type": "service_account",
        "client_email": "sync@project.iam.gserviceaccount.com",
        "private_key": mocks::TEST_KEY_PEM,
    })
    .to_string();
    let (settings, secrets) = DirectorySyncInput {
        admin_email: Some(" admin@example.org ".into()),
        google_service_account_key: Some(key),
        directory_sync_group_match: vec![" vpn-* ".into(), "VPN-*".into(), String::new()],
        ..input(true)
    }
    .validate(ProviderKind::Google, issuer, &stored)
    .unwrap();
    assert_eq!(settings.admin_email.as_deref(), Some("admin@example.org"));
    assert_eq!(
        settings.google_service_account_email.as_deref(),
        Some("sync@project.iam.gserviceaccount.com")
    );
    assert!(settings.google_service_account_key_set);
    assert_eq!(settings.directory_sync_group_match, ["vpn-*"]);
    // Secrets of other providers are dropped; none is ever serialized.
    assert!(secrets.okta_private_jwk.is_none() && secrets.jumpcloud_api_key.is_none());
    let json = serde_json::to_string(&settings).unwrap();
    assert!(!json.contains("PRIVATE KEY"));

    // Left out, the stored secret is kept.
    let (_, secrets) = DirectorySyncInput {
        okta_dirsync_client_id: Some("sync".into()),
        ..input(true)
    }
    .validate(ProviderKind::Okta, "https://example.okta.com", &stored)
    .unwrap();
    assert_eq!(secrets.okta_private_jwk.as_deref(), Some("stored"));
    // A new one must be a valid RSA private JWK.
    assert!(
        DirectorySyncInput {
            okta_private_jwk: Some(r#"{"kty":"EC"}"#.into()),
            ..input(false)
        }
        .validate(ProviderKind::Okta, "https://example.okta.com", &stored)
        .is_err()
    );
    let (settings, _) = DirectorySyncInput {
        okta_dirsync_client_id: Some("sync".into()),
        okta_private_jwk: Some(mocks::okta_jwk()),
        ..input(true)
    }
    .validate(
        ProviderKind::Okta,
        "https://example.okta.com",
        &DirectorySyncSecrets::default(),
    )
    .unwrap();
    assert!(settings.okta_private_jwk_set);

    let fails = |input: DirectorySyncInput, kind, issuer: &str| {
        input
            .validate(kind, issuer, &DirectorySyncSecrets::default())
            .is_err()
    };
    let okta_issuer = "https://example.okta.com";
    assert!(fails(
        DirectorySyncInput {
            directory_sync_interval: Some(59),
            ..input(false)
        },
        ProviderKind::Okta,
        okta_issuer
    ));
    assert!(fails(
        input(true),
        ProviderKind::Custom,
        "https://idp.example.org"
    ));
    assert!(fails(
        input(true),
        ProviderKind::JumpCloud,
        "https://oauth.id.jumpcloud.com"
    ));
    assert!(fails(
        input(true),
        ProviderKind::Microsoft,
        "https://login.microsoftonline.com/common/v2.0"
    ));
    assert!(!fails(
        input(true),
        ProviderKind::Microsoft,
        "https://login.microsoftonline.com/0b6c4f31-4d4b-4bd1-8f4b-0c5b2bcd1d0a/v2.0"
    ));
    assert!(fails(
        DirectorySyncInput {
            admin_email: Some("not an email".into()),
            ..input(false)
        },
        ProviderKind::Google,
        issuer
    ));
    assert!(fails(
        DirectorySyncInput {
            directory_sync_user_groups: (0..101).map(|n| format!("g{n}")).collect(),
            ..input(false)
        },
        ProviderKind::Okta,
        okta_issuer
    ));
}

fn okta_input(issuer: &str, enabled: bool) -> ProviderInput {
    ProviderInput {
        kind: ProviderKind::Okta,
        issuer: issuer.into(),
        client_id: "sign-in".into(),
        client_secret: Some("secret".into()),
        enabled: true,
        display_name: None,
        disable_password_management: false,
        directory_sync: DirectorySyncInput {
            directory_sync_enabled: enabled,
            okta_dirsync_client_id: Some(mocks::OKTA_CLIENT_ID.into()),
            okta_private_jwk: Some(mocks::okta_jwk()),
            directory_sync_user_behavior: MissingUserAction::Disable,
            ..DirectorySyncInput::default()
        },
    }
}

#[sqlx::test]
async fn test_provider_keeps_its_id(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let mut conn = pool.acquire().await.unwrap();
    let first = ProviderConfig::save(&mut conn, okta_input("https://example.okta.com", true))
        .await
        .unwrap();
    assert!(first.directory_sync.okta_private_jwk_set);
    let user = User::new("jdoe", None, "Doe", "Jane", "jane@example.org", None)
        .save(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO user_directory_identity (user_id, provider_id, external_id) \
         VALUES ($1, $2, 'x')",
    )
    .bind(user.id)
    .bind(first.id)
    .execute(&pool)
    .await
    .unwrap();
    let count = "SELECT count(*) FROM user_directory_identity";

    // Saving again (secrets left out) updates the row in place and keeps the identities.
    let mut input = okta_input("https://example.okta.com", true);
    input.client_secret = None;
    input.directory_sync.okta_private_jwk = None;
    let second = ProviderConfig::save(&mut conn, input).await.unwrap();
    assert_eq!(second.id, first.id);
    let identities: i64 = sqlx::query_scalar(count).fetch_one(&pool).await.unwrap();
    assert_eq!(identities, 1);
    let stored = ProviderConfig::current(&pool).await.unwrap().unwrap();
    assert_eq!(
        stored.directory_secrets.okta_private_jwk,
        Some(mocks::okta_jwk())
    );
    assert_eq!(
        stored.provider.directory_sync.directory_sync_user_behavior,
        MissingUserAction::Disable
    );

    // Another directory: its ids mean nothing here.
    ProviderConfig::save(&mut conn, okta_input("https://other.okta.com", true))
        .await
        .unwrap();
    let identities: i64 = sqlx::query_scalar(count).fetch_one(&pool).await.unwrap();
    assert_eq!(identities, 0);
}

async fn find(pool: &sqlx::PgPool, username: &str) -> User<Id> {
    User::find_by_username(pool, username)
        .await
        .unwrap()
        .unwrap()
}

/// A full run against the mock Okta and the database.
#[sqlx::test]
#[allow(clippy::too_many_lines)]
async fn test_sync_runs(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    initialize_current_settings(&pool).await.unwrap();
    let mock = mocks::start(fixture()).await;
    let mut conn = pool.acquire().await.unwrap();
    let mut input = okta_input(&mock.base, true);
    input.directory_sync.prefetch_users = true;
    let provider = ProviderConfig::save(&mut conn, input).await.unwrap();
    drop(conn);
    let stored = ProviderConfig::current(&pool).await.unwrap().unwrap();
    let config = SyncConfig::from_provider(&stored).unwrap();
    assert_eq!(config.provider_id, provider.id);

    // XGuard has an admin, alice (to be linked by email), bob (enabled; suspended in Okta) and
    // a local-only account.
    let admin_group = Group::find_by_name(&pool, "admin").await.unwrap().unwrap();
    let admin = User::new(
        "admin",
        Some("Pass123!"),
        "Admin",
        "Ad",
        "admin@xguard.local",
        None,
    )
    .save(&pool)
    .await
    .unwrap();
    admin.add_to_group(&pool, &admin_group).await.unwrap();
    for (username, email) in [
        ("alice", "ALICE@example.org"),
        ("bob", "bob@example.org"),
        ("local", "local@xguard.local"),
    ] {
        User::new(username, None, "Last", "First", email, None)
            .save(&pool)
            .await
            .unwrap();
    }

    let (events, mut events_rx) = unbounded_channel();
    let (gateway_tx, _gateway_rx) = unbounded_channel();
    let dry = SyncOptions {
        dry_run: true,
        confirm_revocations: false,
    };
    let report = run(&pool, &config, dry, &events, &gateway_tx)
        .await
        .unwrap();
    assert!(!report.applied);
    assert!(events_rx.try_recv().is_err());
    let preview = serde_json::to_value(&report.plan).unwrap();

    let report = run(&pool, &config, SyncOptions::default(), &events, &gateway_tx)
        .await
        .unwrap();
    assert!(report.applied);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    // The dry run showed exactly what the real run did.
    assert_eq!(preview, serde_json::to_value(&report.plan).unwrap());
    assert_eq!(
        names(&report.plan.link_users, |l| &l.username),
        ["alice", "bob"]
    );
    assert_eq!(names(&report.plan.disable_users, |c| &c.username), ["bob"]);
    // carol and erin are new; dave is deprovisioned.
    assert_eq!(
        names(&report.plan.create_users, |u| &u.username),
        ["carol", "erin"]
    );

    assert!(!find(&pool, "bob").await.is_active);
    assert!(find(&pool, "local").await.is_active);
    let carol = find(&pool, "carol").await;
    assert!(!carol.has_password());
    assert_eq!(carol.first_name, "First carol");
    let mut carol_groups = carol.member_of_names(&pool).await.unwrap();
    carol_groups.sort();
    assert_eq!(carol_groups, ["Engineering", "Support"]);
    let alice = find(&pool, "alice").await;
    // The directory's spelling of the email wins.
    assert_eq!(alice.email, "alice@example.org");
    assert_eq!(alice.member_of_names(&pool).await.unwrap(), ["Engineering"]);
    let (local_users, _) = load_local(&pool, Some(provider.id)).await.unwrap();
    let linked: BTreeSet<(String, String)> = local_users
        .iter()
        .filter_map(|u| u.external_id.clone().map(|id| (u.username.clone(), id)))
        .collect();
    let expected: BTreeSet<(String, String)> = [
        ("alice", "u1"),
        ("bob", "u2"),
        ("carol", "u3"),
        ("erin", "u5"),
    ]
    .into_iter()
    .map(|(u, id)| (u.to_owned(), id.to_owned()))
    .collect();
    assert_eq!(linked, expected);

    let mut kinds = Vec::new();
    while let Ok(event) = events_rx.try_recv() {
        assert_eq!(event.provider, "Okta");
        kinds.push(match event.event {
            DirectorySyncEventType::UserCreated { user } => format!("created {}", user.username),
            DirectorySyncEventType::UserModified { after, .. } => {
                format!("modified {}", after.username)
            }
            DirectorySyncEventType::UserDisabled { user } => {
                format!("disabled {}", user.username)
            }
            DirectorySyncEventType::GroupCreated { group } => format!("group {}", group.name),
            DirectorySyncEventType::GroupMemberAdded { group, user } => {
                format!("{} joined {}", user.username, group.name)
            }
            other => format!("{other:?}"),
        });
    }
    for expected in [
        "created carol",
        "disabled bob",
        "group Engineering",
        "alice joined Engineering",
        "erin joined Sales",
    ] {
        assert!(
            kinds.iter().any(|k| k == expected),
            "{expected} in {kinds:?}"
        );
    }

    // A second run has nothing left to do.
    let report = run(&pool, &config, SyncOptions::default(), &events, &gateway_tx)
        .await
        .unwrap();
    assert!(report.plan.is_empty(), "{:?}", report.plan);

    // Okta reactivates bob and moves alice to Sales; carol leaves the directory.
    mock.set(
        Fixture::default()
            .user("u1", "alice@example.org", Status::Active)
            .user("u2", "bob@example.org", Status::Active)
            .user("u5", "erin@example.org", Status::Active)
            .group("g1", "Engineering", &["u2"])
            .group("g2", "Sales", &["u1", "u5"])
            .group("g3", "Support", &["u5"]),
    );
    let report = run(&pool, &config, SyncOptions::default(), &events, &gateway_tx)
        .await
        .unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(find(&pool, "bob").await.is_active);
    assert!(!find(&pool, "carol").await.is_active);
    assert!(find(&pool, "local").await.is_active);
    assert!(find(&pool, "admin").await.is_active);
    assert_eq!(
        find(&pool, "alice")
            .await
            .member_of_names(&pool)
            .await
            .unwrap(),
        ["Sales"]
    );

    // The directory read comes back empty: nothing is revoked without confirmation.
    mock.set(Fixture::default());
    let err = run(&pool, &config, SyncOptions::default(), &events, &gateway_tx)
        .await
        .unwrap_err();
    assert!(matches!(err, DirSyncError::Refused(_)), "{err}");
    assert!(find(&pool, "bob").await.is_active);
    assert!(!super::sync::last_run().unwrap().success);
}

#[test]
fn jumpcloud_regions() {
    use super::jumpcloud::api_base_for;
    assert_eq!(
        api_base_for("https://oauth.id.jumpcloud.com/"),
        "https://console.jumpcloud.com/"
    );
    assert_eq!(
        api_base_for("https://oauth.eu.id.jumpcloud.com/"),
        "https://console.eu.jumpcloud.com/"
    );
    assert_eq!(
        api_base_for("https://oauth.in.id.jumpcloud.com/"),
        "https://console.in.jumpcloud.com/"
    );
}

#[test]
fn does_not_relink_deleted_external_id_or_touch_out_of_scope_unlinked() {
    let mut previously_linked = local(1, "alice", &[]);
    previously_linked.external_id = Some("old-id".into());
    previously_linked.email = "alice@example.org".into();

    let mut out_of_scope_local = local(2, "localbob", &[]);
    out_of_scope_local.email = "bob@example.org".into();

    let users = vec![previously_linked, out_of_scope_local];
    let mut cfg = offline(ProviderKind::Okta);
    cfg.user_groups = crate::dirsync::Patterns::new(&["Engineering".into()]);
    cfg.user_behavior = MissingUserAction::Disable;

    let directory = DirectorySnapshot {
        users: vec![
            remote("new-id-reused-email", "alice", true),
            remote("out-of-scope-bob", "bob", true),
        ],
        groups: vec![DirectoryGroup {
            id: "g1".into(),
            name: "Engineering".into(),
            members: vec!["new-id-reused-email".into()],
        }],
        total_groups: 1,
    };

    let result = plan(&cfg, &users, &[], &directory);
    assert!(
        result.link_users.is_empty(),
        "must not relink stale external_id or out-of-scope local user: {:?}",
        result.link_users
    );
    assert!(
        result
            .disable_users
            .iter()
            .all(|change| change.username != "localbob"),
        "out-of-scope local user must stay untouched"
    );
}
