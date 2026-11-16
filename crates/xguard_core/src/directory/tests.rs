//! Planner tests. Live tests against a real server are in `tests/integration/directory.rs`.

use std::collections::BTreeSet;

use super::{
    config::{Authority, test_config},
    model::{DirectoryGroup, DirectorySnapshot, DirectoryUser},
    plan::{LocalUser, Membership, StatusChange, plan},
};

fn local(id: i64, name: &str, groups: &[&str]) -> LocalUser {
    LocalUser {
        id,
        username: name.into(),
        first_name: "First".into(),
        last_name: name.into(),
        email: format!("{name}@example.org"),
        phone: None,
        is_active: true,
        is_admin: false,
        from_directory: true,
        enrolled_or_from_directory: true,
        rdn: Some(name.into()),
        path: Some("ou=users,dc=example,dc=org".into()),
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
    }
}

fn remote(name: &str) -> DirectoryUser {
    DirectoryUser {
        dn: format!("uid={name},ou=users,dc=example,dc=org"),
        username: name.into(),
        rdn: name.into(),
        path: "ou=users,dc=example,dc=org".into(),
        first_name: "First".into(),
        last_name: name.into(),
        email: format!("{name}@example.org"),
        phone: None,
        disabled: Some(false),
        account_control: None,
        member_of: BTreeSet::new(),
    }
}

fn group(name: &str, members: &[&str]) -> DirectoryGroup {
    DirectoryGroup {
        dn: format!("cn={name},ou=groups,dc=example,dc=org"),
        name: name.into(),
        members: members
            .iter()
            .map(|m| format!("uid={m},ou=users,dc=example,dc=org"))
            .collect(),
    }
}

fn names(groups: &[&str]) -> BTreeSet<String> {
    groups.iter().map(|g| (*g).to_owned()).collect()
}

fn membership(group: &str, username: &str) -> Membership {
    Membership {
        group: group.into(),
        username: username.into(),
    }
}

#[test]
fn in_sync_means_nothing_to_do() {
    let config = test_config();
    let snapshot = DirectorySnapshot {
        users: vec![remote("alice")],
        groups: vec![group("ops", &["alice"])],
    };
    // Usernames match regardless of case.
    let mut alice = local(1, "Alice", &["ops"]);
    alice.last_name = "alice".into();
    alice.email = "alice@example.org".into();
    let result = plan(&config, &[alice], &names(&["ops"]), &snapshot);
    assert!(result.is_empty(), "{result:?}");
}

#[test]
fn directory_authority_pulls_changes() {
    let mut config = test_config();
    config.sync_account_status = true;
    let mut changed = remote("alice");
    changed.email = "new@example.org".into();
    changed.disabled = Some(true);
    let snapshot = DirectorySnapshot {
        users: vec![changed, remote("bob")],
        groups: vec![group("ops", &["bob"]), group("dev", &[])],
    };
    let mut local_only = local(3, "carol", &[]);
    local_only.from_directory = true;
    let mut created_here = local(4, "dave", &[]);
    created_here.from_directory = false;
    let result = plan(
        &config,
        &[
            local(1, "alice", &["dev", "admin"]),
            local_only,
            created_here,
        ],
        &names(&["dev", "admin"]),
        &snapshot,
    );
    assert_eq!(result.create_local, ["bob"]);
    assert_eq!(result.update_local, ["alice"]);
    assert_eq!(result.delete_local, ["carol"]);
    assert_eq!(
        result.local_status,
        [StatusChange {
            username: "alice".into(),
            active: false
        }]
    );
    assert_eq!(result.create_local_groups, ["ops"]);
    assert_eq!(result.add_local_members, [membership("ops", "bob")]);
    // `dev` exists in the directory and alice is not in it there; `admin` does not exist there
    // and keeps its members.
    assert_eq!(result.remove_local_members, [membership("dev", "alice")]);
    assert!(result.skipped.iter().any(|s| s.starts_with("dave")));
    assert!(result.create_remote.is_empty() && result.delete_remote.is_empty());
}

#[test]
fn xguard_authority_pushes_changes() {
    let mut config = test_config();
    config.authority = Authority::XGuard;
    config.sync_account_status = true;
    let mut changed = local(1, "alice", &["ops"]);
    changed.last_name = "Smith".into();
    changed.is_active = false;
    let mut service = remote("svc");
    service.dn = config.bind_dn.clone();
    let snapshot = DirectorySnapshot {
        users: vec![remote("alice"), remote("eve"), service],
        groups: vec![group("dev", &["alice"])],
    };
    let result = plan(
        &config,
        &[changed, local(2, "bob", &["ops"])],
        &names(&["ops", "dev"]),
        &snapshot,
    );
    assert_eq!(result.create_remote, ["bob"]);
    assert_eq!(result.update_remote, ["alice"]);
    assert_eq!(result.delete_remote, ["eve"]);
    assert_eq!(
        result.remote_status,
        [StatusChange {
            username: "alice".into(),
            active: false
        }]
    );
    assert_eq!(result.create_remote_groups, ["ops"]);
    assert_eq!(
        result.add_remote_members,
        [membership("ops", "alice"), membership("ops", "bob")]
    );
    assert_eq!(result.remove_remote_members, [membership("dev", "alice")]);
    // The account XGuard binds with is never deleted.
    assert!(result.skipped.iter().any(|s| s.starts_with("svc")));
    assert!(result.create_local.is_empty() && result.delete_local.is_empty());
}

#[test]
fn admins_are_protected() {
    let mut config = test_config();
    config.sync_account_status = true;
    let mut admin = local(1, "root", &["admin"]);
    admin.is_admin = true;
    let mut disabled_admin = local(2, "boss", &["admin"]);
    disabled_admin.is_admin = true;
    let mut boss = remote("boss");
    boss.disabled = Some(true);
    let snapshot = DirectorySnapshot {
        users: vec![boss],
        groups: vec![],
    };
    let result = plan(
        &config,
        &[admin, disabled_admin],
        &names(&["admin"]),
        &snapshot,
    );
    assert!(result.delete_local.is_empty());
    assert!(result.local_status.is_empty());
    assert_eq!(result.skipped.len(), 2, "{:?}", result.skipped);
}

#[test]
fn sync_groups_limit_scope() {
    let mut config = test_config();
    config.sync_groups = vec!["VPN".into()];
    let snapshot = DirectorySnapshot {
        users: vec![remote("alice"), remote("bob")],
        groups: vec![group("vpn", &["alice"])],
    };
    // bob left the sync group in the directory: he loses it in XGuard but keeps his account.
    let result = plan(
        &config,
        &[local(2, "bob", &["vpn"])],
        &names(&["vpn"]),
        &snapshot,
    );
    assert_eq!(result.create_local, ["alice"]);
    assert!(result.delete_local.is_empty());
    assert_eq!(result.remove_local_members, [membership("vpn", "bob")]);
}

#[test]
fn username_clashes_are_reported() {
    let config = test_config();
    let mut pending = local(1, "alice", &[]);
    pending.enrolled_or_from_directory = false;
    let snapshot = DirectorySnapshot {
        users: vec![remote("alice")],
        groups: vec![],
    };
    let result = plan(&config, &[pending], &BTreeSet::new(), &snapshot);
    assert!(result.create_local.is_empty());
    assert!(result.skipped.iter().any(|s| s.starts_with("alice")));
}

#[test]
fn mass_deletion_needs_confirmation() {
    let mut config = test_config();
    config.authority = Authority::XGuard;
    let users: Vec<DirectoryUser> = (0..10).map(|i| remote(&format!("u{i}"))).collect();
    let snapshot = DirectorySnapshot {
        users,
        groups: vec![],
    };
    let result = plan(&config, &[], &BTreeSet::new(), &snapshot);
    assert_eq!(result.delete_remote.len(), 10);
    assert!(result.check_deletions(false).is_err());
    assert!(result.check_deletions(true).is_ok());

    let few = DirectorySnapshot {
        users: (0..3).map(|i| remote(&format!("u{i}"))).collect(),
        groups: vec![],
    };
    assert!(
        plan(&config, &[], &BTreeSet::new(), &few)
            .check_deletions(false)
            .is_ok()
    );
}
