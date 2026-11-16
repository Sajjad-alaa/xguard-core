use std::net::{IpAddr, Ipv4Addr};

use chrono::{Duration, Utc};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use super::{
    address::AddressRange,
    compile::{PolicyAction, compile, normalize},
    rule::{FirewallRule, FirewallRuleAction, FirewallRuleError, FirewallRuleInput},
};
use crate::db::{
    Id,
    models::{
        Device, DeviceType, User, WireguardNetwork, device::WireguardNetworkDevice, group::Group,
        wireguard::ServiceLocationMode,
    },
    setup_pool,
};

fn input(name: &str) -> FirewallRuleInput {
    FirewallRuleInput {
        name: name.into(),
        description: String::new(),
        enabled: true,
        priority: 1000,
        action: FirewallRuleAction::Allow,
        all_locations: true,
        locations: Vec::new(),
        any_source: true,
        all_users: false,
        all_network_devices: false,
        users: Vec::new(),
        groups: Vec::new(),
        devices: Vec::new(),
        any_destination: true,
        destinations: Vec::new(),
        protocols: Vec::new(),
        ports: Vec::new(),
        expires_at: None,
    }
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 6, 0, last))
}

fn host(last: u8) -> AddressRange {
    AddressRange::single(ip(last))
}

// --- validation (no database) ---

#[test]
fn validation_canonicalises_input() {
    let rule = FirewallRuleInput {
        name: "  web  ".into(),
        any_destination: false,
        destinations: vec!["10.0.0.9/24".into(), "10.0.0.0/24".into(), "fd00::1".into()],
        protocols: vec![17, 6, 6],
        ports: vec!["443".into(), "80 - 81".into()],
        users: vec![3, 1, 3],
        ..input("x")
    }
    .validate()
    .unwrap();
    assert_eq!(rule.name, "web");
    assert_eq!(rule.destinations, ["10.0.0.0/24", "fd00::1"]);
    assert_eq!(rule.protocols, [6, 17]);
    assert_eq!(rule.ports, ["443", "80-81"]);
    assert_eq!(rule.users, [1, 3]);
}

#[test]
fn validation_rejects_bad_rules() {
    let cases = [
        input("   "),
        FirewallRuleInput {
            all_locations: false,
            ..input("no locations")
        },
        FirewallRuleInput {
            any_source: false,
            ..input("nobody")
        },
        FirewallRuleInput {
            any_destination: false,
            ..input("nowhere")
        },
        FirewallRuleInput {
            destinations: vec!["10.0.0.1; flush ruleset".into()],
            ..input("injection")
        },
        FirewallRuleInput {
            protocols: vec![256],
            ..input("protocol")
        },
        FirewallRuleInput {
            protocols: vec![1],
            ports: vec!["22".into()],
            ..input("icmp ports")
        },
        FirewallRuleInput {
            ports: vec!["0".into()],
            ..input("port zero")
        },
    ];
    for case in cases {
        let name = case.name.clone();
        assert!(
            matches!(case.validate(), Err(FirewallRuleError::Invalid(_))),
            "{name:?} should be rejected"
        );
    }
}

#[test]
fn normalize_merges_ranges_per_family() {
    let v6 = AddressRange::single("fd00::1".parse().unwrap());
    let merged = normalize(vec![host(3), v6, host(1), host(2), host(9)]);
    assert_eq!(
        merged,
        [
            AddressRange::V4(Ipv4Addr::new(10, 6, 0, 1), Ipv4Addr::new(10, 6, 0, 3)),
            host(9),
            v6
        ]
    );
}

// --- database ---

struct Fixture {
    location: WireguardNetwork<Id>,
    other_location: WireguardNetwork<Id>,
    alice: Id,
    bob: Id,
    group: Id,
    printer: Id,
}

async fn location(pool: &PgPool, name: &str, acl: bool) -> WireguardNetwork<Id> {
    WireguardNetwork::new(
        name.into(),
        51820,
        "vpn.xguard.local".into(),
        None,
        Vec::new(),
        true,
        acl,
        false,
        false,
        false,
        ServiceLocationMode::Disabled,
    )
    .save(pool)
    .await
    .unwrap()
}

async fn user(pool: &PgPool, name: &str, active: bool) -> User<Id> {
    let email = format!("{name}@xguard.local");
    let mut user = User::new(name, None, "Test", name, email.as_str(), None);
    user.is_active = active;
    user.save(pool).await.unwrap()
}

async fn device(pool: &PgPool, owner: Id, kind: DeviceType, location: Id, address: u8) -> Id {
    let device = Device::new(
        format!("device-{address}"),
        format!("key-{address}"),
        owner,
        kind,
        None,
        true,
    )
    .save(pool)
    .await
    .unwrap();
    WireguardNetworkDevice::new(location, device.id, vec![ip(address)])
        .insert(pool)
        .await
        .unwrap();
    device.id
}

async fn fixture(pool: &PgPool) -> Fixture {
    let location_main = location(pool, "office", true).await;
    let other_location = location(pool, "lab", true).await;
    let alice = user(pool, "alice", true).await;
    let bob = user(pool, "bob", true).await;
    let carol = user(pool, "carol", false).await;
    let group = Group::new("engineering").save(pool).await.unwrap();
    alice.add_to_group(pool, &group).await.unwrap();
    carol.add_to_group(pool, &group).await.unwrap();

    device(pool, alice.id, DeviceType::User, location_main.id, 2).await;
    device(pool, bob.id, DeviceType::User, location_main.id, 3).await;
    device(pool, carol.id, DeviceType::User, location_main.id, 4).await;
    let printer = device(pool, bob.id, DeviceType::Network, location_main.id, 10).await;
    Fixture {
        location: location_main,
        other_location,
        alice: alice.id,
        bob: bob.id,
        group: group.id,
        printer,
    }
}

async fn create(pool: &PgPool, rule: FirewallRuleInput) -> Id {
    let rule = rule.validate().unwrap();
    let mut transaction = pool.begin().await.unwrap();
    let id = FirewallRule::create(&mut transaction, &rule).await.unwrap();
    transaction.commit().await.unwrap();
    id
}

#[sqlx::test]
async fn test_rule_crud(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let f = fixture(&pool).await;

    let id = create(
        &pool,
        FirewallRuleInput {
            all_locations: false,
            locations: vec![f.location.id],
            any_source: false,
            groups: vec![f.group],
            devices: vec![f.printer],
            any_destination: false,
            destinations: vec!["192.168.1.0/24".into()],
            ..input("engineering")
        },
    )
    .await;
    let stored = FirewallRule::find_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(stored.locations, [f.location.id]);
    assert_eq!(stored.groups, [f.group]);
    assert_eq!(stored.devices, [f.printer]);
    assert_eq!(stored.destinations, ["192.168.1.0/24"]);

    let changed = FirewallRuleInput {
        any_source: false,
        users: vec![f.bob],
        action: FirewallRuleAction::Reject,
        ..input("bob only")
    }
    .validate()
    .unwrap();
    let mut transaction = pool.begin().await.unwrap();
    FirewallRule::update(&mut transaction, id, &changed)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    let stored = FirewallRule::find_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(stored.name, "bob only");
    assert_eq!(stored.action, FirewallRuleAction::Reject);
    assert_eq!(stored.users, [f.bob]);
    assert!(stored.groups.is_empty() && stored.devices.is_empty());
    assert!(stored.locations.is_empty());

    // References to rows that don't exist are refused, and nothing is stored.
    let ghost = FirewallRuleInput {
        any_source: false,
        users: vec![987_654],
        ..input("ghost")
    }
    .validate()
    .unwrap();
    let mut transaction = pool.begin().await.unwrap();
    assert!(matches!(
        FirewallRule::create(&mut transaction, &ghost).await,
        Err(FirewallRuleError::UnknownReference)
    ));
    drop(transaction);
    assert_eq!(FirewallRule::all(&pool).await.unwrap().len(), 1);

    FirewallRule::delete(&pool, id).await.unwrap();
    assert!(matches!(
        FirewallRule::delete(&pool, id).await,
        Err(FirewallRuleError::NotFound)
    ));
}

#[sqlx::test]
async fn test_compile_resolves_sources(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let f = fixture(&pool).await;

    let web = create(
        &pool,
        FirewallRuleInput {
            priority: 10,
            any_source: false,
            groups: vec![f.group],
            any_destination: false,
            destinations: vec!["192.168.1.0/24".into()],
            protocols: vec![6],
            ports: vec!["443".into()],
            ..input("engineering web")
        },
    )
    .await;
    let users = create(
        &pool,
        FirewallRuleInput {
            priority: 20,
            any_source: false,
            all_users: true,
            action: FirewallRuleAction::Deny,
            ..input("users denied")
        },
    )
    .await;
    let alice_again = create(
        &pool,
        FirewallRuleInput {
            priority: 30,
            any_source: false,
            users: vec![f.alice],
            ..input("same source as the group rule")
        },
    )
    .await;
    let printers = create(
        &pool,
        FirewallRuleInput {
            priority: 40,
            any_source: false,
            all_network_devices: true,
            ..input("printers")
        },
    )
    .await;
    // Rules that must not show up at the office.
    create(
        &pool,
        FirewallRuleInput {
            enabled: false,
            ..input("disabled")
        },
    )
    .await;
    create(
        &pool,
        FirewallRuleInput {
            expires_at: Some((Utc::now() - Duration::hours(1)).naive_utc()),
            ..input("expired")
        },
    )
    .await;
    let lab_only = create(
        &pool,
        FirewallRuleInput {
            all_locations: false,
            locations: vec![f.other_location.id],
            ..input("lab only")
        },
    )
    .await;
    let bob_rule = create(
        &pool,
        FirewallRuleInput {
            any_source: false,
            users: vec![f.bob],
            ..input("bob")
        },
    )
    .await;

    let mut conn = pool.acquire().await.unwrap();
    let policy = compile(&mut conn, &f.location).await.unwrap().unwrap();
    assert_eq!(policy.default_action, Some(PolicyAction::Drop));
    let ids: Vec<_> = policy.rules.iter().map(|r| r.id).collect();
    assert_eq!(ids, [web, users, alice_again, printers, bob_rule]);

    let source = |rule: usize| {
        policy.rules[rule]
            .source
            .map(|s| policy.sets[s as usize].clone())
    };
    // Carol is in the group but disabled: only Alice.
    assert_eq!(source(0), Some(vec![host(2)]));
    // All active users' user devices; not the printer, not Carol.
    assert_eq!(
        source(1),
        Some(vec![AddressRange::V4(
            Ipv4Addr::new(10, 6, 0, 2),
            Ipv4Addr::new(10, 6, 0, 3)
        )])
    );
    // The same address set is shared, not repeated.
    assert_eq!(policy.rules[0].source, policy.rules[2].source);
    assert_eq!(source(3), Some(vec![host(10)]));
    assert_eq!(policy.rules[0].protocols, [6]);
    assert_eq!(policy.rules[0].ports.len(), 1);
    assert_eq!(policy.rules[0].ports[0], 443..=443);

    // Compiling again gives the same revision; a change gives a new one.
    let again = compile(&mut conn, &f.location).await.unwrap().unwrap();
    assert_eq!(again.revision, policy.revision);
    FirewallRule::delete(&pool, printers).await.unwrap();
    let changed = compile(&mut conn, &f.location).await.unwrap().unwrap();
    assert_ne!(changed.revision, policy.revision);

    // Nobody has a device in the lab: only "any source" rules can match there.
    let lab = compile(&mut conn, &f.other_location)
        .await
        .unwrap()
        .unwrap();
    let lab_ids: Vec<_> = lab.rules.iter().map(|r| r.id).collect();
    assert_eq!(lab_ids, [lab_only]);
}

#[sqlx::test]
async fn test_compile_off_and_snat(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let f = fixture(&pool).await;
    let plain = location(&pool, "plain", false).await;
    let mut conn = pool.acquire().await.unwrap();

    // Firewall off and no SNAT: nothing for the gateway to do.
    assert_eq!(compile(&mut conn, &plain).await.unwrap(), None);

    sqlx::query(
        "INSERT INTO user_snat_binding (user_id, location_id, public_ip) VALUES ($1, $2, $3)",
    )
    .bind(f.alice)
    .bind(f.location.id)
    .bind(ipnetwork::IpNetwork::from(IpAddr::V4(Ipv4Addr::new(
        203, 0, 113, 7,
    ))))
    .execute(&pool)
    .await
    .unwrap();
    let mut location = f.location.clone();
    location.acl_enabled = false;
    let policy = compile(&mut conn, &location).await.unwrap().unwrap();
    assert_eq!(policy.default_action, None);
    assert!(policy.rules.is_empty());
    assert_eq!(policy.snat.len(), 1);
    assert_eq!(policy.snat[0].to, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
    assert_eq!(policy.sets[policy.snat[0].source as usize], [host(2)]);
}
