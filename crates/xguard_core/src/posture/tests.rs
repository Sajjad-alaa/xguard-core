//! Evaluation tests: pure, no database.

use chrono::NaiveDate;
use xguard_common::db::models::device_posture::{
    DevicePosture, DevicePostureOsRule, DevicePostureWithRules, OsType,
};

use super::{PostureFacts, PostureResult, evaluate};

fn today() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 11, 18).unwrap()
}

fn policy(name: &str, rules: Vec<DevicePostureOsRule>) -> DevicePostureWithRules {
    DevicePostureWithRules {
        posture: DevicePosture {
            id: 1,
            name: name.into(),
            description: None,
            min_desktop_client_version: None,
            min_mobile_client_version: None,
            allow_prerelease_client: false,
        },
        os_rules: rules,
        locations: vec![1],
    }
}

fn rule(os: OsType) -> DevicePostureOsRule {
    DevicePostureOsRule {
        posture_id: 1,
        os_type: os,
        ..Default::default()
    }
}

fn linux_facts() -> PostureFacts {
    PostureFacts {
        os: Some(OsType::Linux),
        os_version: Some("24.04".into()),
        kernel_version: Some("6.8.0-45-generic".into()),
        client_version: Some("2.2.0".into()),
        disk_encrypted: Some(true),
        firewall_enabled: Some(true),
        screen_lock_enabled: Some(true),
        ..Default::default()
    }
}

fn failures(result: &PostureResult) -> String {
    result.failures().join(" | ")
}

#[test]
fn no_policies_always_pass() {
    assert_eq!(evaluate(&[], None, today()), PostureResult::Pass);
}

#[test]
fn missing_report_fails() {
    let result = evaluate(&[policy("p", vec![])], None, today());
    assert!(failures(&result).contains("did not report"));
}

#[test]
fn empty_policy_allows_any_os_but_needs_os_and_client() {
    let policies = [policy("p", vec![])];
    assert!(evaluate(&policies, Some(&linux_facts()), today()).is_pass());

    let result = evaluate(&policies, Some(&PostureFacts::default()), today());
    assert!(failures(&result).contains("operating system could not be determined"));

    let mut facts = linux_facts();
    facts.client_version = None;
    let result = evaluate(&policies, Some(&facts), today());
    assert!(failures(&result).contains("client version could not be determined"));
}

#[test]
fn os_without_rule_is_not_allowed() {
    let policies = [policy("Mac only", vec![rule(OsType::Macos)])];
    let result = evaluate(&policies, Some(&linux_facts()), today());
    assert_eq!(
        result.failures(),
        ["Linux devices are not allowed by policy \"Mac only\""]
    );
}

#[test]
fn kernel_and_os_versions() {
    let mut linux = rule(OsType::Linux);
    linux.min_kernel_version = Some("6.1".into());
    assert!(
        evaluate(
            &[policy("p", vec![linux.clone()])],
            Some(&linux_facts()),
            today()
        )
        .is_pass()
    );

    linux.min_kernel_version = Some("6.10".into());
    let result = evaluate(
        &[policy("p", vec![linux.clone()])],
        Some(&linux_facts()),
        today(),
    );
    assert!(
        failures(&result)
            .contains("kernel version 6.8.0-45-generic is older than the required 6.10")
    );

    let mut facts = linux_facts();
    facts.kernel_version = None;
    linux.min_kernel_version = Some("5.0".into());
    let result = evaluate(&[policy("p", vec![linux])], Some(&facts), today());
    assert!(failures(&result).contains("kernel version could not be determined"));

    let mut windows = rule(OsType::Windows);
    windows.min_os_version = Some("10.0.22631".into());
    let mut facts = PostureFacts {
        os: Some(OsType::Windows),
        os_version: Some("10.0.22621.4317".into()),
        client_version: Some("2.2.0".into()),
        ..Default::default()
    };
    let result = evaluate(&[policy("p", vec![windows.clone()])], Some(&facts), today());
    assert!(failures(&result).contains("Windows version 10.0.22621.4317 is older"));
    facts.os_version = Some("10.0.26100".into());
    assert!(evaluate(&[policy("p", vec![windows])], Some(&facts), today()).is_pass());
}

#[test]
fn boolean_facts_missing_means_non_compliant() {
    let mut linux = rule(OsType::Linux);
    linux.disk_encryption_required = Some(true);
    linux.firewall_required = Some(true);
    linux.screen_lock_required = Some(true);
    let policies = [policy("p", vec![linux])];
    assert!(evaluate(&policies, Some(&linux_facts()), today()).is_pass());

    let mut facts = linux_facts();
    facts.disk_encrypted = Some(false);
    facts.firewall_enabled = None;
    facts.screen_lock_enabled = Some(false);
    let result = evaluate(&policies, Some(&facts), today());
    assert_eq!(
        result.failures(),
        [
            "disk encryption is required",
            "firewall status could not be determined",
            "screen lock is required",
        ]
    );
}

#[test]
fn not_required_flags_are_ignored() {
    let mut linux = rule(OsType::Linux);
    linux.disk_encryption_required = Some(false);
    let mut facts = linux_facts();
    facts.disk_encrypted = None;
    assert!(evaluate(&[policy("p", vec![linux])], Some(&facts), today()).is_pass());
}

#[test]
fn client_version_rules() {
    let mut p = policy("p", vec![]);
    p.posture.min_desktop_client_version = Some("2.3.0".into());
    let result = evaluate(&[p.clone()], Some(&linux_facts()), today());
    assert!(failures(&result).contains("XGuard client 2.2.0 is older than the required 2.3.0"));

    let mut facts = linux_facts();
    facts.client_version = Some("2.3.0-beta1".into());
    let result = evaluate(&[p.clone()], Some(&facts), today());
    assert_eq!(
        result.failures(),
        ["pre-release XGuard client 2.3.0-beta1 is not allowed"]
    );
    p.posture.allow_prerelease_client = true;
    assert!(evaluate(&[p.clone()], Some(&facts), today()).is_pass());

    // The mobile minimum does not apply to desktop clients.
    p.posture.min_desktop_client_version = None;
    p.posture.min_mobile_client_version = Some("9.0.0".into());
    assert!(evaluate(&[p], Some(&linux_facts()), today()).is_pass());
}

#[test]
fn update_and_patch_ages() {
    let mut windows = rule(OsType::Windows);
    windows.windows_security_update_max_age = Some(30);
    let mut facts = PostureFacts {
        os: Some(OsType::Windows),
        client_version: Some("2.2.0".into()),
        security_update_age_days: Some(31),
        ..Default::default()
    };
    let policies = [policy("p", vec![windows])];
    let result = evaluate(&policies, Some(&facts), today());
    assert!(failures(&result).contains("31 days old (at most 30 allowed)"));
    facts.security_update_age_days = Some(30);
    assert!(evaluate(&policies, Some(&facts), today()).is_pass());
    facts.security_update_age_days = None;
    assert!(!evaluate(&policies, Some(&facts), today()).is_pass());

    let mut android = rule(OsType::Android);
    android.android_security_patch_level_max_age = Some(90);
    let mut facts = PostureFacts {
        os: Some(OsType::Android),
        client_version: Some("1.8.0".into()),
        security_patch_date: NaiveDate::from_ymd_opt(2026, 9, 1),
        ..Default::default()
    };
    let policies = [policy("p", vec![android])];
    assert!(evaluate(&policies, Some(&facts), today()).is_pass());
    facts.security_patch_date = NaiveDate::from_ymd_opt(2026, 1, 1);
    assert!(!evaluate(&policies, Some(&facts), today()).is_pass());
}

#[test]
fn every_policy_must_pass_and_failures_are_deduplicated() {
    let mut a = rule(OsType::Linux);
    a.disk_encryption_required = Some(true);
    let mut b = rule(OsType::Linux);
    b.disk_encryption_required = Some(true);
    b.firewall_required = Some(true);
    let mut facts = linux_facts();
    facts.disk_encrypted = Some(false);
    let policies = [policy("a", vec![a]), policy("b", vec![b])];
    let result = evaluate(&policies, Some(&facts), today());
    assert_eq!(result.failures(), ["disk encryption is required"]);

    facts.disk_encrypted = Some(true);
    facts.firewall_enabled = Some(false);
    let result = evaluate(&policies, Some(&facts), today());
    assert_eq!(result.failures(), ["firewall is required"]);
}

#[test]
fn broken_stored_requirement_fails_closed() {
    let mut linux = rule(OsType::Linux);
    linux.min_kernel_version = Some("six".into());
    let result = evaluate(&[policy("p", vec![linux])], Some(&linux_facts()), today());
    assert!(failures(&result).contains("requirement is invalid"));
}
