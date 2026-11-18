//! Pure posture evaluation: policies plus facts give a list of failed checks.
//!
//! Rules:
//! - A device must pass every policy attached to the location.
//! - An operating system without a rule in a policy is not allowed by it. A policy without
//!   rules allows every operating system.
//! - A fact needed by a rule that is missing or malformed fails that rule ("could not be
//!   determined"): missing facts are never compliant.

use chrono::NaiveDate;
use xguard_common::db::models::device_posture::{DevicePostureOsRule, DevicePostureWithRules};

use super::{
    facts::PostureFacts,
    version::{DottedVersion, client_meets_minimum, dotted_meets_minimum, parse_client_version},
};

/// At most this many failure messages are reported (the rest are summarised).
const MAX_FAILURES: usize = 16;

/// The result of evaluating a device against a location's policies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostureResult {
    Pass,
    Fail(Vec<String>),
}

impl PostureResult {
    #[must_use]
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    #[must_use]
    pub fn failures(&self) -> &[String] {
        match self {
            Self::Pass => &[],
            Self::Fail(failures) => failures,
        }
    }
}

/// Evaluates `facts` against all `policies`. `today` is used for patch-level ages.
#[must_use]
pub fn evaluate(
    policies: &[DevicePostureWithRules],
    facts: Option<&PostureFacts>,
    today: NaiveDate,
) -> PostureResult {
    if policies.is_empty() {
        return PostureResult::Pass;
    }
    let Some(facts) = facts else {
        return PostureResult::Fail(vec![
            "the client did not report device posture (update the XGuard client)".into(),
        ]);
    };
    let mut failures = Vec::new();
    for policy in policies {
        evaluate_policy(policy, facts, today, &mut failures);
    }
    failures.dedup();
    let mut unique = Vec::with_capacity(failures.len());
    for failure in failures {
        if !unique.contains(&failure) {
            unique.push(failure);
        }
    }
    if unique.len() > MAX_FAILURES {
        let more = unique.len() - MAX_FAILURES;
        unique.truncate(MAX_FAILURES);
        unique.push(format!("and {more} more"));
    }
    if unique.is_empty() {
        PostureResult::Pass
    } else {
        PostureResult::Fail(unique)
    }
}

fn evaluate_policy(
    policy: &DevicePostureWithRules,
    facts: &PostureFacts,
    today: NaiveDate,
    failures: &mut Vec<String>,
) {
    let posture = &policy.posture;
    let Some(os) = facts.os else {
        failures.push("the operating system could not be determined".into());
        return;
    };

    // Client version.
    let minimum = if os.is_mobile() {
        posture.min_mobile_client_version.as_deref()
    } else {
        posture.min_desktop_client_version.as_deref()
    };
    let client = facts
        .client_version
        .as_deref()
        .and_then(parse_client_version);
    match (&client, minimum.and_then(parse_client_version)) {
        (None, _) => failures.push("the XGuard client version could not be determined".into()),
        (Some(actual), Some(minimum)) if !client_meets_minimum(&minimum, actual) => {
            failures.push(format!(
                "XGuard client {actual} is older than the required {minimum}"
            ));
        }
        _ => {}
    }
    if let Some(actual) = client.as_ref().filter(|actual| !actual.pre.is_empty())
        && !posture.allow_prerelease_client
    {
        failures.push(format!("pre-release XGuard client {actual} is not allowed"));
    }

    if policy.os_rules.is_empty() {
        return;
    }
    let Some(rule) = policy.os_rules.iter().find(|rule| rule.os_type == os) else {
        failures.push(format!(
            "{} devices are not allowed by policy \"{}\"",
            os.display_name(),
            posture.name
        ));
        return;
    };
    evaluate_rule(rule, facts, today, failures);
}

fn required(flag: Option<bool>) -> bool {
    flag == Some(true)
}

fn require_true(
    needed: Option<bool>,
    actual: Option<bool>,
    what: &str,
    failures: &mut Vec<String>,
) {
    if !required(needed) {
        return;
    }
    match actual {
        Some(true) => {}
        Some(false) => failures.push(format!("{what} is required")),
        None => failures.push(format!("{what} status could not be determined")),
    }
}

fn require_version(
    minimum: Option<&str>,
    actual: Option<&str>,
    what: &str,
    failures: &mut Vec<String>,
) {
    let Some(minimum) = minimum else {
        return;
    };
    let Some(minimum) = DottedVersion::parse_strict(minimum) else {
        // Validated on input; a broken stored value fails closed.
        failures.push(format!("{what} requirement is invalid"));
        return;
    };
    match actual.map(|actual| (actual, dotted_meets_minimum(&minimum, actual))) {
        Some((_, Some(true))) => {}
        Some((actual, Some(false))) => failures.push(format!(
            "{what} {actual} is older than the required {}",
            minimum.canonical()
        )),
        Some((_, None)) | None => failures.push(format!("{what} could not be determined")),
    }
}

fn require_max_age(
    max_days: Option<i32>,
    age_days: Option<i64>,
    what: &str,
    failures: &mut Vec<String>,
) {
    let Some(max_days) = max_days else {
        return;
    };
    match age_days {
        Some(age) if age <= i64::from(max_days) => {}
        Some(age) => failures.push(format!(
            "{what} is {age} days old (at most {max_days} allowed)"
        )),
        None => failures.push(format!("{what} could not be determined")),
    }
}

fn evaluate_rule(
    rule: &DevicePostureOsRule,
    facts: &PostureFacts,
    today: NaiveDate,
    failures: &mut Vec<String>,
) {
    let os_name = rule.os_type.display_name();
    require_version(
        rule.min_os_version.as_deref(),
        facts.os_version.as_deref(),
        &format!("{os_name} version"),
        failures,
    );
    require_version(
        rule.min_kernel_version.as_deref(),
        facts.kernel_version.as_deref(),
        "kernel version",
        failures,
    );
    require_true(
        rule.disk_encryption_required,
        facts.disk_encrypted,
        "disk encryption",
        failures,
    );
    require_true(
        rule.firewall_required,
        facts.firewall_enabled,
        "firewall",
        failures,
    );
    require_true(
        rule.screen_lock_required,
        facts.screen_lock_enabled,
        "screen lock",
        failures,
    );
    require_true(
        rule.antivirus_required,
        facts.antivirus_enabled,
        "antivirus",
        failures,
    );
    require_true(
        rule.ad_domain_joined_required,
        facts.domain_joined,
        "Active Directory domain membership",
        failures,
    );
    require_true(
        rule.device_integrity_required,
        facts.device_integrity,
        "device integrity protection",
        failures,
    );
    require_max_age(
        rule.windows_security_update_max_age,
        facts.security_update_age_days.map(i64::from),
        "the last security update",
        failures,
    );
    require_max_age(
        rule.android_security_patch_level_max_age,
        facts
            .security_patch_date
            .map(|date| (today - date).num_days().max(0)),
        "the security patch level",
        failures,
    );
}
