//! Posture facts reported by a client, validated and size-limited.
//!
//! The facts are an attestation made by the client, not proof. Core only checks that they are
//! well formed: a value that is malformed or too long is dropped (treated as unknown), so it can
//! never pass a rule, and the stored snapshot stays small.

use chrono::{DateTime, NaiveDate};
use serde::{Deserialize, Serialize};
use xguard_common::db::models::device_posture::OsType;
use xguard_proto::client_types::{DevicePostureFacts, PostureOs};

use super::version::{DottedVersion, MAX_VERSION_LEN, parse_client_version};

const MAX_NAME_LEN: usize = 128;
/// Ten years: a larger update age is nonsense and is dropped.
const MAX_AGE_DAYS: u32 = 3650;

/// Validated posture facts, also the JSON stored in `device_posture_snapshot.facts`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PostureFacts {
    pub os: Option<OsType>,
    pub os_version: Option<String>,
    pub os_name: Option<String>,
    pub kernel_version: Option<String>,
    pub client_version: Option<String>,
    pub disk_encrypted: Option<bool>,
    pub firewall_enabled: Option<bool>,
    pub screen_lock_enabled: Option<bool>,
    pub antivirus_enabled: Option<bool>,
    pub domain_joined: Option<bool>,
    pub device_integrity: Option<bool>,
    pub security_update_age_days: Option<u32>,
    pub security_patch_date: Option<NaiveDate>,
    /// When the client says it collected the facts (Unix seconds, client clock).
    pub collected_at: Option<i64>,
}

/// Keeps a version-like string only when it is short, printable ASCII and starts with a number.
fn version_string(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    (!value.is_empty()
        && value.len() <= MAX_VERSION_LEN
        && value.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        && DottedVersion::parse_prefix(value).is_some())
    .then(|| value.to_owned())
}

/// Keeps a display name, with control characters removed and its length capped.
fn display_string(value: Option<&str>) -> Option<String> {
    let cleaned: String = value?
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_LEN)
        .collect();
    let cleaned = cleaned.trim();
    (!cleaned.is_empty()).then(|| cleaned.to_owned())
}

impl PostureFacts {
    /// Validates facts received from a client.
    #[must_use]
    pub fn from_proto(facts: &DevicePostureFacts) -> Self {
        let os = match PostureOs::try_from(facts.os) {
            Ok(PostureOs::Linux) => Some(OsType::Linux),
            Ok(PostureOs::Macos) => Some(OsType::Macos),
            Ok(PostureOs::Windows) => Some(OsType::Windows),
            Ok(PostureOs::Ios) => Some(OsType::Ios),
            Ok(PostureOs::Android) => Some(OsType::Android),
            Ok(PostureOs::Unspecified) | Err(_) => None,
        };
        let client_version = parse_client_version(&facts.client_version).map(|v| v.to_string());
        let security_patch_date = facts
            .security_patch_date
            .as_deref()
            .filter(|d| d.len() == 10)
            .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok());
        let collected_at = (facts.collected_at > 0
            && DateTime::from_timestamp(facts.collected_at, 0).is_some())
        .then_some(facts.collected_at);
        Self {
            os,
            os_version: version_string(facts.os_version.as_deref()),
            os_name: display_string(facts.os_name.as_deref()),
            kernel_version: version_string(facts.kernel_version.as_deref()),
            client_version,
            disk_encrypted: facts.disk_encrypted,
            firewall_enabled: facts.firewall_enabled,
            screen_lock_enabled: facts.screen_lock_enabled,
            antivirus_enabled: facts.antivirus_enabled,
            domain_joined: facts.domain_joined,
            device_integrity: facts.device_integrity,
            security_update_age_days: facts
                .security_update_age_days
                .filter(|days| *days <= MAX_AGE_DAYS),
            security_patch_date,
            collected_at,
        }
    }

    /// The facts as stored JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Reads stored facts. Unreadable JSON gives `None`, which no policy accepts.
    #[must_use]
    pub fn from_json(value: &serde_json::Value) -> Option<Self> {
        serde_json::from_value(value.clone()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto() -> DevicePostureFacts {
        DevicePostureFacts {
            os: PostureOs::Linux as i32,
            os_version: Some("24.04".into()),
            os_name: Some("Ubuntu 24.04.1 LTS".into()),
            kernel_version: Some("6.8.0-45-generic".into()),
            client_version: "2.2.0".into(),
            disk_encrypted: Some(true),
            firewall_enabled: Some(false),
            screen_lock_enabled: None,
            antivirus_enabled: None,
            domain_joined: None,
            device_integrity: None,
            security_update_age_days: Some(4),
            security_patch_date: Some("2026-10-05".into()),
            collected_at: 1_790_000_000,
        }
    }

    #[test]
    fn valid_facts_are_kept() {
        let facts = PostureFacts::from_proto(&proto());
        assert_eq!(facts.os, Some(OsType::Linux));
        assert_eq!(facts.kernel_version.as_deref(), Some("6.8.0-45-generic"));
        assert_eq!(facts.client_version.as_deref(), Some("2.2.0"));
        assert_eq!(facts.disk_encrypted, Some(true));
        assert_eq!(facts.firewall_enabled, Some(false));
        assert_eq!(facts.screen_lock_enabled, None);
        assert_eq!(
            facts.security_patch_date,
            NaiveDate::from_ymd_opt(2026, 10, 5)
        );
        let json = facts.to_json();
        assert_eq!(PostureFacts::from_json(&json), Some(facts));
        assert!(json.to_string().len() < 1024);
    }

    #[test]
    fn malformed_facts_are_dropped() {
        let mut raw = proto();
        raw.os = 99;
        raw.os_version = Some("x".repeat(500));
        raw.os_name = Some(format!("Evil\u{0}\n{}", "n".repeat(1000)));
        raw.kernel_version = Some("not a version".into());
        raw.client_version = "<script>".into();
        raw.security_update_age_days = Some(u32::MAX);
        raw.security_patch_date = Some("2026-13-40".into());
        raw.collected_at = -5;
        let facts = PostureFacts::from_proto(&raw);
        assert_eq!(facts.os, None);
        assert_eq!(facts.os_version, None);
        assert_eq!(facts.kernel_version, None);
        assert_eq!(facts.client_version, None);
        assert_eq!(facts.security_update_age_days, None);
        assert_eq!(facts.security_patch_date, None);
        assert_eq!(facts.collected_at, None);
        let name = facts.os_name.unwrap();
        assert!(name.starts_with("Evil"));
        assert!(name.chars().count() <= MAX_NAME_LEN);
        assert!(!name.chars().any(char::is_control));
    }
}
