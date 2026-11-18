//! API types for posture policies and their validation.

use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize};
use xguard_common::{
    db::{
        Id, NoId,
        models::device_posture::{
            DevicePosture, DevicePostureOsRule, DevicePostureWithRules, OsType,
        },
    },
    names::is_safe_name,
};

use super::version::{DottedVersion, parse_client_version};

pub const MAX_NAME_LEN: usize = 64;
pub const MAX_DESCRIPTION_LEN: usize = 512;
pub const MAX_AGE_DAYS: i32 = 3650;
/// Most locations a policy can be attached to in one request.
pub const MAX_ASSIGNMENTS: usize = 1000;

/// A version in a request: a dotted string, or a bare number as older web pages send it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInput(pub String);

impl<'de> Deserialize<'de> for VersionInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Number(u32),
            Text(String),
        }
        Ok(Self(match Raw::deserialize(deserializer)? {
            Raw::Number(n) => n.to_string(),
            Raw::Text(s) => s,
        }))
    }
}

impl Serialize for VersionInput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// The requirements for one operating system.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "os_type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ApiOsRule {
    Windows {
        /// Minimum Windows build, e.g. `10.0.22631` (Windows 11 23H2).
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
        min_os_version: Option<VersionInput>,
        #[serde(default)]
        disk_encryption_required: Option<bool>,
        #[serde(default)]
        firewall_required: Option<bool>,
        #[serde(default)]
        screen_lock_required: Option<bool>,
        #[serde(default)]
        antivirus_required: Option<bool>,
        #[serde(default)]
        ad_domain_joined_required: Option<bool>,
        #[serde(default)]
        windows_security_update_max_age: Option<i32>,
    },
    Macos {
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
        min_os_version: Option<VersionInput>,
        #[serde(default)]
        disk_encryption_required: Option<bool>,
        #[serde(default)]
        firewall_required: Option<bool>,
        #[serde(default)]
        screen_lock_required: Option<bool>,
        #[serde(default)]
        device_integrity_required: Option<bool>,
    },
    Linux {
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
        min_kernel_version: Option<VersionInput>,
        #[serde(default)]
        disk_encryption_required: Option<bool>,
        #[serde(default)]
        firewall_required: Option<bool>,
        #[serde(default)]
        screen_lock_required: Option<bool>,
    },
    Ios {
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
        min_os_version: Option<VersionInput>,
    },
    Android {
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
        min_os_version: Option<VersionInput>,
        #[serde(default)]
        device_integrity_required: Option<bool>,
        #[serde(default)]
        android_security_patch_level_max_age: Option<i32>,
    },
}

/// A posture policy as the API returns it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiDevicePosture {
    pub id: Id,
    pub name: String,
    pub description: Option<String>,
    pub min_desktop_client_version: Option<String>,
    pub min_mobile_client_version: Option<String>,
    pub allow_prerelease_client: bool,
    pub os_rules: Vec<ApiOsRule>,
    /// IDs of the locations this policy is attached to.
    pub locations: Vec<Id>,
}

/// Body for creating or updating a posture policy.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EditDevicePosture {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub min_desktop_client_version: Option<String>,
    #[serde(default)]
    pub min_mobile_client_version: Option<String>,
    #[serde(default)]
    pub allow_prerelease_client: bool,
    #[serde(default)]
    pub os_rules: Vec<ApiOsRule>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct PolicyError(pub String);

fn invalid(message: impl Into<String>) -> PolicyError {
    PolicyError(message.into())
}

/// Checks and trims a policy name.
pub fn validate_name(name: &str) -> Result<String, PolicyError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(invalid("The policy name is required."));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(invalid(format!(
            "The policy name can have at most {MAX_NAME_LEN} characters."
        )));
    }
    if !is_safe_name(name) {
        return Err(invalid(
            "The policy name can use letters, digits, spaces and - _ . ( ) : / only.",
        ));
    }
    Ok(name.to_owned())
}

fn validate_description(description: Option<&str>) -> Result<Option<String>, PolicyError> {
    let Some(description) = description.map(str::trim).filter(|d| !d.is_empty()) else {
        return Ok(None);
    };
    if description.chars().count() > MAX_DESCRIPTION_LEN {
        return Err(invalid(format!(
            "The description can have at most {MAX_DESCRIPTION_LEN} characters."
        )));
    }
    if description
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(invalid("The description contains control characters."));
    }
    Ok(Some(description.to_owned()))
}

fn validate_client_version(value: Option<&str>, what: &str) -> Result<Option<String>, PolicyError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    parse_client_version(value)
        .map(|v| Some(v.to_string()))
        .ok_or_else(|| invalid(format!("{what} must be a version such as 2.2.0.")))
}

/// Canonicalises a minimum version. Windows product numbers (10, 11) become their first build.
fn validate_version(
    value: Option<&VersionInput>,
    os: OsType,
    what: &str,
) -> Result<Option<String>, PolicyError> {
    let Some(value) = value.map(|v| v.0.trim()).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let value = match (os, value) {
        (OsType::Windows, "11") => "10.0.22000",
        (OsType::Windows, "10") => "10.0.10240",
        (_, value) => value,
    };
    DottedVersion::parse_strict(value)
        .map(|v| Some(v.canonical()))
        .ok_or_else(|| {
            invalid(format!(
                "{what} must be a dotted version such as 14.5 (at most 4 numbers)."
            ))
        })
}

fn validate_age(value: Option<i32>, what: &str) -> Result<Option<i32>, PolicyError> {
    match value {
        None => Ok(None),
        Some(days) if (1..=MAX_AGE_DAYS).contains(&days) => Ok(Some(days)),
        Some(_) => Err(invalid(format!(
            "{what} must be between 1 and {MAX_AGE_DAYS} days."
        ))),
    }
}

impl ApiOsRule {
    #[must_use]
    pub fn os_type(&self) -> OsType {
        match self {
            Self::Windows { .. } => OsType::Windows,
            Self::Macos { .. } => OsType::Macos,
            Self::Linux { .. } => OsType::Linux,
            Self::Ios { .. } => OsType::Ios,
            Self::Android { .. } => OsType::Android,
        }
    }

    /// Validates and converts the rule to its stored form.
    fn into_db_rule(self, posture_id: Id) -> Result<DevicePostureOsRule, PolicyError> {
        let os = self.os_type();
        let mut rule = DevicePostureOsRule {
            posture_id,
            os_type: os,
            ..Default::default()
        };
        match self {
            Self::Windows {
                min_os_version,
                disk_encryption_required,
                firewall_required,
                screen_lock_required,
                antivirus_required,
                ad_domain_joined_required,
                windows_security_update_max_age,
            } => {
                rule.min_os_version =
                    validate_version(min_os_version.as_ref(), os, "The Windows version")?;
                rule.disk_encryption_required = disk_encryption_required;
                rule.firewall_required = firewall_required;
                rule.screen_lock_required = screen_lock_required;
                rule.antivirus_required = antivirus_required;
                rule.ad_domain_joined_required = ad_domain_joined_required;
                rule.windows_security_update_max_age =
                    validate_age(windows_security_update_max_age, "The security update age")?;
            }
            Self::Macos {
                min_os_version,
                disk_encryption_required,
                firewall_required,
                screen_lock_required,
                device_integrity_required,
            } => {
                rule.min_os_version =
                    validate_version(min_os_version.as_ref(), os, "The macOS version")?;
                rule.disk_encryption_required = disk_encryption_required;
                rule.firewall_required = firewall_required;
                rule.screen_lock_required = screen_lock_required;
                rule.device_integrity_required = device_integrity_required;
            }
            Self::Linux {
                min_kernel_version,
                disk_encryption_required,
                firewall_required,
                screen_lock_required,
            } => {
                rule.min_kernel_version =
                    validate_version(min_kernel_version.as_ref(), os, "The kernel version")?;
                rule.disk_encryption_required = disk_encryption_required;
                rule.firewall_required = firewall_required;
                rule.screen_lock_required = screen_lock_required;
            }
            Self::Ios { min_os_version } => {
                rule.min_os_version =
                    validate_version(min_os_version.as_ref(), os, "The iOS version")?;
            }
            Self::Android {
                min_os_version,
                device_integrity_required,
                android_security_patch_level_max_age,
            } => {
                rule.min_os_version =
                    validate_version(min_os_version.as_ref(), os, "The Android version")?;
                rule.device_integrity_required = device_integrity_required;
                rule.android_security_patch_level_max_age = validate_age(
                    android_security_patch_level_max_age,
                    "The security patch age",
                )?;
            }
        }
        Ok(rule)
    }

    #[must_use]
    pub fn from_db_rule(rule: &DevicePostureOsRule) -> Self {
        let version = |v: &Option<String>| v.clone().map(VersionInput);
        match rule.os_type {
            OsType::Windows => Self::Windows {
                min_os_version: version(&rule.min_os_version),
                disk_encryption_required: rule.disk_encryption_required,
                firewall_required: rule.firewall_required,
                screen_lock_required: rule.screen_lock_required,
                antivirus_required: rule.antivirus_required,
                ad_domain_joined_required: rule.ad_domain_joined_required,
                windows_security_update_max_age: rule.windows_security_update_max_age,
            },
            OsType::Macos => Self::Macos {
                min_os_version: version(&rule.min_os_version),
                disk_encryption_required: rule.disk_encryption_required,
                firewall_required: rule.firewall_required,
                screen_lock_required: rule.screen_lock_required,
                device_integrity_required: rule.device_integrity_required,
            },
            OsType::Linux => Self::Linux {
                min_kernel_version: version(&rule.min_kernel_version),
                disk_encryption_required: rule.disk_encryption_required,
                firewall_required: rule.firewall_required,
                screen_lock_required: rule.screen_lock_required,
            },
            OsType::Ios => Self::Ios {
                min_os_version: version(&rule.min_os_version),
            },
            OsType::Android => Self::Android {
                min_os_version: version(&rule.min_os_version),
                device_integrity_required: rule.device_integrity_required,
                android_security_patch_level_max_age: rule.android_security_patch_level_max_age,
            },
        }
    }
}

/// A validated policy, ready to store. Rules carry posture ID 0 until the policy is saved.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedPolicy {
    pub posture: DevicePosture<NoId>,
    pub os_rules: Vec<DevicePostureOsRule>,
}

impl EditDevicePosture {
    pub fn validate(self) -> Result<ValidatedPolicy, PolicyError> {
        let mut seen = HashSet::new();
        let mut os_rules = Vec::with_capacity(self.os_rules.len());
        for rule in self.os_rules {
            if !seen.insert(rule.os_type()) {
                return Err(invalid(format!(
                    "There can be only one rule for {}.",
                    rule.os_type().display_name()
                )));
            }
            os_rules.push(rule.into_db_rule(0)?);
        }
        os_rules.sort_by_key(|rule| rule.os_type);
        Ok(ValidatedPolicy {
            posture: DevicePosture {
                id: NoId,
                name: validate_name(&self.name)?,
                description: validate_description(self.description.as_deref())?,
                min_desktop_client_version: validate_client_version(
                    self.min_desktop_client_version.as_deref(),
                    "The minimum desktop client version",
                )?,
                min_mobile_client_version: validate_client_version(
                    self.min_mobile_client_version.as_deref(),
                    "The minimum mobile client version",
                )?,
                allow_prerelease_client: self.allow_prerelease_client,
            },
            os_rules,
        })
    }
}

impl From<DevicePostureWithRules> for ApiDevicePosture {
    fn from(value: DevicePostureWithRules) -> Self {
        let DevicePostureWithRules {
            posture,
            os_rules,
            locations,
        } = value;
        Self {
            id: posture.id,
            name: posture.name,
            description: posture.description,
            min_desktop_client_version: posture.min_desktop_client_version,
            min_mobile_client_version: posture.min_mobile_client_version,
            allow_prerelease_client: posture.allow_prerelease_client,
            os_rules: os_rules.iter().map(ApiOsRule::from_db_rule).collect(),
            locations,
        }
    }
}

/// A selectable version with a readable label.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VersionOption {
    pub value: &'static str,
    pub label: &'static str,
}

const fn opt(value: &'static str, label: &'static str) -> VersionOption {
    VersionOption { value, label }
}

/// Suggested versions for the web UI. Any dotted version is accepted; these are shortcuts.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VersionCatalog {
    pub windows: Vec<VersionOption>,
    pub macos: Vec<VersionOption>,
    pub ios: Vec<VersionOption>,
    pub android: Vec<VersionOption>,
    pub linux_kernel: Vec<VersionOption>,
}

impl VersionCatalog {
    #[must_use]
    pub fn new() -> Self {
        Self {
            windows: vec![
                opt("10.0.19045", "Windows 10 22H2"),
                opt("10.0.22000", "Windows 11 21H2"),
                opt("10.0.22621", "Windows 11 22H2"),
                opt("10.0.22631", "Windows 11 23H2"),
                opt("10.0.26100", "Windows 11 24H2"),
                opt("10.0.26200", "Windows 11 25H2"),
            ],
            macos: vec![
                opt("12", "macOS 12 Monterey"),
                opt("13", "macOS 13 Ventura"),
                opt("14", "macOS 14 Sonoma"),
                opt("15", "macOS 15 Sequoia"),
                opt("26", "macOS 26 Tahoe"),
            ],
            ios: vec![
                opt("16", "iOS 16"),
                opt("17", "iOS 17"),
                opt("18", "iOS 18"),
                opt("26", "iOS 26"),
            ],
            android: vec![
                opt("12", "Android 12"),
                opt("13", "Android 13"),
                opt("14", "Android 14"),
                opt("15", "Android 15"),
                opt("16", "Android 16"),
            ],
            linux_kernel: vec![
                opt("5.10", "5.10 LTS"),
                opt("5.15", "5.15 LTS"),
                opt("6.1", "6.1 LTS"),
                opt("6.6", "6.6 LTS"),
                opt("6.12", "6.12 LTS"),
            ],
        }
    }
}

impl Default for VersionCatalog {
    fn default() -> Self {
        Self::new()
    }
}

/// Removes duplicates and checks the size of an assignment list.
pub fn normalize_ids(ids: &[Id]) -> Result<Vec<Id>, PolicyError> {
    if ids.len() > MAX_ASSIGNMENTS {
        return Err(invalid(format!(
            "At most {MAX_ASSIGNMENTS} items can be assigned at once."
        )));
    }
    let mut ids: Vec<Id> = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn edit(rules: serde_json::Value) -> Result<ValidatedPolicy, PolicyError> {
        serde_json::from_value::<EditDevicePosture>(json!({
            "name": "  Laptops  ",
            "description": "Company laptops\nonly",
            "min_desktop_client_version": "v2.2.0",
            "os_rules": rules,
        }))
        .unwrap()
        .validate()
    }

    #[test]
    fn valid_policy_is_canonicalised() {
        let policy = edit(json!([
            {"os_type": "windows", "min_os_version": 11, "disk_encryption_required": true,
             "windows_security_update_max_age": 30},
            {"os_type": "linux", "min_kernel_version": "6.01", "firewall_required": true},
            {"os_type": "macos", "min_os_version": "14.5", "screen_lock_required": true},
        ]))
        .unwrap();
        assert_eq!(policy.posture.name, "Laptops");
        assert_eq!(
            policy.posture.min_desktop_client_version.as_deref(),
            Some("2.2.0")
        );
        assert_eq!(policy.os_rules.len(), 3);
        let windows = &policy.os_rules[0];
        assert_eq!(windows.os_type, OsType::Windows);
        assert_eq!(windows.min_os_version.as_deref(), Some("10.0.22000"));
        let macos = &policy.os_rules[1];
        assert_eq!(macos.min_os_version.as_deref(), Some("14.5"));
        let linux = &policy.os_rules[2];
        assert_eq!(linux.min_kernel_version.as_deref(), Some("6.1"));
        assert_eq!(linux.firewall_required, Some(true));
        // Round trip through the API form keeps the values.
        let api = ApiOsRule::from_db_rule(linux);
        assert_eq!(api.into_db_rule(0).unwrap(), *linux);
    }

    #[test]
    fn invalid_policies_are_rejected() {
        let cases = [
            json!([{"os_type": "linux"}, {"os_type": "linux"}]),
            json!([{"os_type": "macos", "min_os_version": "14.x"}]),
            json!([{"os_type": "windows", "windows_security_update_max_age": 0}]),
            json!([{"os_type": "android", "android_security_patch_level_max_age": 9999}]),
        ];
        for case in cases {
            assert!(edit(case.clone()).is_err(), "{case}");
        }
        // Unknown fields and unknown operating systems are refused while parsing.
        assert!(
            serde_json::from_value::<ApiOsRule>(json!({"os_type": "linux", "min_os_version": "1"}))
                .is_err()
        );
        assert!(serde_json::from_value::<ApiOsRule>(json!({"os_type": "beos"})).is_err());

        for name in ["", "   ", "<b>x</b>", &"n".repeat(65)] {
            assert!(validate_name(name).is_err(), "{name}");
        }
        assert!(validate_description(Some(&"d".repeat(513))).is_err());
        assert!(validate_description(Some("bell\u{7}")).is_err());
        assert_eq!(validate_description(Some("   ")).unwrap(), None);
        assert!(validate_client_version(Some("2.2"), "v").is_err());
    }

    #[test]
    fn assignment_lists_are_normalised() {
        assert_eq!(normalize_ids(&[3, 1, 3, 2]).unwrap(), vec![1, 2, 3]);
        assert!(normalize_ids(&vec![1; MAX_ASSIGNMENTS + 1]).is_err());
    }
}
