//! Version parsing and comparison for posture rules.
//!
//! - OS and kernel versions are dotted numbers. A reported version may carry a suffix
//!   (`6.8.0-45-generic`, `14.5 (23F79)`); only the leading dotted number is compared. Missing
//!   components count as zero, so `14` equals `14.0.0`.
//! - Client versions are semver. Pre-release builds compare by their `major.minor.patch`, and a
//!   policy decides separately whether pre-releases are accepted at all.

use std::cmp::Ordering;

use semver::Version;

/// At most this many components (`10.0.22631.4317`).
pub const MAX_COMPONENTS: usize = 4;
/// Largest value of one component.
pub const MAX_COMPONENT: u32 = 99_999;
/// Longest version string accepted anywhere.
pub const MAX_VERSION_LEN: usize = 64;

/// A dotted numeric version, e.g. `[10, 0, 22631]`. Trailing zeros do not matter: `14` equals
/// `14.0.0`.
#[derive(Clone, Debug)]
pub struct DottedVersion(Vec<u32>);

impl PartialEq for DottedVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for DottedVersion {}

impl DottedVersion {
    /// Parses a whole canonical version (policy input): digits and dots only.
    #[must_use]
    pub fn parse_strict(value: &str) -> Option<Self> {
        if value.is_empty() || value.len() > MAX_VERSION_LEN {
            return None;
        }
        let parts = value
            .split('.')
            .map(parse_component)
            .collect::<Option<Vec<_>>>()?;
        (parts.len() <= MAX_COMPONENTS).then_some(Self(parts))
    }

    /// Parses the leading dotted number of a reported version, ignoring any suffix.
    #[must_use]
    pub fn parse_prefix(value: &str) -> Option<Self> {
        if value.len() > MAX_VERSION_LEN {
            return None;
        }
        let value = value.trim().trim_start_matches(['v', 'V']);
        let end = value
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(value.len());
        let prefix = value[..end].trim_end_matches('.');
        let parts = prefix
            .split('.')
            .take(MAX_COMPONENTS)
            .map(parse_component)
            .collect::<Option<Vec<_>>>()?;
        Some(Self(parts))
    }

    /// The canonical string form (`14.5`).
    #[must_use]
    pub fn canonical(&self) -> String {
        self.0
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }

    fn component(&self, index: usize) -> u32 {
        self.0.get(index).copied().unwrap_or(0)
    }
}

impl Ord for DottedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let len = self.0.len().max(other.0.len());
        (0..len)
            .map(|i| self.component(i).cmp(&other.component(i)))
            .find(|o| o.is_ne())
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for DottedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn parse_component(part: &str) -> Option<u32> {
    if part.is_empty() || part.len() > 5 || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse().ok().filter(|n| *n <= MAX_COMPONENT)
}

/// Whether `actual` meets `minimum`. `None` when `actual` cannot be parsed.
#[must_use]
pub fn dotted_meets_minimum(minimum: &DottedVersion, actual: &str) -> Option<bool> {
    DottedVersion::parse_prefix(actual).map(|actual| actual >= *minimum)
}

/// Parses a client version (semver, a leading `v` allowed).
#[must_use]
pub fn parse_client_version(value: &str) -> Option<Version> {
    if value.len() > MAX_VERSION_LEN {
        return None;
    }
    Version::parse(value.trim().trim_start_matches('v')).ok()
}

/// Whether `actual` is at least `minimum`, comparing `major.minor.patch` only.
#[must_use]
pub fn client_meets_minimum(minimum: &Version, actual: &Version) -> bool {
    (actual.major, actual.minor, actual.patch) >= (minimum.major, minimum.minor, minimum.patch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> DottedVersion {
        DottedVersion::parse_strict(s).unwrap()
    }

    #[test]
    fn strict_parsing() {
        assert_eq!(v("14.5").canonical(), "14.5");
        assert_eq!(v("10.0.22631.4317").canonical(), "10.0.22631.4317");
        assert_eq!(v("007").canonical(), "7");
        for bad in [
            "",
            "14.",
            ".14",
            "14..5",
            "a",
            "14.5-beta",
            "1.2.3.4.5",
            "100000",
            "-1",
            " 14",
            "14 ",
            "1e3",
        ] {
            assert!(DottedVersion::parse_strict(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn prefix_parsing_ignores_suffixes() {
        let parse = |s| DottedVersion::parse_prefix(s).map(|v| v.canonical());
        assert_eq!(parse("6.8.0-45-generic").as_deref(), Some("6.8.0"));
        assert_eq!(parse("14.5 (23F79)").as_deref(), Some("14.5"));
        assert_eq!(parse("v2.1").as_deref(), Some("2.1"));
        assert_eq!(parse("24.04").as_deref(), Some("24.4"));
        assert_eq!(
            parse("10.0.22631.4317.9").as_deref(),
            Some("10.0.22631.4317")
        );
        assert_eq!(parse("6.").as_deref(), Some("6"));
        assert!(parse("rolling").is_none());
        assert!(parse("").is_none());
        assert!(parse(&"9".repeat(100)).is_none());
    }

    #[test]
    fn comparisons() {
        assert!(v("14") == v("14.0.0"));
        assert!(v("14.5") > v("14.4.9"));
        assert!(v("6.10") > v("6.9"), "numeric, not lexical");
        assert!(v("10.0.22000") > v("10.0.19045"));
        assert_eq!(
            dotted_meets_minimum(&v("6.1"), "6.8.0-45-generic"),
            Some(true)
        );
        assert_eq!(dotted_meets_minimum(&v("6.10"), "6.9.12"), Some(false));
        assert_eq!(dotted_meets_minimum(&v("14"), "14.0"), Some(true));
        assert_eq!(dotted_meets_minimum(&v("14"), "13.6.7"), Some(false));
        assert_eq!(dotted_meets_minimum(&v("14"), "garbage"), None);
    }

    #[test]
    fn client_versions() {
        let min = parse_client_version("2.2.0").unwrap();
        assert!(client_meets_minimum(
            &min,
            &parse_client_version("2.2.0").unwrap()
        ));
        assert!(client_meets_minimum(
            &min,
            &parse_client_version("v2.10.1").unwrap()
        ));
        assert!(client_meets_minimum(
            &min,
            &parse_client_version("2.2.0-beta1").unwrap()
        ));
        assert!(!client_meets_minimum(
            &min,
            &parse_client_version("2.1.9").unwrap()
        ));
        assert!(parse_client_version("2.2").is_none());
        assert!(parse_client_version("latest").is_none());
    }
}
