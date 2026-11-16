//! Directory settings, checked once and turned into the values the sync works with.

use std::{net::IpAddr, time::Duration};

use ldap3::dn_escape;
use url::Url;
use xguard_common::db::models::Settings;

use super::DirectoryError;

/// Which system wins when XGuard and the directory disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    Directory,
    XGuard,
}

#[derive(Clone)]
pub struct DirectoryConfig {
    pub url: Url,
    pub bind_dn: String,
    pub bind_password: String,
    pub starttls: bool,
    pub verify_tls: bool,
    pub is_ad: bool,

    pub user_base: String,
    pub user_class: String,
    pub user_aux_classes: Vec<String>,
    pub username_attr: String,
    pub rdn_attr: String,
    /// The attribute on a user listing their groups, such as `memberOf`.
    pub member_attr: String,

    pub group_base: String,
    pub group_class: String,
    pub group_name_attr: String,
    /// The attribute on a group listing its members, such as `member` or `memberUid`.
    pub group_member_attr: String,

    /// When not empty, only members of these groups are synced.
    pub sync_groups: Vec<String>,
    pub authority: Authority,
    pub sync_account_status: bool,
    /// Push XGuard changes to the directory.
    pub integration_enabled: bool,
    /// Also pull directory changes at [`Self::sync_interval`].
    pub two_way: bool,
    pub sync_interval: Duration,
}

impl std::fmt::Debug for DirectoryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryConfig")
            .field("url", &self.url.as_str())
            .field("bind_dn", &self.bind_dn)
            .field("user_base", &self.user_base)
            .field("group_base", &self.group_base)
            .finish_non_exhaustive()
    }
}

/// The shortest allowed sync interval; anything lower would hammer the directory.
pub const MIN_SYNC_INTERVAL: Duration = Duration::from_secs(60);

fn required(value: Option<&String>, name: &'static str) -> Result<String, DirectoryError> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(DirectoryError::NotConfigured(name))
}

fn optional(value: Option<&String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// LDAP attribute names: a letter, then letters, digits and hyphens (RFC 4512), or an OID.
fn valid_attribute(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {
            chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
        }
        Some(first) if first.is_ascii_digit() => name
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())),
        _ => false,
    }
}

impl DirectoryConfig {
    pub fn from_settings(settings: &Settings) -> Result<Self, DirectoryError> {
        let url = required(settings.ldap_url.as_ref(), "server URL")?;
        let url = Url::parse(&url).map_err(|_| DirectoryError::Invalid("server URL".into()))?;
        if !matches!(url.scheme(), "ldap" | "ldaps") || url.host_str().is_none() {
            return Err(DirectoryError::Invalid(
                "server URL: use ldap://host or ldaps://host".into(),
            ));
        }
        let username_attr = required(settings.ldap_username_attr.as_ref(), "username attribute")?;
        let config = Self {
            url,
            bind_dn: required(settings.ldap_bind_username.as_ref(), "bind username")?,
            bind_password: settings
                .ldap_bind_password
                .as_ref()
                .map(|password| password.expose_secret().to_owned())
                .filter(|password| !password.is_empty())
                .ok_or(DirectoryError::NotConfigured("bind password"))?,
            starttls: settings.ldap_use_starttls,
            verify_tls: settings.ldap_tls_verify_cert,
            is_ad: settings.ldap_uses_ad,
            user_base: required(settings.ldap_user_search_base.as_ref(), "user search base")?,
            user_class: required(settings.ldap_user_obj_class.as_ref(), "user object class")?,
            user_aux_classes: settings
                .ldap_user_auxiliary_obj_classes
                .iter()
                .map(|class| class.trim().to_owned())
                .filter(|class| !class.is_empty())
                .collect(),
            rdn_attr: optional(settings.ldap_user_rdn_attr.as_ref())
                .unwrap_or_else(|| username_attr.clone()),
            username_attr,
            member_attr: required(settings.ldap_member_attr.as_ref(), "member attribute")?,
            group_base: required(
                settings.ldap_group_search_base.as_ref(),
                "group search base",
            )?,
            group_class: required(settings.ldap_group_obj_class.as_ref(), "group object class")?,
            group_name_attr: required(
                settings.ldap_groupname_attr.as_ref(),
                "group name attribute",
            )?,
            group_member_attr: required(
                settings.ldap_group_member_attr.as_ref(),
                "group member attribute",
            )?,
            sync_groups: settings
                .ldap_sync_groups
                .iter()
                .map(|group| group.trim().to_owned())
                .filter(|group| !group.is_empty())
                .collect(),
            authority: if settings.ldap_is_authoritative {
                Authority::Directory
            } else {
                Authority::XGuard
            },
            sync_account_status: settings.ldap_sync_account_status,
            integration_enabled: settings.ldap_enabled,
            two_way: settings.ldap_enabled && settings.ldap_sync_enabled,
            sync_interval: Duration::from_secs(
                u64::try_from(settings.ldap_sync_interval).unwrap_or_default(),
            )
            .max(MIN_SYNC_INTERVAL),
        };
        for (attribute, name) in [
            (&config.username_attr, "username attribute"),
            (&config.rdn_attr, "user RDN attribute"),
            (&config.member_attr, "member attribute"),
            (&config.group_name_attr, "group name attribute"),
            (&config.group_member_attr, "group member attribute"),
            (&config.user_class, "user object class"),
            (&config.group_class, "group object class"),
        ] {
            if !valid_attribute(attribute) {
                return Err(DirectoryError::Invalid(format!("{name} \"{attribute}\"")));
            }
        }
        if let Some(class) = config
            .user_aux_classes
            .iter()
            .find(|class| !valid_attribute(class))
        {
            return Err(DirectoryError::Invalid(format!(
                "additional user object class \"{class}\""
            )));
        }
        Ok(config)
    }

    /// Whether the connection is encrypted, or stays on this machine.
    ///
    /// Passwords are only sent over such connections.
    #[must_use]
    pub fn is_protected(&self) -> bool {
        if self.url.scheme() == "ldaps" || self.starttls {
            return true;
        }
        // `ldap://` is not a "special" URL scheme, so the url crate reports IP addresses as
        // domain names; parse the host text instead.
        let Some(host) = self.url.host_str() else {
            return false;
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }

    /// Members of groups that list usernames (`memberUid`) rather than DNs.
    #[must_use]
    pub fn members_are_usernames(&self) -> bool {
        self.group_member_attr.eq_ignore_ascii_case("memberUid")
    }

    #[must_use]
    pub fn user_dn(&self, rdn_value: &str, path: Option<&str>) -> String {
        format!(
            "{}={},{}",
            self.rdn_attr,
            dn_escape(rdn_value),
            path.filter(|path| !path.is_empty())
                .unwrap_or(&self.user_base)
        )
    }

    #[must_use]
    pub fn group_dn(&self, name: &str) -> String {
        format!(
            "{}={},{}",
            self.group_name_attr,
            dn_escape(name),
            self.group_base
        )
    }

    /// Whether a group with this name limits the sync scope.
    #[must_use]
    pub fn is_sync_group(&self, name: &str) -> bool {
        self.sync_groups
            .iter()
            .any(|group| group.eq_ignore_ascii_case(name))
    }
}

#[cfg(test)]
pub(super) fn test_config() -> DirectoryConfig {
    DirectoryConfig {
        url: Url::parse("ldap://localhost:389").unwrap(),
        bind_dn: "cn=admin,dc=example,dc=org".into(),
        bind_password: "pass123".into(),
        starttls: false,
        verify_tls: true,
        is_ad: false,
        user_base: "ou=users,dc=example,dc=org".into(),
        user_class: "inetOrgPerson".into(),
        user_aux_classes: vec!["simpleSecurityObject".into()],
        username_attr: "uid".into(),
        rdn_attr: "uid".into(),
        member_attr: "memberOf".into(),
        group_base: "ou=groups,dc=example,dc=org".into(),
        group_class: "groupOfUniqueNames".into(),
        group_name_attr: "cn".into(),
        group_member_attr: "uniqueMember".into(),
        sync_groups: Vec::new(),
        authority: Authority::Directory,
        sync_account_status: false,
        integration_enabled: true,
        two_way: true,
        sync_interval: MIN_SYNC_INTERVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::{test_config, valid_attribute};

    #[test]
    fn attribute_names() {
        for good in ["uid", "sAMAccountName", "x-custom-1", "2.5.4.3"] {
            assert!(valid_attribute(good), "{good}");
        }
        for bad in ["", "1uid", "u id", "uid)(x", "uid=", "2.5..3", "*"] {
            assert!(!valid_attribute(bad), "{bad}");
        }
    }

    #[test]
    fn dns_are_escaped() {
        let config = test_config();
        assert_eq!(
            config.user_dn("Smith, John", None),
            "uid=Smith\\2c John,ou=users,dc=example,dc=org"
        );
        assert_eq!(
            config.user_dn("jdoe", Some("ou=sales,dc=example,dc=org")),
            "uid=jdoe,ou=sales,dc=example,dc=org"
        );
        assert_eq!(
            config.group_dn("ops+admins"),
            "cn=ops\\2badmins,ou=groups,dc=example,dc=org"
        );
    }

    #[test]
    fn plaintext_is_only_trusted_on_loopback() {
        let mut config = test_config();
        assert!(config.is_protected());
        config.url = url::Url::parse("ldap://ldap.example.org").unwrap();
        assert!(!config.is_protected());
        config.starttls = true;
        assert!(config.is_protected());
        config.starttls = false;
        config.url = url::Url::parse("ldaps://ldap.example.org").unwrap();
        assert!(config.is_protected());
        for local in ["ldap://127.0.0.1:3389", "ldap://[::1]", "ldap://LOCALHOST"] {
            config.url = url::Url::parse(local).unwrap();
            assert!(config.is_protected(), "{local}");
        }
        config.url = url::Url::parse("ldap://127.0.0.1.evil.example").unwrap();
        assert!(!config.is_protected());
    }
}
