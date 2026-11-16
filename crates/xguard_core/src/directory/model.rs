//! Users and groups as the directory sees them.

use std::collections::{BTreeSet, HashMap};

use ldap3::SearchEntry;

use super::config::DirectoryConfig;

/// Active Directory: `userAccountControl` flag for a disabled account.
pub const AD_ACCOUNT_DISABLE: u32 = 0x2;
/// Active Directory: a normal account, the value for newly created users.
pub const AD_NORMAL_ACCOUNT: u32 = 0x200;
/// OpenLDAP ppolicy: this lock time means "locked until an administrator unlocks".
pub const OPENLDAP_PERMANENT_LOCK: &str = "000001010000Z";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryUser {
    pub dn: String,
    pub username: String,
    /// The value of the RDN attribute (the first part of the DN).
    pub rdn: String,
    /// The DN of the entry's parent.
    pub path: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone: Option<String>,
    /// `None` when the directory has no account status for this user.
    pub disabled: Option<bool>,
    /// `userAccountControl` on Active Directory, kept so status changes only touch one flag.
    pub account_control: Option<u32>,
    /// Lower-cased DNs of the groups listed on the user (`memberOf`).
    pub member_of: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryGroup {
    pub dn: String,
    pub name: String,
    /// Member values as stored: DNs, or usernames for `memberUid`.
    pub members: Vec<String>,
}

fn first<'a>(attrs: &'a HashMap<String, Vec<String>>, name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, values)| values.first())
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn all<'a>(attrs: &'a HashMap<String, Vec<String>>, name: &str) -> &'a [String] {
    attrs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map_or(&[], |(_, values)| values.as_slice())
}

/// The parent of `dn`, honouring escaped commas in the first RDN.
#[must_use]
pub fn parent_dn(dn: &str) -> &str {
    let bytes = dn.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b',' => return dn[i + 1..].trim_start(),
            _ => i += 1,
        }
    }
    ""
}

/// The value of the first RDN of `dn`, unescaped, if its attribute is `attr`.
#[must_use]
pub fn rdn_value(dn: &str, attr: &str) -> Option<String> {
    let end = dn.len() - parent_dn(dn).len();
    let rdn = dn[..end].trim_end_matches([',', ' ']);
    let (name, value) = rdn.split_once('=')?;
    if !name.trim().eq_ignore_ascii_case(attr) {
        return None;
    }
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let hex = bytes.get(i + 1..i + 3).and_then(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            });
            if let Some(byte) = hex {
                out.push(byte);
                i += 3;
            } else {
                out.push(bytes[i + 1]);
                i += 2;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

impl DirectoryUser {
    /// Attributes to read for users.
    #[must_use]
    pub fn attributes(config: &DirectoryConfig) -> Vec<String> {
        let mut attrs: Vec<String> = [
            "cn",
            "sn",
            "givenName",
            "mail",
            "mobile",
            "telephoneNumber",
            "userAccountControl",
            "pwdAccountLockedTime",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        for attr in [&config.username_attr, &config.rdn_attr, &config.member_attr] {
            if !attrs.iter().any(|known| known.eq_ignore_ascii_case(attr)) {
                attrs.push(attr.clone());
            }
        }
        attrs
    }

    /// Reads a user entry. Entries without a username are skipped.
    #[must_use]
    pub fn from_entry(entry: SearchEntry, config: &DirectoryConfig) -> Option<Self> {
        let attrs = &entry.attrs;
        let username = first(attrs, &config.username_attr)?.to_owned();
        let rdn = rdn_value(&entry.dn, &config.rdn_attr)
            .or_else(|| first(attrs, &config.rdn_attr).map(str::to_owned))
            .unwrap_or_else(|| username.clone());
        let account_control = first(attrs, "userAccountControl").and_then(|v| v.parse().ok());
        let disabled = if config.is_ad {
            account_control.map(|uac: u32| uac & AD_ACCOUNT_DISABLE != 0)
        } else {
            Some(first(attrs, "pwdAccountLockedTime").is_some())
        };
        let cn = first(attrs, "cn").unwrap_or_default();
        let last_name = first(attrs, "sn").unwrap_or(cn).to_owned();
        let first_name = first(attrs, "givenName")
            .map(str::to_owned)
            .unwrap_or_else(|| {
                cn.strip_suffix(last_name.as_str())
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .unwrap_or(cn)
                    .to_owned()
            });
        Some(Self {
            path: parent_dn(&entry.dn).to_owned(),
            dn: entry.dn.clone(),
            first_name,
            last_name,
            email: first(attrs, "mail").unwrap_or_default().to_owned(),
            phone: first(attrs, "mobile")
                .or_else(|| first(attrs, "telephoneNumber"))
                .map(str::to_owned),
            disabled,
            account_control,
            member_of: all(attrs, &config.member_attr)
                .iter()
                .map(|dn| dn.to_lowercase())
                .collect(),
            rdn,
            username,
        })
    }
}

impl DirectoryGroup {
    #[must_use]
    pub fn attributes(config: &DirectoryConfig) -> Vec<String> {
        vec![
            config.group_name_attr.clone(),
            config.group_member_attr.clone(),
        ]
    }

    #[must_use]
    pub fn from_entry(entry: SearchEntry, config: &DirectoryConfig) -> Option<Self> {
        let name = first(&entry.attrs, &config.group_name_attr)?.to_owned();
        Some(Self {
            members: all(&entry.attrs, &config.group_member_attr)
                .iter()
                .map(|member| member.trim().to_owned())
                .filter(|member| !member.is_empty())
                .collect(),
            dn: entry.dn,
            name,
        })
    }
}

/// Everything read from the directory in one pass.
#[derive(Debug, Default)]
pub struct DirectorySnapshot {
    pub users: Vec<DirectoryUser>,
    pub groups: Vec<DirectoryGroup>,
}

impl DirectorySnapshot {
    /// Group names of each user (by lower-cased username), from both group member lists and the
    /// users' own `memberOf`, so it works with and without the memberOf overlay.
    #[must_use]
    pub fn memberships(&self, config: &DirectoryConfig) -> HashMap<String, BTreeSet<String>> {
        let by_dn: HashMap<String, &DirectoryUser> = self
            .users
            .iter()
            .map(|user| (user.dn.to_lowercase(), user))
            .collect();
        let by_username: HashMap<String, &DirectoryUser> = self
            .users
            .iter()
            .map(|user| (user.username.to_lowercase(), user))
            .collect();
        let group_names: HashMap<String, &str> = self
            .groups
            .iter()
            .map(|group| (group.dn.to_lowercase(), group.name.as_str()))
            .collect();

        let mut memberships: HashMap<String, BTreeSet<String>> = self
            .users
            .iter()
            .map(|user| (user.username.to_lowercase(), BTreeSet::new()))
            .collect();
        for group in &self.groups {
            for member in &group.members {
                let user = if config.members_are_usernames() {
                    by_username.get(&member.to_lowercase())
                } else {
                    by_dn.get(&member.to_lowercase())
                };
                if let Some(user) = user {
                    memberships
                        .entry(user.username.to_lowercase())
                        .or_default()
                        .insert(group.name.clone());
                }
            }
        }
        for user in &self.users {
            for group_dn in &user.member_of {
                if let Some(name) = group_names.get(group_dn) {
                    memberships
                        .entry(user.username.to_lowercase())
                        .or_default()
                        .insert((*name).to_owned());
                }
            }
        }
        memberships
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ldap3::SearchEntry;

    use super::*;
    use crate::directory::config::test_config;

    fn entry(dn: &str, attrs: &[(&str, &[&str])]) -> SearchEntry {
        SearchEntry {
            dn: dn.into(),
            attrs: attrs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.iter().map(|s| (*s).to_owned()).collect()))
                .collect::<HashMap<_, _>>(),
            bin_attrs: HashMap::new(),
        }
    }

    #[test]
    fn dn_parts() {
        assert_eq!(parent_dn("uid=a,ou=users,dc=x"), "ou=users,dc=x");
        assert_eq!(parent_dn("cn=Smith\\, J,ou=users"), "ou=users");
        assert_eq!(parent_dn("dc=x"), "");
        assert_eq!(
            rdn_value("cn=Smith\\, J,ou=users", "CN").as_deref(),
            Some("Smith, J")
        );
        assert_eq!(rdn_value("cn=a\\2bb,ou=x", "cn").as_deref(), Some("a+b"));
        assert_eq!(rdn_value("uid=a,ou=x", "cn"), None);
    }

    #[test]
    fn reads_users_and_status() {
        let mut config = test_config();
        let user = DirectoryUser::from_entry(
            entry(
                "uid=jdoe,ou=users,dc=example,dc=org",
                &[
                    ("uid", &["jdoe"]),
                    ("cn", &["John Doe"]),
                    ("sn", &["Doe"]),
                    ("mail", &["jdoe@example.org"]),
                    ("telephoneNumber", &["123"]),
                    ("memberOf", &["cn=Ops,ou=groups,dc=example,dc=org"]),
                ],
            ),
            &config,
        )
        .unwrap();
        assert_eq!(user.username, "jdoe");
        assert_eq!(user.rdn, "jdoe");
        assert_eq!(
            (user.first_name.as_str(), user.last_name.as_str()),
            ("John", "Doe")
        );
        assert_eq!(user.phone.as_deref(), Some("123"));
        assert_eq!(user.disabled, Some(false));
        assert!(
            user.member_of
                .contains("cn=ops,ou=groups,dc=example,dc=org")
        );

        config.is_ad = true;
        config.username_attr = "sAMAccountName".into();
        config.rdn_attr = "cn".into();
        let ad = DirectoryUser::from_entry(
            entry(
                "CN=Jane Roe,OU=Staff,DC=corp",
                &[
                    ("sAMAccountName", &["jroe"]),
                    ("givenName", &["Jane"]),
                    ("sn", &["Roe"]),
                    ("userAccountControl", &["514"]),
                ],
            ),
            &config,
        )
        .unwrap();
        assert_eq!(
            (ad.username.as_str(), ad.rdn.as_str()),
            ("jroe", "Jane Roe")
        );
        assert_eq!(ad.path, "OU=Staff,DC=corp");
        assert_eq!(ad.disabled, Some(true));
        assert!(DirectoryUser::from_entry(entry("cn=x,dc=y", &[]), &config).is_none());
    }

    #[test]
    fn memberships_from_both_sides() {
        let config = test_config();
        let user = |name: &str, member_of: &[&str]| DirectoryUser {
            dn: format!("uid={name},ou=users,dc=example,dc=org"),
            username: name.into(),
            rdn: name.into(),
            path: "ou=users,dc=example,dc=org".into(),
            first_name: String::new(),
            last_name: String::new(),
            email: String::new(),
            phone: None,
            disabled: Some(false),
            account_control: None,
            member_of: member_of.iter().map(|s| s.to_lowercase()).collect(),
        };
        let snapshot = DirectorySnapshot {
            users: vec![
                user("a", &[]),
                user("b", &["cn=dev,ou=groups,dc=example,dc=org"]),
            ],
            groups: vec![
                DirectoryGroup {
                    dn: "cn=ops,ou=groups,dc=example,dc=org".into(),
                    name: "ops".into(),
                    members: vec!["UID=A,ou=users,dc=example,dc=org".into()],
                },
                DirectoryGroup {
                    dn: "cn=dev,ou=groups,dc=example,dc=org".into(),
                    name: "dev".into(),
                    members: vec![],
                },
            ],
        };
        let memberships = snapshot.memberships(&config);
        assert_eq!(memberships["a"], BTreeSet::from(["ops".to_owned()]));
        assert_eq!(memberships["b"], BTreeSet::from(["dev".to_owned()]));
    }
}
