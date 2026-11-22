//! A connection to the directory, with the few operations the sync needs.
//!
//! - Searches are paged, so large directories (and Active Directory's 1000-entry limit) work.
//! - Every value placed in a filter or DN is escaped.
//! - Passwords are only sent over LDAPS, StartTLS or to a server on this machine. OpenLDAP
//!   hashes new passwords itself (Password Modify operation); XGuard never stores or sends a
//!   hash it made.

use std::{collections::HashSet, time::Duration};

use ldap3::{
    Ldap, LdapConnAsync, LdapConnSettings, LdapError, Mod, Scope, SearchEntry,
    adapters::{Adapter, EntriesOnly, PagedResults},
    exop::PasswordModify,
    ldap_escape,
};

use super::{
    DirectoryError,
    config::DirectoryConfig,
    model::{
        AD_ACCOUNT_DISABLE, AD_NORMAL_ACCOUNT, DirectoryGroup, DirectorySnapshot, DirectoryUser,
        OPENLDAP_PERMANENT_LOCK,
    },
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const PAGE_SIZE: i32 = 500;
/// LDAP result code for a wrong password.
const INVALID_CREDENTIALS: u32 = 49;
/// LDAP result code for a missing entry.
const NO_SUCH_OBJECT: u32 = 32;
/// LDAP result codes for a value that is already (or not) present.
const ATTRIBUTE_OR_VALUE_EXISTS: u32 = 20;
const NO_SUCH_ATTRIBUTE: u32 = 16;

/// How XGuard wants a user to look in the directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserAttributes {
    pub username: String,
    pub rdn: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone: Option<String>,
}

impl UserAttributes {
    fn full_name(&self) -> String {
        format!("{} {}", self.first_name, self.last_name)
            .trim()
            .to_owned()
    }
}

fn result_code(err: &LdapError) -> Option<u32> {
    match err {
        LdapError::LdapResult { result } => Some(result.rc),
        _ => None,
    }
}

fn set(values: &[&str]) -> HashSet<Vec<u8>> {
    values
        .iter()
        .filter(|value| !value.is_empty())
        .map(|value| value.as_bytes().to_vec())
        .collect()
}

pub struct DirectoryClient {
    ldap: Ldap,
    pub config: DirectoryConfig,
}

impl DirectoryClient {
    async fn open(config: &DirectoryConfig) -> Result<Ldap, DirectoryError> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(CONNECT_TIMEOUT)
            .set_starttls(config.starttls && config.url.scheme() == "ldap")
            .set_no_tls_verify(!config.verify_tls);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, config.url.as_str()).await?;
        ldap3::drive!(conn);
        ldap.with_timeout(OPERATION_TIMEOUT);
        Ok(ldap)
    }

    /// Connects and binds with the service account.
    pub async fn connect(config: DirectoryConfig) -> Result<Self, DirectoryError> {
        let mut ldap = Self::open(&config).await?;
        if !config.is_protected() {
            warn!(
                "The directory connection to {} is not encrypted; use LDAPS or StartTLS",
                config.url
            );
        }
        ldap.simple_bind(&config.bind_dn, &config.bind_password)
            .await?
            .success()?;
        Ok(Self { ldap, config })
    }

    pub async fn close(mut self) {
        let _ = self.ldap.unbind().await;
    }

    async fn search(
        &mut self,
        base: &str,
        filter: &str,
        attrs: Vec<String>,
    ) -> Result<Vec<SearchEntry>, DirectoryError> {
        let adapters: Vec<Box<dyn Adapter<'_, String, Vec<String>>>> = vec![
            Box::new(EntriesOnly::new()),
            Box::new(PagedResults::new(PAGE_SIZE)),
        ];
        let mut stream = self
            .ldap
            .streaming_search_with(adapters, base, Scope::Subtree, filter, attrs)
            .await?;
        let mut entries = Vec::new();
        while let Some(entry) = stream.next().await? {
            entries.push(SearchEntry::construct(entry));
        }
        stream.finish().await.success()?;
        Ok(entries)
    }

    fn user_filter(&self, extra: Option<(&str, &str)>) -> String {
        let class = format!("(objectClass={})", self.config.user_class);
        match extra {
            Some((attr, value)) => format!("(&{class}({attr}={}))", ldap_escape(value)),
            None => class,
        }
    }

    /// Reads all users and groups.
    pub async fn snapshot(&mut self) -> Result<DirectorySnapshot, DirectoryError> {
        let config = self.config.clone();
        let users = self
            .search(
                &config.user_base,
                &self.user_filter(None),
                DirectoryUser::attributes(&config),
            )
            .await?
            .into_iter()
            .filter_map(|entry| DirectoryUser::from_entry(entry, &config))
            .collect();
        let groups = self
            .search(
                &config.group_base,
                &format!("(objectClass={})", config.group_class),
                DirectoryGroup::attributes(&config),
            )
            .await?
            .into_iter()
            .filter_map(|entry| DirectoryGroup::from_entry(entry, &config))
            .collect();
        Ok(DirectorySnapshot { users, groups })
    }

    async fn find_user_by(
        &mut self,
        attr: &str,
        value: &str,
    ) -> Result<Option<DirectoryUser>, DirectoryError> {
        let config = self.config.clone();
        let mut users: Vec<DirectoryUser> = self
            .search(
                &config.user_base,
                &self.user_filter(Some((attr, value))),
                DirectoryUser::attributes(&config),
            )
            .await?
            .into_iter()
            .filter_map(|entry| DirectoryUser::from_entry(entry, &config))
            .collect();
        // A login name must identify exactly one account.
        if users.len() > 1 {
            warn!(
                "{} directory users have {attr}={value}; ignoring them",
                users.len()
            );
            return Ok(None);
        }
        Ok(users.pop())
    }

    pub async fn find_user(
        &mut self,
        username: &str,
    ) -> Result<Option<DirectoryUser>, DirectoryError> {
        let attr = self.config.username_attr.clone();
        self.find_user_by(&attr, username).await
    }

    pub async fn find_user_by_email(
        &mut self,
        email: &str,
    ) -> Result<Option<DirectoryUser>, DirectoryError> {
        self.find_user_by("mail", email).await
    }

    pub async fn find_group(
        &mut self,
        name: &str,
    ) -> Result<Option<DirectoryGroup>, DirectoryError> {
        let config = self.config.clone();
        let filter = format!(
            "(&(objectClass={})({}={}))",
            config.group_class,
            config.group_name_attr,
            ldap_escape(name)
        );
        Ok(self
            .search(
                &config.group_base,
                &filter,
                DirectoryGroup::attributes(&config),
            )
            .await?
            .into_iter()
            .find_map(|entry| DirectoryGroup::from_entry(entry, &config)))
    }

    /// Checks a user's password by binding as them on a separate connection.
    ///
    /// Empty passwords are refused: LDAP treats them as an anonymous bind, which "succeeds".
    pub async fn verify_password(&self, dn: &str, password: &str) -> Result<bool, DirectoryError> {
        if password.is_empty() {
            return Ok(false);
        }
        if !self.config.is_protected() {
            return Err(DirectoryError::Insecure);
        }
        let mut ldap = Self::open(&self.config).await?;
        let result = ldap.simple_bind(dn, password).await?;
        let _ = ldap.unbind().await;
        match result.rc {
            0 => Ok(true),
            INVALID_CREDENTIALS => Ok(false),
            _ => Err(LdapError::LdapResult { result }.into()),
        }
    }

    /// Creates a user. Without a password, the account is created disabled on Active Directory,
    /// which refuses enabled accounts without one.
    pub async fn add_user(
        &mut self,
        user: &UserAttributes,
        path: Option<&str>,
        password: Option<&str>,
    ) -> Result<String, DirectoryError> {
        let config = self.config.clone();
        let dn = config.user_dn(&user.rdn, path);
        let full_name = user.full_name();
        let mut classes: Vec<&str> = vec![&config.user_class];
        classes.extend(config.user_aux_classes.iter().map(String::as_str));
        let mut attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
            (b"objectClass".to_vec(), set(&classes)),
            (
                config.username_attr.as_bytes().to_vec(),
                set(&[&user.username]),
            ),
            (
                b"sn".to_vec(),
                set(&[if user.last_name.is_empty() {
                    &user.username
                } else {
                    &user.last_name
                }]),
            ),
            (b"givenName".to_vec(), set(&[&user.first_name])),
            (b"mail".to_vec(), set(&[&user.email])),
            (
                b"mobile".to_vec(),
                set(&[user.phone.as_deref().unwrap_or_default()]),
            ),
        ];
        if !config.rdn_attr.eq_ignore_ascii_case(&config.username_attr) {
            attrs.push((config.rdn_attr.as_bytes().to_vec(), set(&[&user.rdn])));
        }
        if !config.rdn_attr.eq_ignore_ascii_case("cn") {
            attrs.push((
                b"cn".to_vec(),
                set(&[if full_name.is_empty() {
                    &user.username
                } else {
                    &full_name
                }]),
            ));
        }
        if config.is_ad {
            let control = (AD_NORMAL_ACCOUNT | AD_ACCOUNT_DISABLE).to_string();
            attrs.push((b"userAccountControl".to_vec(), set(&[&control])));
        }
        attrs.retain(|(_, values)| !values.is_empty());
        self.ldap.add(&dn, attrs).await?.success()?;
        if let Some(password) = password {
            self.set_password(&dn, password).await?;
            if config.is_ad {
                self.write_account_control(&dn, AD_NORMAL_ACCOUNT).await?;
            }
        }
        Ok(dn)
    }

    /// Brings a user's attributes in line with `wanted`, renaming the entry if its RDN changed.
    /// Returns the user's DN afterwards.
    pub async fn update_user(
        &mut self,
        current: &DirectoryUser,
        wanted: &UserAttributes,
    ) -> Result<String, DirectoryError> {
        let config = self.config.clone();
        let mut mods: Vec<Mod<Vec<u8>>> = Vec::new();
        let mut replace = |attr: &str, now: &str, want: &str| {
            if now != want {
                mods.push(Mod::Replace(attr.as_bytes().to_vec(), set(&[want])));
            }
        };
        replace("givenName", &current.first_name, &wanted.first_name);
        if !wanted.last_name.is_empty() {
            replace("sn", &current.last_name, &wanted.last_name);
        }
        replace("mail", &current.email, &wanted.email);
        replace(
            "mobile",
            current.phone.as_deref().unwrap_or_default(),
            wanted.phone.as_deref().unwrap_or_default(),
        );
        if !config.username_attr.eq_ignore_ascii_case(&config.rdn_attr) {
            replace(&config.username_attr, &current.username, &wanted.username);
        }
        let full_name = wanted.full_name();
        let names_changed =
            current.first_name != wanted.first_name || current.last_name != wanted.last_name;
        if names_changed && !full_name.is_empty() && !config.rdn_attr.eq_ignore_ascii_case("cn") {
            mods.push(Mod::Replace(b"cn".to_vec(), set(&[&full_name])));
        }
        if !mods.is_empty() {
            self.ldap.modify(&current.dn, mods).await?.success()?;
        }
        if current.rdn == wanted.rdn {
            return Ok(current.dn.clone());
        }
        let new_rdn = format!("{}={}", config.rdn_attr, ldap3::dn_escape(&wanted.rdn));
        self.ldap
            .modifydn(&current.dn, &new_rdn, true, None)
            .await?
            .success()?;
        Ok(config.user_dn(&wanted.rdn, Some(&current.path)))
    }

    /// Deletes an entry. A missing entry counts as deleted.
    pub async fn delete(&mut self, dn: &str) -> Result<(), DirectoryError> {
        match self.ldap.delete(dn).await?.success() {
            Ok(_) => Ok(()),
            Err(err) if result_code(&err) == Some(NO_SUCH_OBJECT) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn set_password(&mut self, dn: &str, password: &str) -> Result<(), DirectoryError> {
        if !self.config.is_protected() {
            return Err(DirectoryError::Insecure);
        }
        if self.config.is_ad {
            // AD takes the new password as a quoted UTF-16LE string in unicodePwd.
            let quoted: Vec<u8> = format!("\"{password}\"")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            let mods = vec![Mod::Replace(
                b"unicodePwd".to_vec(),
                HashSet::from([quoted]),
            )];
            self.ldap.modify(dn, mods).await?.success()?;
        } else {
            self.ldap
                .extended(PasswordModify {
                    user_id: Some(dn),
                    old_pass: None,
                    new_pass: Some(password),
                })
                .await?
                .success()?;
        }
        Ok(())
    }

    async fn write_account_control(&mut self, dn: &str, value: u32) -> Result<(), DirectoryError> {
        let mods = vec![Mod::Replace(
            b"userAccountControl".to_vec(),
            set(&[&value.to_string()]),
        )];
        self.ldap.modify(dn, mods).await?.success()?;
        Ok(())
    }

    /// Enables or disables an account: `userAccountControl` on Active Directory, the ppolicy
    /// lock on OpenLDAP.
    pub async fn set_disabled(
        &mut self,
        user: &DirectoryUser,
        disabled: bool,
    ) -> Result<(), DirectoryError> {
        if user.disabled == Some(disabled) {
            return Ok(());
        }
        if self.config.is_ad {
            let current = user.account_control.unwrap_or(AD_NORMAL_ACCOUNT);
            let value = if disabled {
                current | AD_ACCOUNT_DISABLE
            } else {
                current & !AD_ACCOUNT_DISABLE
            };
            return self.write_account_control(&user.dn, value).await;
        }
        let values = if disabled {
            set(&[OPENLDAP_PERMANENT_LOCK])
        } else {
            HashSet::new()
        };
        let mods = vec![Mod::Replace(b"pwdAccountLockedTime".to_vec(), values)];
        match self.ldap.modify(&user.dn, mods).await?.success() {
            Ok(_) => Ok(()),
            Err(err) if !disabled && result_code(&err) == Some(NO_SUCH_ATTRIBUTE) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Writes `value` to `attribute` of the entry `dn`, replacing what is there, or removes the
    /// attribute when `value` is `None`. Used for enrollment tokens, which are credentials, so
    /// it is only done over a protected connection.
    pub async fn write_secret_attribute(
        &mut self,
        dn: &str,
        attribute: &str,
        value: Option<&str>,
    ) -> Result<(), DirectoryError> {
        if !self.config.is_protected() {
            return Err(DirectoryError::Insecure);
        }
        let values = value.map_or_else(HashSet::new, |value| set(&[value]));
        let mods = vec![Mod::Replace(attribute.as_bytes().to_vec(), values)];
        match self.ldap.modify(dn, mods).await?.success() {
            Ok(_) => Ok(()),
            // Removing an attribute that is not there.
            Err(err) if value.is_none() && result_code(&err) == Some(NO_SUCH_ATTRIBUTE) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Reads the values of `attribute` of the entry `dn` (for tests and diagnostics).
    pub async fn read_attribute(
        &mut self,
        dn: &str,
        attribute: &str,
    ) -> Result<Vec<String>, DirectoryError> {
        let (entries, _) = self
            .ldap
            .search(dn, Scope::Base, "(objectClass=*)", vec![attribute])
            .await?
            .success()?;
        Ok(entries
            .into_iter()
            .map(SearchEntry::construct)
            .flat_map(|entry| {
                entry
                    .attrs
                    .into_iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case(attribute))
                    .flat_map(|(_, values)| values)
            })
            .collect())
    }

    /// The value that names `user` in a group's member list.
    #[must_use]
    pub fn member_value(&self, user: &DirectoryUser) -> String {
        if self.config.members_are_usernames() {
            user.username.clone()
        } else {
            user.dn.clone()
        }
    }

    pub async fn add_member(&mut self, group_dn: &str, member: &str) -> Result<(), DirectoryError> {
        let attr = self.config.group_member_attr.as_bytes().to_vec();
        let mods = vec![Mod::Add(attr, set(&[member]))];
        match self.ldap.modify(group_dn, mods).await?.success() {
            Ok(_) => Ok(()),
            Err(err) if result_code(&err) == Some(ATTRIBUTE_OR_VALUE_EXISTS) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn remove_member(
        &mut self,
        group_dn: &str,
        member: &str,
    ) -> Result<(), DirectoryError> {
        let attr = self.config.group_member_attr.as_bytes().to_vec();
        let mods = vec![Mod::Delete(attr, set(&[member]))];
        match self.ldap.modify(group_dn, mods).await?.success() {
            Ok(_) => Ok(()),
            Err(err) if result_code(&err) == Some(NO_SUCH_ATTRIBUTE) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Creates a group with its first member; most group classes need at least one.
    pub async fn create_group(
        &mut self,
        name: &str,
        first_member: &str,
    ) -> Result<String, DirectoryError> {
        let config = self.config.clone();
        let dn = config.group_dn(name);
        let mut attrs = vec![
            (b"objectClass".to_vec(), set(&[&config.group_class])),
            (config.group_name_attr.as_bytes().to_vec(), set(&[name])),
            (
                config.group_member_attr.as_bytes().to_vec(),
                set(&[first_member]),
            ),
        ];
        if config.is_ad {
            attrs.push((b"sAMAccountName".to_vec(), set(&[name])));
        }
        self.ldap.add(&dn, attrs).await?.success()?;
        Ok(dn)
    }
}
