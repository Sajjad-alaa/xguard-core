//! JumpCloud through its v1 and v2 APIs.
//!
//! - **Auth:** an API key in the `x-api-key` header (a read-only admin's key is enough).
//! - **Users:** `GET /api/systemusers`; suspended users count as disabled.
//! - **Groups:** `GET /api/v2/usergroups`, members through `/api/v2/usergroups/{id}/membership`,
//!   which resolves nested groups to users.
//! - **Paging:** `limit` and `skip`, until a page comes back short.
//! - **Region:** the EU or India console (`console.eu.jumpcloud.com`, `console.in.jumpcloud.com`)
//!   when the issuer is in that region.

use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{
    DirSyncError, DirectoryUser, GroupRef,
    http::{Pager, join, send_json},
    valid_id,
};

pub const API_BASE: &str = "https://console.jumpcloud.com/";
pub const EU_API_BASE: &str = "https://console.eu.jumpcloud.com/";
pub const IN_API_BASE: &str = "https://console.in.jumpcloud.com/";
const API_KEY_HEADER: &str = "x-api-key";
const PAGE_SIZE: usize = 100;

pub struct JumpCloudCredentials {
    pub api_key: String,
    pub base: Url,
}

pub struct JumpCloudClient {
    http: Client,
    base: Url,
    api_key: String,
}

#[derive(Deserialize)]
struct UsersPage {
    #[serde(default)]
    results: Vec<User>,
}

#[derive(Deserialize)]
struct User {
    #[serde(rename = "_id")]
    id: String,
    email: Option<String>,
    firstname: Option<String>,
    lastname: Option<String>,
    #[serde(default)]
    suspended: bool,
    state: Option<String>,
}

#[derive(Deserialize)]
struct Group {
    id: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct Member {
    id: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
}

/// The console API for an issuer: the EU or India one for `*.eu.*` and `*.in.*` issuers.
pub(crate) fn api_base_for(issuer: &str) -> &'static str {
    let host = Url::parse(issuer)
        .ok()
        .and_then(|url| url.host_str().map(str::to_lowercase))
        .unwrap_or_default();
    if host.contains(".eu.") {
        EU_API_BASE
    } else if host.contains(".in.") {
        IN_API_BASE
    } else {
        API_BASE
    }
}

impl JumpCloudClient {
    #[must_use]
    pub fn new(http: Client, credentials: &JumpCloudCredentials) -> Self {
        Self {
            http,
            base: credentials.base.clone(),
            api_key: credentials.api_key.clone(),
        }
    }

    /// Reads pages of `limit`/`skip` until one is short.
    async fn list<P: serde::de::DeserializeOwned, U>(
        &self,
        url: Url,
        what: &'static str,
        mut items: impl FnMut(P) -> Vec<U>,
        page_len: impl Fn(&[U]) -> usize,
    ) -> Result<Vec<U>, DirSyncError> {
        let mut pager = Pager::new(what);
        let mut skip = 0;
        loop {
            let request = self
                .http
                .get(url.clone())
                .header(API_KEY_HEADER, &self.api_key)
                .header(reqwest::header::ACCEPT, "application/json")
                .query(&[("limit", PAGE_SIZE), ("skip", skip)]);
            let (page, _): (P, _) =
                send_json(request, &format!("listing JumpCloud {what}")).await?;
            let page = items(page);
            let len = page_len(&page);
            pager.add(page)?;
            if len < PAGE_SIZE {
                return Ok(pager.items);
            }
            skip += PAGE_SIZE;
        }
    }

    /// Checks the key with one small request.
    pub async fn check(&self) -> Result<(), DirSyncError> {
        let request = self
            .http
            .get(join(&self.base, &["api", "systemusers"]))
            .header(API_KEY_HEADER, &self.api_key)
            .query(&[("limit", 1)]);
        send_json::<UsersPage>(request, "JumpCloud API key check")
            .await
            .map(|_| ())
            .map_err(DirSyncError::into_auth)
    }

    pub async fn users(&self) -> Result<Vec<DirectoryUser>, DirSyncError> {
        let url = join(&self.base, &["api", "systemusers"]);
        let users: Vec<Option<DirectoryUser>> = self
            .list(
                url,
                "users",
                |page: UsersPage| {
                    page.results
                        .into_iter()
                        .map(|user| {
                            valid_id(&user.id).then(|| DirectoryUser {
                                active: !user.suspended
                                    && !user.state.as_deref().is_some_and(|state| {
                                        state.eq_ignore_ascii_case("SUSPENDED")
                                    }),
                                id: user.id,
                                email: user.email,
                                first_name: user.firstname,
                                last_name: user.lastname,
                                phone: None,
                            })
                        })
                        .collect()
                },
                <[_]>::len,
            )
            .await?;
        Ok(users.into_iter().flatten().collect())
    }

    pub async fn groups(&self) -> Result<Vec<GroupRef>, DirSyncError> {
        let url = join(&self.base, &["api", "v2", "usergroups"]);
        let groups: Vec<Option<GroupRef>> = self
            .list(
                url,
                "groups",
                |page: Vec<Group>| {
                    page.into_iter()
                        .map(|group| {
                            let name = group.name?;
                            valid_id(&group.id).then_some(GroupRef { id: group.id, name })
                        })
                        .collect()
                },
                <[_]>::len,
            )
            .await?;
        Ok(groups.into_iter().flatten().collect())
    }

    pub async fn members(&self, group: &GroupRef) -> Result<Vec<String>, DirSyncError> {
        let url = join(
            &self.base,
            &["api", "v2", "usergroups", &group.id, "membership"],
        );
        let members: Vec<Option<String>> = self
            .list(
                url,
                "group members",
                |page: Vec<Member>| {
                    page.into_iter()
                        .map(|member| {
                            (member.kind.as_deref() == Some("user"))
                                .then_some(member.id)
                                .flatten()
                        })
                        .collect()
                },
                <[_]>::len,
            )
            .await?;
        Ok(members.into_iter().flatten().collect())
    }
}
