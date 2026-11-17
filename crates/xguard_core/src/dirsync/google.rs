//! Google Workspace through the Admin SDK Directory API.
//!
//! - **Auth:** a service account with domain-wide delegation. XGuard signs a JWT (RS256) as the
//!   service account for the admin in `admin_email` and trades it for an access token
//!   (RFC 7523). The service account needs the read-only user and group scopes.
//! - **Users:** `GET /admin/directory/v1/users?customer=my_customer`, suspended and archived
//!   users count as disabled.
//! - **Groups:** `GET /admin/directory/v1/groups?customer=my_customer`, members with nested
//!   groups expanded (`includeDerivedMembership`).
//! - **Paging:** `pageToken`/`nextPageToken`.

use std::collections::HashSet;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    DirSyncError, DirectoryUser, GroupRef,
    http::{Pager, join, send_json},
    valid_id,
};

pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const API_BASE: &str = "https://admin.googleapis.com/admin/directory/v1/";
pub const SCOPES: &str = "https://www.googleapis.com/auth/admin.directory.user.readonly \
                          https://www.googleapis.com/auth/admin.directory.group.readonly";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const TOKEN_LIFETIME_SECS: i64 = 3600;

pub struct GoogleCredentials {
    pub service_account_email: String,
    /// PKCS#1 DER.
    pub private_key: Vec<u8>,
    pub admin_email: String,
    pub token_url: Url,
    pub api_base: Url,
}

pub struct GoogleClient {
    http: Client,
    api_base: Url,
    token: String,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserName {
    given_name: Option<String>,
    family_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    primary_email: Option<String>,
    name: Option<UserName>,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    archived: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsersPage {
    #[serde(default)]
    users: Vec<User>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct Group {
    id: String,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupsPage {
    #[serde(default)]
    groups: Vec<Group>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct Member {
    id: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MembersPage {
    #[serde(default)]
    members: Vec<Member>,
    next_page_token: Option<String>,
}

impl GoogleClient {
    pub async fn connect(
        http: Client,
        credentials: &GoogleCredentials,
    ) -> Result<Self, DirSyncError> {
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            iss: &credentials.service_account_email,
            sub: &credentials.admin_email,
            scope: SCOPES,
            aud: credentials.token_url.as_str(),
            iat: now,
            exp: now + TOKEN_LIFETIME_SECS,
        };
        let assertion = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_der(&credentials.private_key),
        )
        .map_err(|err| DirSyncError::Auth(format!("signing the token request failed: {err}")))?;
        let request = http
            .post(credentials.token_url.clone())
            .form(&[("grant_type", GRANT_TYPE), ("assertion", &assertion)]);
        let (token, _): (TokenResponse, _) = send_json(request, "Google token request")
            .await
            .map_err(DirSyncError::into_auth)?;
        Ok(Self {
            http,
            api_base: credentials.api_base.clone(),
            token: token.access_token,
        })
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        url: Url,
        query: &[(&str, &str)],
        page_token: Option<&str>,
        what: &str,
    ) -> Result<T, DirSyncError> {
        let mut request = self.http.get(url).bearer_auth(&self.token).query(query);
        if let Some(token) = page_token {
            request = request.query(&[("pageToken", token)]);
        }
        Ok(send_json(request, what).await?.0)
    }

    pub async fn users(&self) -> Result<Vec<DirectoryUser>, DirSyncError> {
        let url = join(&self.api_base, &["users"]);
        let mut pager = Pager::new("users");
        let mut seen_tokens = HashSet::new();
        let mut page_token: Option<String> = None;
        loop {
            let page: UsersPage = self
                .get(
                    url.clone(),
                    &[
                        ("customer", "my_customer"),
                        ("maxResults", "500"),
                        ("projection", "basic"),
                    ],
                    page_token.as_deref(),
                    "listing Google users",
                )
                .await?;
            pager.add(
                page.users
                    .into_iter()
                    .filter(|u| valid_id(&u.id))
                    .map(|user| {
                        let name = user.name.unwrap_or(UserName {
                            given_name: None,
                            family_name: None,
                        });
                        DirectoryUser {
                            id: user.id,
                            email: user.primary_email,
                            first_name: name.given_name,
                            last_name: name.family_name,
                            phone: None,
                            active: !user.suspended && !user.archived,
                        }
                    }),
            )?;
            match page.next_page_token.filter(|token| !token.is_empty()) {
                Some(token) if seen_tokens.insert(token.clone()) => page_token = Some(token),
                Some(_) => return Err(DirSyncError::Http("Google repeated a page token".into())),
                None => return Ok(pager.items),
            }
        }
    }

    pub async fn groups(&self) -> Result<Vec<GroupRef>, DirSyncError> {
        let url = join(&self.api_base, &["groups"]);
        let mut pager = Pager::new("groups");
        let mut seen_tokens = HashSet::new();
        let mut page_token: Option<String> = None;
        loop {
            let page: GroupsPage = self
                .get(
                    url.clone(),
                    &[("customer", "my_customer"), ("maxResults", "200")],
                    page_token.as_deref(),
                    "listing Google groups",
                )
                .await?;
            pager.add(
                page.groups
                    .into_iter()
                    .filter(|g| valid_id(&g.id))
                    .filter_map(|group| {
                        let name = group.name.or(group.email)?;
                        Some(GroupRef { id: group.id, name })
                    }),
            )?;
            match page.next_page_token.filter(|token| !token.is_empty()) {
                Some(token) if seen_tokens.insert(token.clone()) => page_token = Some(token),
                Some(_) => return Err(DirSyncError::Http("Google repeated a page token".into())),
                None => return Ok(pager.items),
            }
        }
    }

    pub async fn members(&self, group: &GroupRef) -> Result<Vec<String>, DirSyncError> {
        let url = join(&self.api_base, &["groups", &group.id, "members"]);
        let mut pager = Pager::new("group members");
        let mut seen_tokens = HashSet::new();
        let mut page_token: Option<String> = None;
        loop {
            let page: MembersPage = self
                .get(
                    url.clone(),
                    &[("maxResults", "200"), ("includeDerivedMembership", "true")],
                    page_token.as_deref(),
                    "listing Google group members",
                )
                .await?;
            pager.add(page.members.into_iter().filter_map(|member| {
                (member.kind.as_deref() == Some("USER"))
                    .then_some(member.id)
                    .flatten()
            }))?;
            match page.next_page_token.filter(|token| !token.is_empty()) {
                Some(token) if seen_tokens.insert(token.clone()) => page_token = Some(token),
                Some(_) => return Err(DirSyncError::Http("Google repeated a page token".into())),
                None => return Ok(pager.items),
            }
        }
    }
}
