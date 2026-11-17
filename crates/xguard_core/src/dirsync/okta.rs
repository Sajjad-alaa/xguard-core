//! Okta through its management API.
//!
//! - **Auth:** OAuth client credentials with a private key JWT (RFC 7523) for an API service app
//!   granted `okta.users.read` and `okta.groups.read`, against the org authorization server
//!   (`{org}/oauth2/v1/token`). DPoP-bound tokens are not supported, so the app must not require
//!   DPoP.
//! - **Users:** `GET /api/v1/users`, plus the deprovisioned ones, which the plain listing leaves
//!   out. Suspended and deprovisioned users count as disabled.
//! - **Groups:** `GET /api/v1/groups` and `/api/v1/groups/{id}/users`.
//! - **Paging:** `Link: <…>; rel="next"`, followed only on the Okta org's host.

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand::{Rng, distributions::Alphanumeric, rngs::OsRng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    DirSyncError, DirectoryUser, GroupRef,
    http::{Pager, join, next_link, send_json},
    valid_id,
};

const SCOPES: &str = "okta.users.read okta.groups.read";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ASSERTION_LIFETIME_SECS: i64 = 300;
const PAGE_SIZE: &str = "200";
const DISABLED_STATUSES: [&str; 2] = ["SUSPENDED", "DEPROVISIONED"];

pub struct OktaCredentials {
    /// The org URL, such as `https://example.okta.com/`.
    pub base: Url,
    pub client_id: String,
    /// PKCS#1 DER.
    pub private_key: Vec<u8>,
    pub key_id: Option<String>,
}

pub struct OktaClient {
    http: Client,
    base: Url,
    token: String,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    jti: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    email: Option<String>,
    login: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    mobile_phone: Option<String>,
}

#[derive(Deserialize)]
struct User {
    id: String,
    status: Option<String>,
    profile: Option<Profile>,
}

#[derive(Deserialize)]
struct GroupProfile {
    name: Option<String>,
}

#[derive(Deserialize)]
struct Group {
    id: String,
    profile: Option<GroupProfile>,
}

/// The org URL from the issuer: the scheme and host (custom authorization servers live under
/// `/oauth2/…`, but the management API is on the org).
pub(crate) fn org_base(issuer: &Url) -> Url {
    let mut base = issuer.clone();
    base.set_path("/");
    base.set_query(None);
    base.set_fragment(None);
    base
}

fn user(user: User) -> Option<DirectoryUser> {
    if !valid_id(&user.id) {
        return None;
    }
    let profile = user.profile.unwrap_or(Profile {
        email: None,
        login: None,
        first_name: None,
        last_name: None,
        mobile_phone: None,
    });
    let active = !user
        .status
        .as_deref()
        .is_some_and(|status| DISABLED_STATUSES.contains(&status));
    Some(DirectoryUser {
        id: user.id,
        email: profile
            .email
            .or_else(|| profile.login.filter(|login| login.contains('@'))),
        first_name: profile.first_name,
        last_name: profile.last_name,
        phone: profile.mobile_phone.filter(|phone| !phone.is_empty()),
        active,
    })
}

impl OktaClient {
    pub async fn connect(
        http: Client,
        credentials: &OktaCredentials,
    ) -> Result<Self, DirSyncError> {
        let token_url = join(&credentials.base, &["oauth2", "v1", "token"]);
        let now = chrono::Utc::now().timestamp();
        let jti: String = OsRng
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        let claims = Claims {
            iss: &credentials.client_id,
            sub: &credentials.client_id,
            aud: token_url.as_str(),
            iat: now,
            exp: now + ASSERTION_LIFETIME_SECS,
            jti,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid.clone_from(&credentials.key_id);
        let assertion = jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_der(&credentials.private_key),
        )
        .map_err(|err| DirSyncError::Auth(format!("signing the token request failed: {err}")))?;
        let request = http.post(token_url).form(&[
            ("grant_type", "client_credentials"),
            ("scope", SCOPES),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", &assertion),
        ]);
        let (token, _): (TokenResponse, _) = send_json(request, "Okta token request")
            .await
            .map_err(DirSyncError::into_auth)?;
        if token
            .token_type
            .as_deref()
            .is_some_and(|kind| !kind.eq_ignore_ascii_case("bearer"))
        {
            return Err(DirSyncError::Auth(
                "Okta issued a DPoP-bound token; turn off \"Require DPoP\" for the sync app".into(),
            ));
        }
        Ok(Self {
            http,
            base: credentials.base.clone(),
            token: token.access_token,
        })
    }

    async fn list<T: serde::de::DeserializeOwned, U>(
        &self,
        mut url: Url,
        what: &'static str,
        mut map: impl FnMut(T) -> Option<U>,
    ) -> Result<Vec<U>, DirSyncError> {
        let mut pager = Pager::new(what);
        loop {
            let request = self
                .http
                .get(url)
                .bearer_auth(&self.token)
                .header(reqwest::header::ACCEPT, "application/json");
            let (page, headers): (Vec<T>, _) =
                send_json(request, &format!("listing Okta {what}")).await?;
            pager.add(page.into_iter().filter_map(&mut map))?;
            match next_link(&headers, &self.base)? {
                Some(next) => url = next,
                None => return Ok(pager.items),
            }
        }
    }

    pub async fn users(&self) -> Result<Vec<DirectoryUser>, DirSyncError> {
        let mut url = join(&self.base, &["api", "v1", "users"]);
        url.query_pairs_mut().append_pair("limit", PAGE_SIZE);
        let mut users = self.list(url.clone(), "users", user).await?;
        url.query_pairs_mut()
            .append_pair("filter", "status eq \"DEPROVISIONED\"");
        let deprovisioned = self.list(url, "users", user).await?;
        let known: std::collections::HashSet<String> = users.iter().map(|u| u.id.clone()).collect();
        users.extend(deprovisioned.into_iter().filter(|u| !known.contains(&u.id)));
        Ok(users)
    }

    pub async fn groups(&self) -> Result<Vec<GroupRef>, DirSyncError> {
        let mut url = join(&self.base, &["api", "v1", "groups"]);
        url.query_pairs_mut().append_pair("limit", PAGE_SIZE);
        self.list(url, "groups", |group: Group| {
            let name = group.profile?.name?;
            valid_id(&group.id).then_some(GroupRef { id: group.id, name })
        })
        .await
    }

    pub async fn members(&self, group: &GroupRef) -> Result<Vec<String>, DirSyncError> {
        let mut url = join(&self.base, &["api", "v1", "groups", &group.id, "users"]);
        url.query_pairs_mut().append_pair("limit", PAGE_SIZE);
        self.list(url, "group members", |user: User| Some(user.id))
            .await
    }
}
