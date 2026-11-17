//! Microsoft Entra ID through Microsoft Graph.
//!
//! - **Auth:** the client credentials grant with the sign-in app's client ID and secret, for
//!   the tenant in the issuer URL. The app needs the `User.Read.All` and `GroupMember.Read.All`
//!   application permissions.
//! - **Users:** `GET /v1.0/users` (`accountEnabled` false counts as disabled).
//! - **Groups:** `GET /v1.0/groups`, members through `transitiveMembers`, so nested groups count.
//! - **Paging:** `$top=999`, then `@odata.nextLink`, followed only on the Graph host.

use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{
    DirSyncError, DirectoryUser, GroupRef,
    http::{Pager, checked_next, join, send_json},
    valid_id,
};

pub const LOGIN_BASE: &str = "https://login.microsoftonline.com/";
pub const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0/";
const SCOPE: &str = "https://graph.microsoft.com/.default";
const PAGE_SIZE: &str = "999";
const USER_FIELDS: &str = "id,mail,userPrincipalName,givenName,surname,accountEnabled,mobilePhone";

pub struct MicrosoftCredentials {
    pub tenant: String,
    pub client_id: String,
    pub client_secret: String,
    pub login_base: Url,
    pub graph_base: Url,
}

pub struct MicrosoftClient {
    http: Client,
    graph_base: Url,
    token: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct Page<T> {
    #[serde(default = "Vec::new")]
    value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    mail: Option<String>,
    user_principal_name: Option<String>,
    given_name: Option<String>,
    surname: Option<String>,
    account_enabled: Option<bool>,
    mobile_phone: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Group {
    id: String,
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct Member {
    id: Option<String>,
    #[serde(rename = "@odata.type")]
    kind: Option<String>,
}

impl MicrosoftClient {
    pub async fn connect(
        http: Client,
        credentials: &MicrosoftCredentials,
    ) -> Result<Self, DirSyncError> {
        let token_url = join(
            &credentials.login_base,
            &[&credentials.tenant, "oauth2", "v2.0", "token"],
        );
        let request = http.post(token_url).form(&[
            ("grant_type", "client_credentials"),
            ("client_id", credentials.client_id.as_str()),
            ("client_secret", credentials.client_secret.as_str()),
            ("scope", SCOPE),
        ]);
        let (token, _): (TokenResponse, _) = send_json(request, "Microsoft token request")
            .await
            .map_err(DirSyncError::into_auth)?;
        Ok(Self {
            http,
            graph_base: credentials.graph_base.clone(),
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
            let request = self.http.get(url).bearer_auth(&self.token);
            let (page, _): (Page<T>, _) =
                send_json(request, &format!("listing Microsoft {what}")).await?;
            pager.add(page.value.into_iter().filter_map(&mut map))?;
            match page.next_link {
                Some(next) => {
                    let next = Url::parse(&next)
                        .map_err(|_| DirSyncError::Http("the paging link is not valid".into()))?;
                    url = checked_next(next, &self.graph_base)?;
                }
                None => return Ok(pager.items),
            }
        }
    }

    pub async fn users(&self) -> Result<Vec<DirectoryUser>, DirSyncError> {
        let mut url = join(&self.graph_base, &["users"]);
        url.query_pairs_mut()
            .append_pair("$select", USER_FIELDS)
            .append_pair("$top", PAGE_SIZE);
        self.list(url, "users", |user: User| {
            if !valid_id(&user.id) {
                return None;
            }
            let email = user.mail.filter(|mail| !mail.is_empty()).or_else(|| {
                user.user_principal_name
                    .filter(|upn| upn.contains('@') && !upn.contains("#EXT#"))
            });
            Some(DirectoryUser {
                id: user.id,
                email,
                first_name: user.given_name,
                last_name: user.surname,
                phone: user.mobile_phone.filter(|phone| !phone.is_empty()),
                active: user.account_enabled.unwrap_or(true),
            })
        })
        .await
    }

    pub async fn groups(&self) -> Result<Vec<GroupRef>, DirSyncError> {
        let mut url = join(&self.graph_base, &["groups"]);
        url.query_pairs_mut()
            .append_pair("$select", "id,displayName")
            .append_pair("$top", PAGE_SIZE);
        self.list(url, "groups", |group: Group| {
            let name = group.display_name?;
            valid_id(&group.id).then_some(GroupRef { id: group.id, name })
        })
        .await
    }

    pub async fn members(&self, group: &GroupRef) -> Result<Vec<String>, DirSyncError> {
        let mut url = join(
            &self.graph_base,
            &["groups", &group.id, "transitiveMembers"],
        );
        url.query_pairs_mut()
            .append_pair("$select", "id")
            .append_pair("$top", PAGE_SIZE);
        self.list(url, "group members", |member: Member| {
            (member.kind.as_deref() == Some("#microsoft.graph.user"))
                .then_some(member.id)
                .flatten()
        })
        .await
    }
}
