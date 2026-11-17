//! Mock directory APIs that speak the real protocols of Google Workspace, Microsoft Graph,
//! Okta and JumpCloud: their token endpoints check the credentials the way the real ones do
//! (signed JWT assertions, client secrets, API keys), and listings are paged in each API's own
//! way. One server answers for all four, on loopback.
//!
//! Self-contained (no `crate::` paths), so the API integration tests include it too.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rsa::{
    RsaPrivateKey, pkcs8::DecodePrivateKey, traits::PrivateKeyParts, traits::PublicKeyParts,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// A throwaway RSA key, for tests only.
pub const TEST_KEY_PEM: &str = concat!(
    "-----BEGIN PRIVATE KEY-----\n",
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCHCnaKDNY4xHTp\n",
    "swGO8xinvZW5xHqgpWtzlTxfCqF2/Z8Yqj2QsV/YMIfFLRhIz5sdcS+CvgyiC6ko\n",
    "rHuHScQGeOHpxV2BKqApJcbN8dmFKQOGyllySjO7tTYAwmrI9uHNKRij50fp6UtK\n",
    "ymP3DtVHDoCXntR1Y50YvE96yEb5rb9+0v92XvEa/a28I8kUWMKCJlXuqhvIDc82\n",
    "XodQacEEi2kTXLGqQfnw+Kh+L9x4/FPxTnnR7YbYmdid9y0cta2/ShbUJsw7ULTB\n",
    "r7tpZ4/0F8T6sitbLZpBMIHnU1mANn7fXXWdd9Mbl6M05Y1nz3K37douApeZJckj\n",
    "k5AGV9G9AgMBAAECggEABEdumNKYpH/afIqcOAgNS0i/Sn2mrRnQx9QoxOeJ/5fr\n",
    "HKr4UcdtFA/68rffwcmM+WfcFjZ+IVG2myqsAg4c/1+BORkfQg00ZK66bU2Gk6jz\n",
    "Cv21ITanYQFNpBnaVw02USabjfCxigCceX2O9rB/ovAbXwfnZOOH14AlZ0HwDc/0\n",
    "gqEwTsDN6+GBWkQkGALKj9dP8XqB37nBgdT7F9eWNazKgl8mAU73i4DC77Ro4MzZ\n",
    "Yr1LlF7r0PRdFJ2UQQ2qF/wso56rPIt+qtXFbmUJs2eHkenEH1qob9VgMEPIUwtG\n",
    "ueNin0pDUCbBC/IwwlxFO37RlqKSVGtyrZ60RUw7uQKBgQC8ewS5sipDK6DsgmGT\n",
    "dQ9i+A/sXpgA+s/XqhQC9ata5NEaKdiV2hRs8E4HBEE+eoQkaDWpdcYakKq43Kbx\n",
    "TkCuWMAA3K6ZLWj2ZzLKp9kbbZNDiXB5ioHPcveVGYSTmTLjGnYCVb57kmKFj7xR\n",
    "ABDQVutDPbIvGoGb9iJatPUpkwKBgQC3aqdd2mwm5/RQAXGLJ+4UWKD/3DLkslTo\n",
    "jzCD7J3uJUZoU+csxMyNRf2+7Co1zRxyUZ8kzZZDx7TaG40bLx0/ywQh/aLpRMum\n",
    "5AIgUc/cbrJ9e/CoY+3PmAEzxazXTjP13M49SO4HcEw51G2bgVdMXLr08POrRPns\n",
    "Hw3cznzpbwKBgHfJ57LtnRabv+cQ5lsFZwYLinM7m3fj7/ytR5Kp+IIIMy1hsxlq\n",
    "RNkH0U98UMsYqqtI3/IXvBReJWLgOenbRhiIp17k4sLPrYoNBKbwDnf0KEggLa/R\n",
    "a7cg5mGImk4Ea+cShjXtsOZwntUsCQ+h7w26cEOIDpsJSZ6JzEPCBp6pAoGBAKmR\n",
    "m8wD/Er31QIGY5+gOdZrneUOAas3R5J9lv/QSK37nh0jvKzCAM53L8FL+zYkO7Fg\n",
    "zn2q58ogHo4qPIkuRJ9OpLJ8GBoK9TCEyYZxvHbxjGjApdw4DosG382qakHfVeBu\n",
    "0+kKvKz54C7yuqayrC+350w+WzgzG891Yk6KRCdXAoGBAK3dKGku12xdvDG8S2ww\n",
    "+7wctEOTk11Jm8iR3zpptBG6zSe0H/Z/T1HI5qw3EK8rhBBWG4Hoo1qwd2fnZsKL\n",
    "yLZlL3BQHDsj1ksCk93EaU4FUfCp9SByAJ6r8sxttCHZLgmJY5xSkozTKq9XF89/\n",
    "lccOEa6ea9sZli2RSFmla5jV\n",
    "-----END PRIVATE KEY-----\n",
);

pub const GOOGLE_SERVICE_ACCOUNT: &str = "sync@xguard-test.iam.gserviceaccount.com";
pub const GOOGLE_ADMIN: &str = "admin@example.org";
pub const GOOGLE_SCOPES: &str = "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.readonly";
pub const MS_TENANT: &str = "tenant-1";
pub const MS_CLIENT_ID: &str = "ms-client";
pub const MS_CLIENT_SECRET: &str = "ms-secret";
pub const OKTA_CLIENT_ID: &str = "okta-sync";
pub const OKTA_KEY_ID: &str = "k1";
pub const JUMPCLOUD_KEY: &str = "jc-key";

const GOOGLE_TOKEN: &str = "google-access-token";
const MS_TOKEN: &str = "ms-access-token";
const OKTA_TOKEN: &str = "okta-access-token";

#[must_use]
pub fn test_key() -> RsaPrivateKey {
    RsaPrivateKey::from_pkcs8_pem(TEST_KEY_PEM).unwrap()
}

/// The test key as an Okta private JWK.
#[must_use]
pub fn okta_jwk() -> String {
    let key = test_key();
    let b64 = |n: &rsa::BigUint| URL_SAFE_NO_PAD.encode(n.to_bytes_be());
    json!({
        "kty": "RSA", "kid": OKTA_KEY_ID, "alg": "RS256", "use": "sig",
        "n": b64(key.n()), "e": b64(key.e()), "d": b64(key.d()),
        "p": b64(&key.primes()[0]), "q": b64(&key.primes()[1]),
    })
    .to_string()
}

fn decoding_key() -> DecodingKey {
    let key = test_key();
    DecodingKey::from_rsa_components(
        &URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        &URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    )
    .unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Active,
    Suspended,
    /// Okta leaves these out of its plain user listing.
    Deprovisioned,
}

#[derive(Clone, Debug)]
pub struct MockUser {
    pub id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub status: Status,
}

#[derive(Clone, Debug)]
pub struct MockGroup {
    pub id: String,
    pub name: String,
    pub members: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Fixture {
    pub users: Vec<MockUser>,
    pub groups: Vec<MockGroup>,
}

impl Fixture {
    #[must_use]
    pub fn user(mut self, id: &str, email: &str, status: Status) -> Self {
        let local = email.split('@').next().unwrap_or_default();
        self.users.push(MockUser {
            id: id.into(),
            email: email.into(),
            first_name: format!("First {local}"),
            last_name: format!("Last {local}"),
            status,
        });
        self
    }

    #[must_use]
    pub fn group(mut self, id: &str, name: &str, members: &[&str]) -> Self {
        self.groups.push(MockGroup {
            id: id.into(),
            name: name.into(),
            members: members.iter().map(|m| (*m).to_owned()).collect(),
        });
        self
    }
}

#[derive(Clone)]
pub struct Mock {
    /// `http://127.0.0.1:<port>`
    pub base: String,
    pub fixture: Arc<Mutex<Fixture>>,
    pub token_requests: Arc<AtomicUsize>,
    /// Paging links point to another host.
    pub evil_links: Arc<AtomicBool>,
    pub requests: Arc<Mutex<Vec<String>>>,
}

impl Mock {
    pub fn set(&self, fixture: Fixture) {
        *self.fixture.lock().unwrap() = fixture;
    }

    #[must_use]
    pub fn requested(&self, part: &str) -> bool {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.contains(part))
    }
}

type Reply = Result<Response, (StatusCode, Json<Value>)>;

fn unauthorized() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": { "code": 401, "message": "Invalid Credentials" } })),
    )
}

fn bearer(headers: &HeaderMap, token: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let expected = format!("Bearer {token}");
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(expected.as_str())
    {
        Ok(())
    } else {
        Err(unauthorized())
    }
}

fn log(mock: &Mock, what: String) {
    mock.requests.lock().unwrap().push(what);
}

/// A page of `items` from `start`, and where the next one starts.
fn page<T: Clone>(items: &[T], start: usize, size: usize) -> (Vec<T>, Option<usize>) {
    let end = (start + size).min(items.len());
    let next = (end < items.len()).then_some(end);
    (items.get(start..end).unwrap_or_default().to_vec(), next)
}

fn number(query: &HashMap<String, String>, name: &str) -> usize {
    query.get(name).and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn group_members(mock: &Mock, id: &str) -> Option<Vec<MockUser>> {
    let fixture = mock.fixture.lock().unwrap();
    let group = fixture.groups.iter().find(|g| g.id == id)?;
    Some(
        group
            .members
            .iter()
            .filter_map(|m| fixture.users.iter().find(|u| &u.id == m).cloned())
            .collect(),
    )
}

fn json_reply(value: Value) -> Response {
    Json(value).into_response()
}

fn verify_assertion(assertion: &str, audience: &str) -> Option<Value> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iat", "aud", "iss", "sub"]);
    decode::<Value>(assertion, &decoding_key(), &validation)
        .ok()
        .map(|data| data.claims)
}

// Google Workspace

async fn google_token(
    State(mock): State<Mock>,
    Form(form): Form<HashMap<String, String>>,
) -> Reply {
    mock.token_requests.fetch_add(1, Ordering::SeqCst);
    let bad = || {
        (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": "invalid_grant", "error_description": "Invalid JWT Signature." }),
            ),
        )
    };
    if form.get("grant_type").map(String::as_str)
        != Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
    {
        return Err(bad());
    }
    let claims = verify_assertion(
        form.get("assertion").map_or("", String::as_str),
        &format!("{}/token", mock.base),
    )
    .ok_or_else(bad)?;
    if claims["iss"] != GOOGLE_SERVICE_ACCOUNT || claims["scope"] != GOOGLE_SCOPES {
        return Err(bad());
    }
    if claims["sub"] != GOOGLE_ADMIN {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                json!({ "error": "unauthorized_client", "error_description": "Client is unauthorized to retrieve access tokens using this method." }),
            ),
        ));
    }
    Ok(json_reply(
        json!({ "access_token": GOOGLE_TOKEN, "token_type": "Bearer", "expires_in": 3599 }),
    ))
}

fn google_page(items: Vec<Value>, field: &str, next: Option<usize>) -> Response {
    let mut body = json!({ "kind": "admin#directory#list" });
    body[field] = Value::Array(items);
    if let Some(next) = next {
        body["nextPageToken"] = json!(format!("t{next}"));
    }
    json_reply(body)
}

fn google_start(query: &HashMap<String, String>) -> usize {
    query
        .get("pageToken")
        .and_then(|t| t.strip_prefix('t'))
        .and_then(|t| t.parse().ok())
        .unwrap_or(0)
}

async fn google_users(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    bearer(&headers, GOOGLE_TOKEN)?;
    if query.get("customer").map(String::as_str) != Some("my_customer") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "message": "Bad Request" } })),
        ));
    }
    let users = mock.fixture.lock().unwrap().users.clone();
    let (items, next) = page(&users, google_start(&query), 2);
    let items = items
        .into_iter()
        .map(|u| {
            json!({
                "kind": "admin#directory#user", "id": u.id, "primaryEmail": u.email,
                "name": { "givenName": u.first_name, "familyName": u.last_name },
                "suspended": u.status == Status::Suspended,
                "archived": u.status == Status::Deprovisioned,
            })
        })
        .collect();
    Ok(google_page(items, "users", next))
}

async fn google_groups(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    bearer(&headers, GOOGLE_TOKEN)?;
    let groups = mock.fixture.lock().unwrap().groups.clone();
    let (items, next) = page(&groups, google_start(&query), 2);
    let items = items
        .into_iter()
        .map(|g| json!({ "kind": "admin#directory#group", "id": g.id, "name": g.name, "email": format!("{}@example.org", g.id) }))
        .collect();
    Ok(google_page(items, "groups", next))
}

async fn google_members(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    bearer(&headers, GOOGLE_TOKEN)?;
    log(
        &mock,
        format!(
            "google members {id} derived={}",
            query
                .get("includeDerivedMembership")
                .map_or("", String::as_str)
        ),
    );
    let members = group_members(&mock, &id).ok_or((StatusCode::NOT_FOUND, Json(json!({}))))?;
    let mut members: Vec<Value> = members
        .into_iter()
        .map(|u| json!({ "kind": "admin#directory#member", "id": u.id, "email": u.email, "type": "USER", "status": "ACTIVE" }))
        .collect();
    // A nested group, which the derived membership has already expanded.
    members.push(json!({ "kind": "admin#directory#member", "id": "nested", "type": "GROUP" }));
    let (items, next) = page(&members, google_start(&query), 2);
    Ok(google_page(items, "members", next))
}

// Microsoft Graph

async fn ms_token(
    State(mock): State<Mock>,
    Path(tenant): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> Reply {
    mock.token_requests.fetch_add(1, Ordering::SeqCst);
    let ok = tenant == MS_TENANT
        && form.get("grant_type").map(String::as_str) == Some("client_credentials")
        && form.get("client_id").map(String::as_str) == Some(MS_CLIENT_ID)
        && form.get("client_secret").map(String::as_str) == Some(MS_CLIENT_SECRET)
        && form.get("scope").map(String::as_str) == Some("https://graph.microsoft.com/.default");
    if !ok {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(
                json!({ "error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided." }),
            ),
        ));
    }
    Ok(json_reply(
        json!({ "token_type": "Bearer", "expires_in": 3599, "access_token": MS_TOKEN }),
    ))
}

fn ms_page(mock: &Mock, path: &str, items: Vec<Value>, next: Option<usize>) -> Response {
    let mut body =
        json!({ "@odata.context": "https://graph.microsoft.com/v1.0/$metadata", "value": items });
    if let Some(next) = next {
        let host = if mock.evil_links.load(Ordering::SeqCst) {
            "https://attacker.example".to_owned()
        } else {
            mock.base.clone()
        };
        body["@odata.nextLink"] = json!(format!("{host}{path}?$skiptoken={next}"));
    }
    json_reply(body)
}

async fn ms_users(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    bearer(&headers, MS_TOKEN)?;
    let users = mock.fixture.lock().unwrap().users.clone();
    let (items, next) = page(&users, number(&query, "$skiptoken"), 2);
    let items = items
        .into_iter()
        .map(|u| {
            json!({
                "id": u.id, "mail": u.email, "userPrincipalName": u.email,
                "givenName": u.first_name, "surname": u.last_name,
                "accountEnabled": u.status == Status::Active, "mobilePhone": null,
            })
        })
        .collect();
    Ok(ms_page(&mock, "/v1.0/users", items, next))
}

async fn ms_groups(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    bearer(&headers, MS_TOKEN)?;
    let groups = mock.fixture.lock().unwrap().groups.clone();
    let (items, next) = page(&groups, number(&query, "$skiptoken"), 2);
    let items = items
        .into_iter()
        .map(|g| json!({ "id": g.id, "displayName": g.name }))
        .collect();
    Ok(ms_page(&mock, "/v1.0/groups", items, next))
}

async fn ms_members(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    bearer(&headers, MS_TOKEN)?;
    let members = group_members(&mock, &id).ok_or((StatusCode::NOT_FOUND, Json(json!({}))))?;
    let mut members: Vec<Value> = members
        .into_iter()
        .map(|u| json!({ "@odata.type": "#microsoft.graph.user", "id": u.id }))
        .collect();
    members.push(json!({ "@odata.type": "#microsoft.graph.group", "id": "nested" }));
    let (items, next) = page(&members, number(&query, "$skiptoken"), 2);
    Ok(ms_page(
        &mock,
        &format!("/v1.0/groups/{id}/transitiveMembers"),
        items,
        next,
    ))
}

// Okta

async fn okta_token(State(mock): State<Mock>, Form(form): Form<HashMap<String, String>>) -> Reply {
    mock.token_requests.fetch_add(1, Ordering::SeqCst);
    let bad = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(
                json!({ "error": "invalid_client", "error_description": "The client_assertion signature is invalid." }),
            ),
        )
    };
    let assertion = form.get("client_assertion").map_or("", String::as_str);
    let claims =
        verify_assertion(assertion, &format!("{}/oauth2/v1/token", mock.base)).ok_or_else(bad)?;
    let kid = decode_header(assertion).ok().and_then(|h| h.kid);
    let scopes: Vec<&str> = form
        .get("scope")
        .map_or("", String::as_str)
        .split(' ')
        .collect();
    let ok = claims["iss"] == OKTA_CLIENT_ID
        && claims["sub"] == OKTA_CLIENT_ID
        && claims["jti"].as_str().is_some_and(|jti| !jti.is_empty())
        && kid.as_deref() == Some(OKTA_KEY_ID)
        && form.get("grant_type").map(String::as_str) == Some("client_credentials")
        && form.get("client_assertion_type").map(String::as_str)
            == Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        && scopes.contains(&"okta.users.read")
        && scopes.contains(&"okta.groups.read");
    if !ok {
        return Err(bad());
    }
    Ok(json_reply(json!({
        "token_type": "Bearer", "expires_in": 3600, "access_token": OKTA_TOKEN,
        "scope": "okta.users.read okta.groups.read",
    })))
}

fn okta_page(
    mock: &Mock,
    path: &str,
    query: &HashMap<String, String>,
    items: &[Value],
) -> Response {
    let start = number(query, "after");
    let size = number(query, "limit").clamp(1, 2);
    let (items, next) = page(items, start, size);
    let mut response = Json(Value::Array(items)).into_response();
    let mut link = format!("<{}{path}?limit={size}>; rel=\"self\"", mock.base);
    if let Some(next) = next {
        let host = if mock.evil_links.load(Ordering::SeqCst) {
            "https://attacker.example".to_owned()
        } else {
            mock.base.clone()
        };
        let mut url = url::Url::parse(&format!("{host}{path}")).unwrap();
        url.query_pairs_mut()
            .append_pair("after", &next.to_string())
            .append_pair("limit", &size.to_string());
        if let Some(filter) = query.get("filter") {
            url.query_pairs_mut().append_pair("filter", filter);
        }
        link.push_str(&format!(", <{url}>; rel=\"next\""));
    }
    response
        .headers_mut()
        .insert(header::LINK, link.parse().unwrap());
    response
}

fn okta_user(u: &MockUser) -> Value {
    json!({
        "id": u.id,
        "status": match u.status {
            Status::Active => "ACTIVE",
            Status::Suspended => "SUSPENDED",
            Status::Deprovisioned => "DEPROVISIONED",
        },
        "profile": { "login": u.email, "email": u.email, "firstName": u.first_name, "lastName": u.last_name },
    })
}

async fn okta_users(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    bearer(&headers, OKTA_TOKEN)?;
    let deprovisioned = match query.get("filter").map(String::as_str) {
        None => false,
        Some("status eq \"DEPROVISIONED\"") => true,
        Some(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "errorSummary": "Invalid filter" })),
            ));
        }
    };
    let users: Vec<Value> = mock
        .fixture
        .lock()
        .unwrap()
        .users
        .iter()
        .filter(|u| (u.status == Status::Deprovisioned) == deprovisioned)
        .map(okta_user)
        .collect();
    Ok(okta_page(&mock, "/api/v1/users", &query, &users))
}

async fn okta_groups(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    bearer(&headers, OKTA_TOKEN)?;
    let groups: Vec<Value> = mock
        .fixture
        .lock()
        .unwrap()
        .groups
        .iter()
        .map(|g| json!({ "id": g.id, "type": "OKTA_GROUP", "profile": { "name": g.name } }))
        .collect();
    Ok(okta_page(&mock, "/api/v1/groups", &query, &groups))
}

async fn okta_members(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    bearer(&headers, OKTA_TOKEN)?;
    let members: Vec<Value> = group_members(&mock, &id)
        .ok_or((StatusCode::NOT_FOUND, Json(json!({}))))?
        .iter()
        .map(okta_user)
        .collect();
    Ok(okta_page(
        &mock,
        &format!("/api/v1/groups/{id}/users"),
        &query,
        &members,
    ))
}

// JumpCloud

fn api_key(headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    if headers.get("x-api-key").and_then(|v| v.to_str().ok()) == Some(JUMPCLOUD_KEY) {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "message": "Unauthorized" })),
        ))
    }
}

fn jumpcloud_window(query: &HashMap<String, String>) -> (usize, usize) {
    (number(query, "skip"), number(query, "limit").clamp(1, 100))
}

async fn jumpcloud_users(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    api_key(&headers)?;
    let users = mock.fixture.lock().unwrap().users.clone();
    let (skip, limit) = jumpcloud_window(&query);
    let (items, _) = page(&users, skip, limit);
    let results: Vec<Value> = items
        .iter()
        .map(|u| {
            json!({
                "_id": u.id, "email": u.email, "username": u.email.split('@').next(),
                "firstname": u.first_name, "lastname": u.last_name,
                "suspended": u.status != Status::Active,
                "state": if u.status == Status::Active { "ACTIVATED" } else { "SUSPENDED" },
                "activated": true,
            })
        })
        .collect();
    Ok(json_reply(
        json!({ "totalCount": users.len(), "results": results }),
    ))
}

async fn jumpcloud_groups(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    api_key(&headers)?;
    let groups = mock.fixture.lock().unwrap().groups.clone();
    let (skip, limit) = jumpcloud_window(&query);
    let (items, _) = page(&groups, skip, limit);
    let items: Vec<Value> = items
        .iter()
        .map(|g| json!({ "id": g.id, "name": g.name, "type": "user_group" }))
        .collect();
    Ok(json_reply(Value::Array(items)))
}

async fn jumpcloud_members(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    api_key(&headers)?;
    let members = group_members(&mock, &id).ok_or((StatusCode::NOT_FOUND, Json(json!({}))))?;
    let (skip, limit) = jumpcloud_window(&query);
    let (items, _) = page(&members, skip, limit);
    let items: Vec<Value> = items
        .iter()
        .map(|u| json!({ "id": u.id, "type": "user", "compiledAttributes": {}, "paths": [] }))
        .collect();
    Ok(json_reply(Value::Array(items)))
}

/// Starts the mock on a free loopback port.
pub async fn start(fixture: Fixture) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock = Mock {
        base: format!("http://{}", listener.local_addr().unwrap()),
        fixture: Arc::new(Mutex::new(fixture)),
        token_requests: Arc::default(),
        evil_links: Arc::default(),
        requests: Arc::default(),
    };
    let app = Router::new()
        .route("/token", post(google_token))
        .route("/admin/directory/v1/users", get(google_users))
        .route("/admin/directory/v1/groups", get(google_groups))
        .route(
            "/admin/directory/v1/groups/{id}/members",
            get(google_members),
        )
        .route("/{tenant}/oauth2/v2.0/token", post(ms_token))
        .route("/v1.0/users", get(ms_users))
        .route("/v1.0/groups", get(ms_groups))
        .route("/v1.0/groups/{id}/transitiveMembers", get(ms_members))
        .route("/oauth2/v1/token", post(okta_token))
        .route("/api/v1/users", get(okta_users))
        .route("/api/v1/groups", get(okta_groups))
        .route("/api/v1/groups/{id}/users", get(okta_members))
        .route("/api/systemusers", get(jumpcloud_users))
        .route("/api/v2/usergroups", get(jumpcloud_groups))
        .route("/api/v2/usergroups/{id}/membership", get(jumpcloud_members))
        .with_state(mock.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    mock
}
