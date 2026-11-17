//! HTTP plumbing the directory API clients share.
//!
//! - **Timeouts:** 10 seconds per request (connect included).
//! - **No redirects:** a provider cannot point XGuard at other hosts, internal ones included.
//! - **Bounded reads:** a response body is read up to [`MAX_BODY_BYTES`]; listings stop at
//!   [`MAX_PAGES`] pages and [`MAX_ITEMS`] entries.
//! - **Paging links** (Microsoft `@odata.nextLink`, Okta `Link` headers) are followed only to
//!   the API's own origin, so a response cannot send the bearer token elsewhere.
//! - **Rate limits:** a `429` or `503` is retried twice, waiting as `Retry-After` asks (at most
//!   10 seconds).

use std::time::Duration;

use reqwest::{
    Client, RequestBuilder, Response, StatusCode,
    header::{HeaderMap, RETRY_AFTER},
    redirect::Policy,
};
use serde::de::DeserializeOwned;
use url::Url;

use super::DirSyncError;

pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);
/// The largest response body read.
pub(crate) const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// The most pages one listing reads.
pub(crate) const MAX_PAGES: usize = 2_000;
/// The most entries one listing returns.
pub(crate) const MAX_ITEMS: usize = 200_000;
const MAX_RETRIES: usize = 2;
const MAX_RETRY_WAIT: Duration = Duration::from_secs(10);
/// How much of an error response is quoted in messages.
const MAX_ERROR_CHARS: usize = 300;

pub(crate) fn client() -> Result<Client, DirSyncError> {
    Client::builder()
        .redirect(Policy::none())
        .timeout(TIMEOUT)
        .connect_timeout(TIMEOUT)
        .user_agent(concat!(
            "XGuard/",
            env!("CARGO_PKG_VERSION"),
            " directory-sync"
        ))
        .build()
        .map_err(|err| DirSyncError::Http(err.to_string()))
}

/// Whether `url` has the same scheme, host and port as `base`.
pub(crate) fn same_origin(url: &Url, base: &Url) -> bool {
    url.scheme() == base.scheme()
        && url.host_str() == base.host_str()
        && url.port_or_known_default() == base.port_or_known_default()
}

/// Reads at most [`MAX_BODY_BYTES`] of the body.
async fn read_body(mut response: Response) -> Result<Vec<u8>, DirSyncError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        return Err(DirSyncError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| DirSyncError::Http(err.to_string()))?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(DirSyncError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// A short, printable excerpt of an error body: the OAuth `error_description` or `error`, the
/// API's `error.message`, or the start of the text.
fn error_excerpt(body: &[u8]) -> String {
    let text = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
        let pick = |value: &serde_json::Value| value.as_str().map(str::to_owned);
        pick(&json["error_description"])
            .or_else(|| pick(&json["errorSummary"]))
            .or_else(|| pick(&json["error"]["message"]))
            .or_else(|| pick(&json["message"]))
            .or_else(|| pick(&json["error"]))
            .unwrap_or_else(|| json.to_string())
    } else {
        String::from_utf8_lossy(body).into_owned()
    };
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_ERROR_CHARS)
        .collect()
}

fn retry_wait(headers: &HeaderMap) -> Duration {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map_or(Duration::from_secs(1), Duration::from_secs)
        .min(MAX_RETRY_WAIT)
}

/// Sends `request` and parses a JSON reply. `what` names the request in errors.
pub(crate) async fn send_json<T: DeserializeOwned>(
    request: RequestBuilder,
    what: &str,
) -> Result<(T, HeaderMap), DirSyncError> {
    let mut attempt = 0;
    loop {
        let this = request
            .try_clone()
            .ok_or_else(|| DirSyncError::Http("the request cannot be repeated".into()))?;
        let response = this
            .send()
            .await
            .map_err(|err| DirSyncError::Http(format!("{what}: {}", super::error_chain(&err))))?;
        let status = response.status();
        let headers = response.headers().clone();
        if matches!(
            status,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
        ) && attempt < MAX_RETRIES
        {
            attempt += 1;
            tokio::time::sleep(retry_wait(&headers)).await;
            continue;
        }
        let body = read_body(response).await?;
        if status.is_redirection() {
            return Err(DirSyncError::Api {
                what: what.to_owned(),
                status: status.as_u16(),
                message: "redirects are not followed".into(),
            });
        }
        if !status.is_success() {
            return Err(DirSyncError::Api {
                what: what.to_owned(),
                status: status.as_u16(),
                message: error_excerpt(&body),
            });
        }
        let value = serde_json::from_slice(&body).map_err(|err| DirSyncError::Api {
            what: what.to_owned(),
            status: status.as_u16(),
            message: format!("unexpected response: {err}"),
        })?;
        return Ok((value, headers));
    }
}

/// The `rel="next"` URL of a `Link` header, if it points to `base`'s origin.
pub(crate) fn next_link(headers: &HeaderMap, base: &Url) -> Result<Option<Url>, DirSyncError> {
    for value in headers.get_all(reqwest::header::LINK) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for link in value.split(',') {
            let mut parts = link.split(';');
            let target = parts.next().unwrap_or_default().trim();
            let is_next = parts.any(|param| {
                let param = param.trim().replace(' ', "");
                param.eq_ignore_ascii_case("rel=\"next\"") || param.eq_ignore_ascii_case("rel=next")
            });
            if !is_next {
                continue;
            }
            let url = target
                .strip_prefix('<')
                .and_then(|t| t.strip_suffix('>'))
                .and_then(|t| Url::parse(t).ok())
                .ok_or_else(|| DirSyncError::Http("the paging link is not valid".into()))?;
            return checked_next(url, base).map(Some);
        }
    }
    Ok(None)
}

/// Accepts a paging URL only on the API's own origin.
pub(crate) fn checked_next(url: Url, base: &Url) -> Result<Url, DirSyncError> {
    if same_origin(&url, base) {
        Ok(url)
    } else {
        Err(DirSyncError::Http(format!(
            "refusing to follow a paging link to {}",
            url.host_str().unwrap_or("another host")
        )))
    }
}

/// Collects pages, guarding against endless or oversized listings.
pub(crate) struct Pager<T> {
    pub items: Vec<T>,
    pages: usize,
    what: &'static str,
}

impl<T> Pager<T> {
    pub(crate) fn new(what: &'static str) -> Self {
        Self {
            items: Vec::new(),
            pages: 0,
            what,
        }
    }

    pub(crate) fn add(&mut self, page: impl IntoIterator<Item = T>) -> Result<(), DirSyncError> {
        self.pages += 1;
        if self.pages > MAX_PAGES {
            return Err(DirSyncError::Http(format!(
                "listing {} took more than {MAX_PAGES} pages",
                self.what
            )));
        }
        self.items.extend(page);
        if self.items.len() > MAX_ITEMS {
            return Err(DirSyncError::Http(format!(
                "the directory has more than {MAX_ITEMS} {}",
                self.what
            )));
        }
        Ok(())
    }
}

/// `base` with `segments` appended to its path, each percent-encoded.
pub(crate) fn join(base: &Url, segments: &[&str]) -> Url {
    let mut url = base.clone();
    if let Ok(mut path) = url.path_segments_mut() {
        path.pop_if_empty();
        for segment in segments {
            path.push(segment);
        }
    }
    url
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderValue, LINK};

    use super::*;

    #[test]
    fn link_headers_stay_on_the_api_host() {
        let base = Url::parse("https://example.okta.com/api/v1/users").unwrap();
        let mut headers = HeaderMap::new();
        headers.append(
            LINK,
            HeaderValue::from_static(
                "<https://example.okta.com/api/v1/users?limit=2>; rel=\"self\", \
                 <https://example.okta.com/api/v1/users?after=abc&limit=2>; rel=\"next\"",
            ),
        );
        assert_eq!(
            next_link(&headers, &base).unwrap().unwrap().as_str(),
            "https://example.okta.com/api/v1/users?after=abc&limit=2"
        );
        let mut evil = HeaderMap::new();
        evil.append(
            LINK,
            HeaderValue::from_static("<https://attacker.example/steal>; rel=\"next\""),
        );
        assert!(next_link(&evil, &base).is_err());
        let mut downgrade = HeaderMap::new();
        downgrade.append(
            LINK,
            HeaderValue::from_static("<http://example.okta.com/api/v1/users>; rel=\"next\""),
        );
        assert!(next_link(&downgrade, &base).is_err());
        assert!(next_link(&HeaderMap::new(), &base).unwrap().is_none());
    }

    #[test]
    fn ids_are_encoded_in_paths() {
        let base = Url::parse("https://graph.microsoft.com/v1.0/").unwrap();
        assert_eq!(
            join(&base, &["groups", "../users?x=1", "members"]).as_str(),
            "https://graph.microsoft.com/v1.0/groups/..%2Fusers%3Fx=1/members"
        );
    }

    #[test]
    fn error_bodies_are_summarized() {
        assert_eq!(
            error_excerpt(br#"{"error":"invalid_client","error_description":"bad key"}"#),
            "bad key"
        );
        assert_eq!(
            error_excerpt(br#"{"error":{"code":"x","message":"Insufficient privileges"}}"#),
            "Insufficient privileges"
        );
        assert_eq!(error_excerpt(&[b'a'; 1000]).len(), MAX_ERROR_CHARS);
    }
}
