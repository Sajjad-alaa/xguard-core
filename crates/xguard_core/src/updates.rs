//! "A new XGuard version is available" check, against the GitHub releases of xguard-core.
//!
//! - One request per day (and one at start-up), at most 1 MiB read, 10 s timeout, no redirects.
//! - Failures are expected on networks without internet access, and before the first release is
//!   published (GitHub answers 404), so they are logged at debug level only.
//! - Only published releases count: `/releases/latest` never returns drafts or pre-releases.

use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};
use reqwest::{StatusCode, header};
use semver::Version;
use xguard_common::{REPORTED_VERSION, global_value};
use xguard_version::is_version_lower;

/// GitHub API endpoint for the newest published xguard-core release.
pub(crate) const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/Sajjad-alaa/xguard-core/releases/latest";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// A release response is a few KiB; anything larger is not what we asked for.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Release notes shown in the update dialog are cut here.
const MAX_NOTES_CHARS: usize = 20_000;
/// A release whose title contains this marker is announced as a critical update.
const CRITICAL_MARKER: &str = "[critical]";

#[derive(Deserialize, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(Clone))]
pub struct Update {
    version: String,
    release_date: NaiveDate,
    release_notes_url: String,
    update_url: String,
    critical: bool,
    notes: String,
}

global_value!(NEW_UPDATE, Option<Update>, None, set_update, get_update);

/// The fields of a GitHub release this check uses.
#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    published_at: Option<DateTime<Utc>>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

/// Why no update information is available. All of these are expected in normal operation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum UpdateCheckError {
    #[error("no release has been published yet")]
    NoRelease,
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("unexpected HTTP status {0}")]
    Status(StatusCode),
    #[error("response is larger than {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    #[error("invalid release data: {0}")]
    Invalid(String),
}

fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("xguard-core/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// Turns a release into update information, or `None` for drafts and pre-releases.
fn parse_release(body: &[u8]) -> Result<Option<(Version, Update)>, UpdateCheckError> {
    let release: GithubRelease =
        serde_json::from_slice(body).map_err(|err| UpdateCheckError::Invalid(err.to_string()))?;
    if release.draft || release.prerelease {
        return Ok(None);
    }
    let tag = release.tag_name.trim();
    let version_str = tag.strip_prefix(['v', 'V']).unwrap_or(tag);
    let version = Version::parse(version_str)
        .map_err(|err| UpdateCheckError::Invalid(format!("tag {tag:?}: {err}")))?;
    if !release.html_url.starts_with("https://") {
        return Err(UpdateCheckError::Invalid(format!(
            "release URL {:?} is not https",
            release.html_url
        )));
    }
    let critical = release
        .name
        .as_deref()
        .is_some_and(|name| name.to_ascii_lowercase().contains(CRITICAL_MARKER));
    let notes: String = release
        .body
        .unwrap_or_default()
        .chars()
        .take(MAX_NOTES_CHARS)
        .collect();
    let update = Update {
        version: version.to_string(),
        release_date: release.published_at.unwrap_or_else(Utc::now).date_naive(),
        release_notes_url: release.html_url.clone(),
        update_url: release.html_url,
        critical,
        notes,
    };
    Ok(Some((version, update)))
}

/// Fetches the newest release from `url` (the GitHub releases API).
pub(crate) async fn fetch_latest_release(
    url: &str,
) -> Result<Option<(Version, Update)>, UpdateCheckError> {
    let mut response = http_client()?
        .get(url)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::NOT_FOUND => return Err(UpdateCheckError::NoRelease),
        status => return Err(UpdateCheckError::Status(status)),
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err(UpdateCheckError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(UpdateCheckError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    parse_release(&body)
}

fn is_newer_update_available(current_version: &Version, new_version: &Version) -> bool {
    is_version_lower(current_version, new_version)
}

/// Checks `url` and returns the update to announce, if the release is newer than `current`.
pub(crate) async fn check_for_update(
    url: &str,
    current: &str,
) -> Result<Option<Update>, UpdateCheckError> {
    let current = Version::parse(current)
        .map_err(|err| UpdateCheckError::Invalid(format!("running version {current:?}: {err}")))?;
    Ok(fetch_latest_release(url)
        .await?
        .and_then(|(version, update)| {
            is_newer_update_available(&current, &version).then_some(update)
        }))
}

/// Runs the check and stores the result for `GET /api/v1/updates`. Never fails: problems are
/// logged at debug level and the previous result is kept.
pub(crate) async fn do_new_version_check() {
    debug!("Checking for a new version of XGuard at {LATEST_RELEASE_URL}");
    match check_for_update(LATEST_RELEASE_URL, REPORTED_VERSION).await {
        Ok(Some(update)) => {
            if update.critical {
                warn!(
                    "There is a new critical XGuard update available: {} (released on {}). It's \
                    recommended to update as soon as possible: {}",
                    update.version, update.release_date, update.update_url
                );
            } else {
                info!(
                    "There is a new XGuard version available: {} (released on {}): {}",
                    update.version, update.release_date, update.update_url
                );
            }
            set_update(Some(update));
        }
        Ok(None) => {
            debug!("New version check done. You are using the latest version of XGuard.");
            set_update(None);
        }
        Err(err) => debug!("Could not check for a new XGuard version: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use semver::Version;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::*;

    const RELEASE_PATH: &str = "/repos/Sajjad-alaa/xguard-core/releases/latest";

    fn release(tag: &str) -> serde_json::Value {
        json!({
            "url": "https://api.github.com/repos/Sajjad-alaa/xguard-core/releases/1",
            "html_url": format!("https://github.com/Sajjad-alaa/xguard-core/releases/tag/{tag}"),
            "id": 1,
            "tag_name": tag,
            "name": format!("XGuard {tag}"),
            "draft": false,
            "prerelease": false,
            "created_at": "2026-11-20T10:00:00Z",
            "published_at": "2026-11-21T10:00:00Z",
            "assets": [],
            "body": "Bug fixes.\n\n- one\n- two",
        })
    }

    async fn server_with(response: ResponseTemplate) -> (MockServer, String) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(RELEASE_PATH))
            .and(header("accept", "application/vnd.github+json"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let url = format!("{}{RELEASE_PATH}", server.uri());
        (server, url)
    }

    #[test]
    fn ignores_prerelease_suffixes_when_comparing_update_versions() {
        let cases = [
            ("2.0.0-beta1", "2.0.0", false),
            ("2.0.0", "2.0.0-beta1", false),
            ("2.0.0-beta1", "2.0.0-rc1", false),
            ("2.0.0-beta1", "2.0.1", true),
            ("2.0.0-beta1", "2.1.0-alpha1", true),
            ("2.0.1", "2.0.0-rc1", false),
        ];

        for (current, new, expected) in cases {
            let current = Version::parse(current).expect("valid current version");
            let new = Version::parse(new).expect("valid new version");
            assert_eq!(
                is_newer_update_available(&current, &new),
                expected,
                "current={current}, new={new}"
            );
        }
    }

    #[test]
    fn parses_github_release() {
        let body = serde_json::to_vec(&release("v2.3.1")).unwrap();
        let (version, update) = parse_release(&body).unwrap().unwrap();
        assert_eq!(version, Version::new(2, 3, 1));
        assert_eq!(update.version, "2.3.1");
        assert_eq!(update.release_date.to_string(), "2026-11-21");
        assert_eq!(
            update.update_url,
            "https://github.com/Sajjad-alaa/xguard-core/releases/tag/v2.3.1"
        );
        assert_eq!(update.release_notes_url, update.update_url);
        assert!(!update.critical);
        assert_eq!(update.notes, "Bug fixes.\n\n- one\n- two");

        // Tags without the "v" prefix work too; a "[critical]" title marks a critical update.
        let mut critical = release("2.3.2");
        critical["name"] = json!("XGuard 2.3.2 [CRITICAL]");
        let body = serde_json::to_vec(&critical).unwrap();
        let (_, update) = parse_release(&body).unwrap().unwrap();
        assert_eq!(update.version, "2.3.2");
        assert!(update.critical);
    }

    #[test]
    fn skips_or_rejects_unusable_releases() {
        let mut pre = release("v2.4.0-rc1");
        pre["prerelease"] = json!(true);
        assert!(
            parse_release(&serde_json::to_vec(&pre).unwrap())
                .unwrap()
                .is_none()
        );
        let mut draft = release("v2.4.0");
        draft["draft"] = json!(true);
        assert!(
            parse_release(&serde_json::to_vec(&draft).unwrap())
                .unwrap()
                .is_none()
        );
        let bad_tag = release("latest");
        assert!(matches!(
            parse_release(&serde_json::to_vec(&bad_tag).unwrap()),
            Err(UpdateCheckError::Invalid(_))
        ));
        let mut bad_url = release("v2.4.0");
        bad_url["html_url"] = json!("javascript:alert(1)");
        assert!(matches!(
            parse_release(&serde_json::to_vec(&bad_url).unwrap()),
            Err(UpdateCheckError::Invalid(_))
        ));
        assert!(matches!(
            parse_release(b"<html>rate limited</html>"),
            Err(UpdateCheckError::Invalid(_))
        ));
        // Long notes are cut.
        let mut long = release("v2.4.0");
        long["body"] = json!("x".repeat(MAX_NOTES_CHARS + 10));
        let (_, update) = parse_release(&serde_json::to_vec(&long).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(update.notes.len(), MAX_NOTES_CHARS);
    }

    #[tokio::test]
    async fn announces_newer_release_from_mock_github() {
        let (_server, url) =
            server_with(ResponseTemplate::new(200).set_body_json(release("v2.3.0"))).await;
        let update = check_for_update(&url, "2.2.0").await.unwrap().unwrap();
        assert_eq!(update.version, "2.3.0");
    }

    #[tokio::test]
    async fn same_or_older_release_is_not_announced() {
        let (_server, url) =
            server_with(ResponseTemplate::new(200).set_body_json(release("v2.2.0"))).await;
        assert!(check_for_update(&url, "2.2.0").await.unwrap().is_none());
        let (_server, url) =
            server_with(ResponseTemplate::new(200).set_body_json(release("v2.1.9"))).await;
        assert!(check_for_update(&url, "2.2.0").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn no_release_yet_is_reported_as_such() {
        let (_server, url) = server_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "Not Found",
            "documentation_url": "https://docs.github.com/rest/releases/releases#get-the-latest-release",
            "status": "404"
        })))
        .await;
        assert!(matches!(
            check_for_update(&url, "2.2.0").await,
            Err(UpdateCheckError::NoRelease)
        ));
    }

    #[tokio::test]
    async fn rate_limit_redirect_and_oversized_responses_fail_quietly() {
        let (_server, url) = server_with(ResponseTemplate::new(403)).await;
        assert!(matches!(
            check_for_update(&url, "2.2.0").await,
            Err(UpdateCheckError::Status(StatusCode::FORBIDDEN))
        ));
        // Redirects are not followed.
        let (_server, url) = server_with(
            ResponseTemplate::new(301).insert_header("location", "https://evil.example/latest"),
        )
        .await;
        assert!(matches!(
            check_for_update(&url, "2.2.0").await,
            Err(UpdateCheckError::Status(StatusCode::MOVED_PERMANENTLY))
        ));
        let (_server, url) = server_with(
            ResponseTemplate::new(200).set_body_string("x".repeat(MAX_RESPONSE_BYTES + 1)),
        )
        .await;
        assert!(matches!(
            check_for_update(&url, "2.2.0").await,
            Err(UpdateCheckError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn network_errors_and_timeouts_fail_quietly() {
        // Nothing listens on this port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/latest", listener.local_addr().unwrap());
        drop(listener);
        assert!(matches!(
            check_for_update(&url, "2.2.0").await,
            Err(UpdateCheckError::Request(_))
        ));
        let (_server, url) = server_with(
            ResponseTemplate::new(200)
                .set_body_json(release("v9.0.0"))
                .set_delay(REQUEST_TIMEOUT + Duration::from_secs(2)),
        )
        .await;
        assert!(matches!(
            check_for_update(&url, "2.2.0").await,
            Err(UpdateCheckError::Request(err)) if err.is_timeout()
        ));
    }
}
