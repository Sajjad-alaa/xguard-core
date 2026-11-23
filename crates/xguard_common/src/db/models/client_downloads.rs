//! Where users download the XGuard clients from.
//!
//! - Desktop installers are `<base_url>/<asset name>`, with fixed, version-less asset names that
//!   the client release workflow uploads to every GitHub release (see [`CLIENT_ASSET_NAMES`]).
//!   The default base URL is the latest GitHub release, so the links always point at the newest
//!   client. Admins of networks without internet access point it at their own web server.
//! - The mobile links are optional and hidden when unset.
//! - The settings live in the single-row `client_download_settings` table (a missing row means
//!   the defaults) and are cached in memory like [`crate::db::models::ClientSettings`]; every
//!   write goes through [`ClientDownloadSettings::save`] and [`ClientDownloadSettings::set_cached`].

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use thiserror::Error;
use url::Url;

use crate::global_value;

/// Default installer base URL: the newest GitHub release of the XGuard client.
pub const DEFAULT_CLIENT_DOWNLOAD_BASE_URL: &str =
    "https://github.com/Sajjad-alaa/xguard-client/releases/latest/download";
/// Default releases page.
pub const DEFAULT_CLIENT_RELEASES_URL: &str =
    "https://github.com/Sajjad-alaa/xguard-client/releases/latest";

/// Installer file names appended to the base URL. They are a contract with the client release
/// workflow (`xguard-client/.github/workflows/release-installers.yaml`) and the web UIs.
pub const CLIENT_ASSET_NAMES: [&str; 6] = [
    "xguard-client_amd64.deb",
    "xguard-client_arm64.deb",
    "xguard-client.x86_64.rpm",
    "xguard-client.aarch64.rpm",
    "xguard-client_x64.msi",
    "xguard-client_universal.dmg",
];

/// Longest URL accepted. Far above any real link; bounds what is stored and sent to every Edge.
pub const MAX_CLIENT_DOWNLOAD_URL_LEN: usize = 2048;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientDownloadsError {
    #[error("{field} is required")]
    Missing { field: &'static str },
    #[error("{field} is longer than {MAX_CLIENT_DOWNLOAD_URL_LEN} characters")]
    TooLong { field: &'static str },
    #[error("{field} is not a valid URL")]
    Invalid { field: &'static str },
    #[error(
        "{field} must use https (plain http is accepted only with \"allow_http\" for a server in \
        your own network)"
    )]
    InsecureScheme { field: &'static str },
    #[error("{field} must not contain a user name or password")]
    Credentials { field: &'static str },
    #[error("{field} must not contain a query (?...) or fragment (#...)")]
    QueryOrFragment { field: &'static str },
}

/// Where the clients are downloaded from. Admin setting, readable by every signed-in user.
#[derive(Clone, Debug, Deserialize, Eq, FromRow, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ClientDownloadSettings {
    /// Installers are `<base_url>/<asset name>`. No trailing slash, query or fragment.
    pub base_url: String,
    /// Page listing every release ("all downloads").
    pub releases_url: String,
    /// Android APK or store page; `null` hides the Android link.
    #[serde(default)]
    pub android_url: Option<String>,
    /// iOS App Store page; `null` hides the iOS link.
    #[serde(default)]
    pub ios_url: Option<String>,
    /// A macOS installer is published under `base_url`. Off by default: macOS builds need an
    /// Apple Developer account to be signed, so the macOS button opens `releases_url` instead.
    #[serde(default)]
    pub macos_installer: bool,
    /// Accept plain `http://` URLs, for a download server inside the network. Off by default:
    /// installers fetched over plain HTTP can be replaced in transit.
    #[serde(default)]
    pub allow_http: bool,
}

impl Default for ClientDownloadSettings {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_CLIENT_DOWNLOAD_BASE_URL.into(),
            releases_url: DEFAULT_CLIENT_RELEASES_URL.into(),
            android_url: None,
            ios_url: None,
            macos_installer: false,
            allow_http: false,
        }
    }
}

global_value!(
    CLIENT_DOWNLOAD_SETTINGS,
    Option<ClientDownloadSettings>,
    None,
    set_client_download_settings,
    get_client_download_settings
);

/// Loads the client download settings into the cache at program start.
pub async fn initialize_client_download_settings<'e, E: PgExecutor<'e>>(
    executor: E,
) -> sqlx::Result<()> {
    set_client_download_settings(Some(ClientDownloadSettings::load(executor).await?));
    Ok(())
}

/// Validates and canonicalizes one URL.
///
/// - `https`, or `http` when `allow_http`; a host is required; no user name or password.
/// - `path_only` (the base URL, which file names are appended to) also rejects a query or a
///   fragment and drops trailing slashes.
fn canonical_url(
    raw: &str,
    field: &'static str,
    allow_http: bool,
    path_only: bool,
) -> Result<String, ClientDownloadsError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ClientDownloadsError::Missing { field });
    }
    if raw.len() > MAX_CLIENT_DOWNLOAD_URL_LEN {
        return Err(ClientDownloadsError::TooLong { field });
    }
    let url = Url::parse(raw).map_err(|_| ClientDownloadsError::Invalid { field })?;
    match url.scheme() {
        "https" => {}
        "http" if allow_http => {}
        "http" => return Err(ClientDownloadsError::InsecureScheme { field }),
        _ => return Err(ClientDownloadsError::Invalid { field }),
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(ClientDownloadsError::Invalid { field });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ClientDownloadsError::Credentials { field });
    }
    if path_only && (url.query().is_some() || url.fragment().is_some()) {
        return Err(ClientDownloadsError::QueryOrFragment { field });
    }
    let mut canonical = url.to_string();
    if path_only {
        while canonical.ends_with('/') {
            canonical.pop();
        }
    }
    if canonical.len() > MAX_CLIENT_DOWNLOAD_URL_LEN {
        return Err(ClientDownloadsError::TooLong { field });
    }
    Ok(canonical)
}

fn canonical_optional_url(
    raw: Option<&str>,
    field: &'static str,
    allow_http: bool,
) -> Result<Option<String>, ClientDownloadsError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(raw) => canonical_url(raw, field, allow_http, false).map(Some),
    }
}

impl ClientDownloadSettings {
    /// Checks every URL and returns the canonical form that is stored: trimmed, normalized by
    /// the URL parser, base URL without trailing slash, empty mobile links as `None`.
    pub fn canonicalize(&self) -> Result<Self, ClientDownloadsError> {
        Ok(Self {
            base_url: canonical_url(&self.base_url, "base_url", self.allow_http, true)?,
            releases_url: canonical_url(
                &self.releases_url,
                "releases_url",
                self.allow_http,
                false,
            )?,
            android_url: canonical_optional_url(
                self.android_url.as_deref(),
                "android_url",
                self.allow_http,
            )?,
            ios_url: canonical_optional_url(self.ios_url.as_deref(), "ios_url", self.allow_http)?,
            macos_installer: self.macos_installer,
            allow_http: self.allow_http,
        })
    }

    /// Whether any link uses plain HTTP.
    #[must_use]
    pub fn uses_http(&self) -> bool {
        [
            Some(self.base_url.as_str()),
            Some(self.releases_url.as_str()),
            self.android_url.as_deref(),
            self.ios_url.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|url| url.starts_with("http://"))
    }

    /// Download URL of one installer.
    #[must_use]
    pub fn asset_url(&self, asset_name: &str) -> String {
        format!("{}/{asset_name}", self.base_url)
    }

    /// Reads the settings from the database, bypassing the cache. A missing row means defaults.
    pub async fn load<'e, E: PgExecutor<'e>>(executor: E) -> sqlx::Result<Self> {
        let settings: Option<Self> = sqlx::query_as(
            "SELECT base_url, releases_url, android_url, ios_url, macos_installer, allow_http \
            FROM client_download_settings WHERE id = 1",
        )
        .fetch_optional(executor)
        .await?;
        Ok(settings.unwrap_or_default())
    }

    /// The cached settings. Before [`initialize_client_download_settings`] has run (in tests, for
    /// example) this reads the database every time, so separate databases never share a value.
    pub async fn current<'e, E: PgExecutor<'e>>(executor: E) -> sqlx::Result<Self> {
        if let Some(settings) = get_client_download_settings().clone() {
            return Ok(settings);
        }
        Self::load(executor).await
    }

    /// Writes already canonicalized settings. Call [`Self::set_cached`] after the commit.
    pub async fn save<'e, E: PgExecutor<'e>>(&self, executor: E) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO client_download_settings \
            (id, base_url, releases_url, android_url, ios_url, macos_installer, allow_http) \
            VALUES (1, $1, $2, $3, $4, $5, $6) \
            ON CONFLICT (id) DO UPDATE SET \
            base_url = EXCLUDED.base_url, \
            releases_url = EXCLUDED.releases_url, \
            android_url = EXCLUDED.android_url, \
            ios_url = EXCLUDED.ios_url, \
            macos_installer = EXCLUDED.macos_installer, \
            allow_http = EXCLUDED.allow_http",
        )
        .bind(&self.base_url)
        .bind(&self.releases_url)
        .bind(&self.android_url)
        .bind(&self.ios_url)
        .bind(self.macos_installer)
        .bind(self.allow_http)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Replaces the cached settings, if the cache is in use.
    pub fn set_cached(self) {
        let mut cache = CLIENT_DOWNLOAD_SETTINGS
            .write()
            .expect("Failed to acquire RwLock for write");
        if cache.is_some() {
            *cache = Some(self);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(base_url: &str) -> ClientDownloadSettings {
        ClientDownloadSettings {
            base_url: base_url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn defaults_are_valid_and_canonical() {
        let defaults = ClientDownloadSettings::default();
        assert_eq!(defaults.canonicalize().unwrap(), defaults);
        assert!(!defaults.uses_http());
        assert_eq!(
            defaults.asset_url(CLIENT_ASSET_NAMES[4]),
            "https://github.com/Sajjad-alaa/xguard-client/releases/latest/download/\
            xguard-client_x64.msi"
        );
    }

    #[test]
    fn canonicalizes_urls() {
        let input = ClientDownloadSettings {
            base_url: "  https://Downloads.Example.com/xguard//  ".into(),
            releases_url: "https://downloads.example.com/xguard/".into(),
            android_url: Some("   ".into()),
            ios_url: Some(" https://apps.apple.com/app/id1 ".into()),
            macos_installer: true,
            allow_http: false,
        };
        let output = input.canonicalize().unwrap();
        assert_eq!(output.base_url, "https://downloads.example.com/xguard");
        assert_eq!(output.releases_url, "https://downloads.example.com/xguard/");
        assert_eq!(output.android_url, None);
        assert_eq!(
            output.ios_url.as_deref(),
            Some("https://apps.apple.com/app/id1")
        );
        // A host-only base URL loses the slash the parser adds.
        assert_eq!(
            settings("https://mirror.lan")
                .canonicalize()
                .unwrap()
                .base_url,
            "https://mirror.lan"
        );
        // Store pages keep their query.
        let store = ClientDownloadSettings {
            android_url: Some("https://play.google.com/store/apps/details?id=x.y".into()),
            ..Default::default()
        };
        assert_eq!(
            store.canonicalize().unwrap().android_url.as_deref(),
            Some("https://play.google.com/store/apps/details?id=x.y")
        );
    }

    #[test]
    fn rejects_bad_urls() {
        let cases = [
            ("", ClientDownloadsError::Missing { field: "base_url" }),
            (
                "downloads",
                ClientDownloadsError::Invalid { field: "base_url" },
            ),
            (
                "javascript:alert(1)",
                ClientDownloadsError::Invalid { field: "base_url" },
            ),
            (
                "ftp://mirror.lan/x",
                ClientDownloadsError::Invalid { field: "base_url" },
            ),
            (
                "file:///srv/x",
                ClientDownloadsError::Invalid { field: "base_url" },
            ),
            (
                "http://mirror.lan/x",
                ClientDownloadsError::InsecureScheme { field: "base_url" },
            ),
            (
                "https://user:pw@mirror.lan/x",
                ClientDownloadsError::Credentials { field: "base_url" },
            ),
            (
                "https://mirror.lan/x?v=1",
                ClientDownloadsError::QueryOrFragment { field: "base_url" },
            ),
            (
                "https://mirror.lan/x#top",
                ClientDownloadsError::QueryOrFragment { field: "base_url" },
            ),
        ];
        for (url, expected) in cases {
            assert_eq!(settings(url).canonicalize(), Err(expected), "{url}");
        }
        let long = format!(
            "https://mirror.lan/{}",
            "a".repeat(MAX_CLIENT_DOWNLOAD_URL_LEN)
        );
        assert_eq!(
            settings(&long).canonicalize(),
            Err(ClientDownloadsError::TooLong { field: "base_url" })
        );
        let bad_mobile = ClientDownloadSettings {
            ios_url: Some("itms-apps://apps.apple.com/app/id1".into()),
            ..Default::default()
        };
        assert_eq!(
            bad_mobile.canonicalize(),
            Err(ClientDownloadsError::Invalid { field: "ios_url" })
        );
    }

    #[test]
    fn http_needs_opt_in() {
        let lan = ClientDownloadSettings {
            base_url: "http://10.0.0.5/xguard/".into(),
            releases_url: "http://10.0.0.5/xguard/".into(),
            android_url: Some("http://10.0.0.5/xguard/xguard.apk".into()),
            ios_url: None,
            macos_installer: false,
            allow_http: true,
        };
        let canonical = lan.canonicalize().unwrap();
        assert_eq!(canonical.base_url, "http://10.0.0.5/xguard");
        assert!(canonical.uses_http());
        let refused = ClientDownloadSettings {
            allow_http: false,
            ..lan
        };
        assert_eq!(
            refused.canonicalize(),
            Err(ClientDownloadsError::InsecureScheme { field: "base_url" })
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let result: Result<ClientDownloadSettings, _> = serde_json::from_str(
            r#"{"base_url":"https://a.b","releases_url":"https://a.b","extra":1}"#,
        );
        assert!(result.is_err());
        let minimal: ClientDownloadSettings =
            serde_json::from_str(r#"{"base_url":"https://a.b","releases_url":"https://a.b"}"#)
                .unwrap();
        assert!(!minimal.allow_http);
        assert!(!minimal.macos_installer);
        assert_eq!(minimal.android_url, None);
    }

    #[test]
    fn cache_is_used_once_initialized() {
        // Before initialization, updates do not populate the cache.
        settings("https://one.example").set_cached();
        assert!(get_client_download_settings().is_none());
        set_client_download_settings(Some(ClientDownloadSettings::default()));
        settings("https://two.example").set_cached();
        assert_eq!(
            get_client_download_settings().as_ref().unwrap().base_url,
            "https://two.example"
        );
        set_client_download_settings(None);
    }
}
