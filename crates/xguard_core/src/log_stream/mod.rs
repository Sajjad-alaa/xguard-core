//! Activity log streaming: every activity log entry is sent to SIEMs and log collectors. New
//! code, AGPL-3.0.
//!
//! - **Destinations** are stored in `activity_log_stream`. Secrets (password, Splunk token,
//!   custom header values, TLS client key) are kept server-side and never returned by the API;
//!   the API shows `*_set` flags instead.
//! - **Outputs** ([`output`]): Vector and Logstash (newline-delimited JSON over HTTP), generic
//!   JSON over HTTP(S) (one entry per request, a JSON array or NDJSON), Splunk HEC, and syslog
//!   ([`syslog`]: RFC 5424 or RFC 3164 over UDP, TCP or TLS).
//! - **Delivery** ([`sender`]): one worker per destination; see there for buffering and
//!   retries.
//!
//! Every output carries the same entry: the activity log entry as JSON, as documented in
//! `docs/activity-log-streaming.md`.

pub mod output;
pub mod sender;
pub mod syslog;
#[cfg(test)]
mod tests;

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor, types::Json};
use url::Url;
use xguard_common::db::Id;

/// At most this many destinations; each one holds a buffer and a connection.
pub const MAX_STREAMS: i64 = 10;
const MAX_NAME_CHARS: usize = 100;
const MAX_CERT_BYTES: usize = 64 * 1024;
/// At most this many custom HTTP headers per destination.
pub const MAX_HEADERS: usize = 16;
const MAX_HEADER_NAME_BYTES: usize = 64;
const MAX_HEADER_VALUE_BYTES: usize = 4096;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_SPLUNK_FIELD_CHARS: usize = 100;
/// RFC 5424 limits.
const MAX_APP_NAME_BYTES: usize = 48;
const MAX_HOSTNAME_BYTES: usize = 255;
/// Default syslog facility: local0.
pub const DEFAULT_FACILITY: u8 = 16;
pub const DEFAULT_APP_NAME: &str = "xguard";
/// Default Splunk HEC path, used when the URL has none.
const SPLUNK_EVENT_PATH: &str = "/services/collector/event";
pub const DEFAULT_SPLUNK_SOURCETYPE: &str = "xguard:activity";

/// Headers that are set by XGuard or by the HTTP stack, and can't be overridden.
const RESERVED_HEADERS: [&str; 10] = [
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "expect",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    /// Vector's `http_server` source: NDJSON over HTTP.
    VectorHttp,
    /// Logstash's `http` input (codec `json_lines`): NDJSON over HTTP.
    LogstashHttp,
    /// Syslog (rsyslog, syslog-ng, QRadar, Wazuh, Graylog) over UDP, TCP or TLS.
    Syslog,
    /// Generic JSON over HTTP(S), e.g. a webhook.
    Http,
    /// Splunk HTTP Event Collector.
    SplunkHec,
}

impl StreamType {
    fn as_str(self) -> &'static str {
        match self {
            Self::VectorHttp => "vector_http",
            Self::LogstashHttp => "logstash_http",
            Self::Syslog => "syslog",
            Self::Http => "http",
            Self::SplunkHec => "splunk_hec",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "vector_http" => Some(Self::VectorHttp),
            "logstash_http" => Some(Self::LogstashHttp),
            "syslog" => Some(Self::Syslog),
            "http" => Some(Self::Http),
            "splunk_hec" => Some(Self::SplunkHec),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_http(self) -> bool {
        !matches!(self, Self::Syslog)
    }
}

/// How entries are put in an HTTP request body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BodyFormat {
    /// One JSON object per line (`application/x-ndjson`), batched.
    #[default]
    Ndjson,
    /// A JSON array of entries (`application/json`), batched.
    JsonArray,
    /// One entry per request, as a JSON object (`application/json`).
    Json,
}

/// Syslog message format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SyslogFormat {
    #[default]
    Rfc5424,
    Rfc3164,
}

/// How syslog messages are delimited on TCP and TLS (RFC 6587). Not used for UDP.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SyslogFraming {
    /// `<length> <message>`: works with any message content.
    #[default]
    OctetCounting,
    /// `<message>\n`: for collectors that only take newline-delimited messages.
    Newline,
}

/// Syslog settings. The transport comes from the URL scheme: `udp://`, `tcp://` or `tls://`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SyslogOptions {
    #[serde(default)]
    pub format: SyslogFormat,
    #[serde(default)]
    pub framing: SyslogFraming,
    /// Facility number, 0 to 23 (16 is local0).
    #[serde(default = "default_facility")]
    pub facility: u8,
    /// APP-NAME (RFC 5424) or TAG (RFC 3164). Default `xguard`.
    #[serde(default)]
    pub app_name: Option<String>,
    /// HOSTNAME field. Default: this machine's host name.
    #[serde(default)]
    pub hostname: Option<String>,
}

fn default_facility() -> u8 {
    DEFAULT_FACILITY
}

impl Default for SyslogOptions {
    fn default() -> Self {
        Self {
            format: SyslogFormat::default(),
            framing: SyslogFraming::default(),
            facility: DEFAULT_FACILITY,
            app_name: None,
            hostname: None,
        }
    }
}

/// Splunk HEC envelope fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SplunkOptions {
    /// Default `xguard:activity`.
    #[serde(default)]
    pub sourcetype: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
}

/// A custom header as stored: the value is a secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredHeader {
    pub name: String,
    pub value: String,
}

/// A custom header as the API shows it: only whether a value is set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HeaderView {
    pub name: String,
    pub value_set: bool,
}

/// A custom header in a request.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HeaderInput {
    pub name: String,
    /// The value. Leave it out to keep the stored value of the header with this name.
    #[serde(default)]
    pub value: Option<String>,
}

/// What is stored in the `config` column. Fields added after the first version have defaults,
/// so older rows keep working.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredConfig {
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// PEM CA certificate trusted instead of the system ones.
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default = "default_true")]
    pub tls_verify: bool,
    /// PEM client certificate (syslog over TLS).
    #[serde(default)]
    pub client_cert: Option<String>,
    /// PEM private key of the client certificate.
    #[serde(default)]
    pub client_key: Option<String>,
    #[serde(default)]
    pub body_format: BodyFormat,
    #[serde(default)]
    pub headers: Vec<StoredHeader>,
    #[serde(default)]
    pub syslog: Option<SyslogOptions>,
    #[serde(default)]
    pub splunk: Option<SplunkOptions>,
    /// Splunk HEC token.
    #[serde(default)]
    pub token: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for StoredConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            username: None,
            password: None,
            cert: None,
            tls_verify: true,
            client_cert: None,
            client_key: None,
            body_format: BodyFormat::default(),
            headers: Vec::new(),
            syslog: None,
            splunk: None,
            token: None,
        }
    }
}

impl StoredConfig {
    fn has_secrets(&self) -> bool {
        self.password.is_some()
            || self.token.is_some()
            || self.client_key.is_some()
            || !self.headers.is_empty()
    }
}

/// A destination as the API shows it: no secrets, only whether they are set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ActivityLogStream {
    pub id: Id,
    pub name: String,
    pub stream_type: StreamType,
    /// `http(s)://` for HTTP outputs; `udp://`, `tcp://` or `tls://` for syslog.
    pub url: String,
    pub username: Option<String>,
    /// PEM CA certificate trusted for this destination, instead of the system ones.
    pub cert: Option<String>,
    pub password_set: bool,
    /// Whether the destination's TLS certificate is verified (on unless turned off).
    pub tls_verify: bool,
    /// PEM client certificate for syslog over TLS.
    pub client_cert: Option<String>,
    pub client_key_set: bool,
    /// How entries are put in a request (HTTP outputs).
    pub body_format: BodyFormat,
    /// Custom HTTP headers; their values are never returned.
    pub headers: Vec<HeaderView>,
    pub syslog: Option<SyslogOptions>,
    pub splunk: Option<SplunkOptions>,
    /// Whether a Splunk HEC token is stored.
    pub token_set: bool,
}

/// A destination with everything the sender needs.
#[derive(Clone)]
pub struct StreamTarget {
    pub id: Id,
    pub name: String,
    pub stream_type: StreamType,
    pub config: StoredConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StreamInput {
    pub name: String,
    pub stream_type: StreamType,
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
    /// A new password. Leave it out to keep the stored one; send an empty string to remove it.
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
    /// Verify the destination's TLS certificate. Default `true`.
    #[serde(default)]
    pub tls_verify: Option<bool>,
    /// PEM client certificate for syslog over TLS.
    #[serde(default)]
    pub client_cert: Option<String>,
    /// PEM private key of the client certificate. Leave it out to keep the stored one; send an
    /// empty string to remove it.
    #[serde(default)]
    pub client_key: Option<String>,
    /// For the generic HTTP output; Vector and Logstash always use NDJSON.
    #[serde(default)]
    pub body_format: Option<BodyFormat>,
    /// Custom HTTP headers (generic HTTP only). Leave the list out to keep the stored headers.
    #[serde(default)]
    pub headers: Option<Vec<HeaderInput>>,
    #[serde(default)]
    pub syslog: Option<SyslogOptions>,
    #[serde(default)]
    pub splunk: Option<SplunkOptions>,
    /// A new Splunk HEC token. Leave it out to keep the stored one.
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("{0}")]
    Invalid(String),
    #[error("Activity log stream not found")]
    NotFound,
    #[error("At most {MAX_STREAMS} activity log streams can be configured.")]
    TooMany,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

fn invalid(message: impl Into<String>) -> StreamError {
    StreamError::Invalid(message.into())
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Whether `url` is HTTPS or TLS, or goes to this machine.
fn is_protected(url: &Url) -> bool {
    if matches!(url.scheme(), "https" | "tls") {
        return true;
    }
    url.host_str().is_some_and(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    })
}

/// Scheme, host and port: stored secrets are only reused while these stay the same.
fn origin(url: &str) -> Option<(String, String, Option<u16>)> {
    let url = Url::parse(url).ok()?;
    Some((
        url.scheme().to_owned(),
        url.host_str()?.to_ascii_lowercase(),
        url.port_or_known_default(),
    ))
}

/// Printable US-ASCII without spaces (RFC 5424 PRINTUSASCII).
fn is_print_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (33..=126).contains(&byte))
}

fn is_header_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn is_splunk_field(value: &str) -> bool {
    value.chars().count() <= MAX_SPLUNK_FIELD_CHARS
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.:/".contains(c))
}

fn check_pem_cert(cert: &str, what: &str) -> Result<(), StreamError> {
    if cert.len() > MAX_CERT_BYTES {
        return Err(invalid(format!("The {what} is too large.")));
    }
    if syslog::parse_certs(cert).is_none_or(|certs| certs.is_empty()) {
        return Err(invalid(format!("The {what} is not valid PEM.")));
    }
    Ok(())
}

/// Secrets of a destination being edited. Tracks whether a stored secret was kept, so a
/// changed address can't receive it without the admin entering it again.
struct Secrets {
    stored: StoredConfig,
    kept: bool,
}

impl Secrets {
    /// A new secret: `None` keeps the stored one, an empty string removes it.
    fn pick(
        &mut self,
        new: Option<String>,
        stored: fn(&StoredConfig) -> &Option<String>,
    ) -> Option<String> {
        match new {
            Some(value) if value.trim().is_empty() => None,
            Some(value) => Some(value.trim().to_owned()),
            None => {
                let value = stored(&self.stored).clone();
                self.kept |= value.is_some();
                value
            }
        }
    }

    /// Checks custom headers. A header without a value keeps the stored value of the same name.
    fn headers(&mut self, inputs: Vec<HeaderInput>) -> Result<Vec<StoredHeader>, StreamError> {
        if inputs.len() > MAX_HEADERS {
            return Err(invalid(format!(
                "At most {MAX_HEADERS} custom headers can be set."
            )));
        }
        let mut headers: Vec<StoredHeader> = Vec::with_capacity(inputs.len());
        for input in inputs {
            let name = input.name.trim().to_owned();
            if name.len() > MAX_HEADER_NAME_BYTES || !is_header_token(&name) {
                return Err(invalid("A custom header name is not valid."));
            }
            let lower = name.to_ascii_lowercase();
            if RESERVED_HEADERS.contains(&lower.as_str()) || lower.starts_with("proxy-") {
                return Err(invalid(format!("The {name} header is set by XGuard.")));
            }
            if headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case(&name))
            {
                return Err(invalid(format!("The {name} header is set twice.")));
            }
            let value = match input.value {
                Some(value) => value.trim().to_owned(),
                None => {
                    let value = self
                        .stored
                        .headers
                        .iter()
                        .find(|header| header.name.eq_ignore_ascii_case(&name))
                        .map(|header| header.value.clone())
                        .ok_or_else(|| invalid(format!("Enter a value for the {name} header.")))?;
                    self.kept = true;
                    value
                }
            };
            if value.is_empty()
                || value.len() > MAX_HEADER_VALUE_BYTES
                || value.contains(['\r', '\n'])
                || reqwest::header::HeaderValue::from_str(&value).is_err()
            {
                return Err(invalid(format!(
                    "The value of the {name} header is not valid."
                )));
            }
            headers.push(StoredHeader { name, value });
        }
        Ok(headers)
    }
}

impl StreamInput {
    /// Checks the input and builds what is stored. Secrets that are left out are taken from
    /// `stored`, but only while the destination's scheme, host and port stay the same: a
    /// changed address needs them entered again, so it can't be used to collect them.
    pub fn into_config(
        self,
        stored: Option<StoredConfig>,
    ) -> Result<(String, StreamType, StoredConfig), StreamError> {
        let name = self.name.trim().to_owned();
        if name.chars().count() > MAX_NAME_CHARS || !xguard_common::names::is_safe_name(&name) {
            return Err(invalid(
                "Use a name of up to 100 letters, digits, spaces and - _ . ( ) : /.",
            ));
        }
        let stream_type = self.stream_type;
        let mut url = Url::parse(self.url.trim()).map_err(|_| invalid("The URL is not valid."))?;
        if stream_type.is_http() {
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(invalid("Use an http:// or https:// URL."));
            }
        } else {
            if !matches!(url.scheme(), "udp" | "tcp" | "tls")
                || url.host_str().is_none_or(str::is_empty)
            {
                return Err(invalid(
                    "Use a udp://, tcp:// or tls:// URL with a host, e.g. tls://siem.example.com:6514.",
                ));
            }
            if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some()
            {
                return Err(invalid("A syslog URL has only a host and a port."));
            }
            if url.port().is_none() {
                let port = if url.scheme() == "tls" { 6514 } else { 514 };
                url.set_port(Some(port))
                    .map_err(|()| invalid("The URL is not valid."))?;
            }
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(invalid(
                "Put credentials in the username and password fields, not in the URL.",
            ));
        }
        // Block cloud metadata / link-local / unspecified destinations (SSRF hardening).
        // Note: `url::Url` only parses IP literals into `Host::Ipv4` for special schemes
        // (http/https), whereas syslog schemes (`udp`, `tcp`, `tls`) yield `Host::Domain`.
        if let Some(host) = url.host() {
            let is_blocked_ip = |ip: std::net::IpAddr| match ip {
                std::net::IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified(),
                std::net::IpAddr::V6(v6) => {
                    v6.is_unspecified()
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                        || v6
                            .to_ipv4_mapped()
                            .is_some_and(|v4| v4.is_link_local() || v4.is_unspecified())
                }
            };
            let blocked = match host {
                url::Host::Ipv4(ip) => is_blocked_ip(std::net::IpAddr::V4(ip)),
                url::Host::Ipv6(ip) => is_blocked_ip(std::net::IpAddr::V6(ip)),
                url::Host::Domain(domain) => {
                    let bare = domain.trim_start_matches('[').trim_end_matches(']');
                    bare.eq_ignore_ascii_case("metadata.google.internal")
                        || bare.eq_ignore_ascii_case("metadata.goog")
                        || bare.parse::<std::net::IpAddr>().is_ok_and(is_blocked_ip)
                }
            };
            if blocked {
                return Err(invalid(
                    "Link-local, unspecified, and cloud metadata addresses are not allowed.",
                ));
            }
        }
        if stream_type == StreamType::SplunkHec && matches!(url.path(), "" | "/") {
            url.set_path(SPLUNK_EVENT_PATH);
        }
        let url_string = url.to_string();
        let same_origin = stored
            .as_ref()
            .is_some_and(|stored| origin(&stored.url) == origin(&url_string));
        let mut secrets = Secrets {
            stored: stored.unwrap_or_default(),
            kept: false,
        };

        let tls = matches!(url.scheme(), "https" | "tls");
        let tls_verify = self.tls_verify.unwrap_or(true);
        if !tls_verify && !tls {
            return Err(invalid(
                "Turning off certificate verification only applies to https:// and tls:// URLs.",
            ));
        }

        // HTTP basic auth; Splunk authenticates with its token.
        let (username, password) = if matches!(
            stream_type,
            StreamType::VectorHttp | StreamType::LogstashHttp | StreamType::Http
        ) {
            let username = non_empty(self.username);
            let password = secrets.pick(self.password, |stored| &stored.password);
            if password.is_some() && username.is_none() {
                return Err(invalid("A password needs a username."));
            }
            (username, password)
        } else {
            (None, None)
        };

        let cert = non_empty(self.cert);
        if let Some(cert) = &cert {
            if !tls {
                return Err(invalid(
                    "A CA certificate only applies to https:// and tls:// URLs.",
                ));
            }
            check_pem_cert(cert, "CA certificate")?;
            if stream_type.is_http() {
                reqwest::Certificate::from_pem(cert.as_bytes())
                    .map_err(|_| invalid("The CA certificate is not valid PEM."))?;
            }
        }

        // TLS client certificate: syslog over TLS only.
        let (client_cert, client_key) = if url.scheme() == "tls" {
            let client_cert = non_empty(self.client_cert);
            let client_key = secrets.pick(self.client_key, |stored| &stored.client_key);
            match (&client_cert, &client_key) {
                (Some(cert), Some(key)) => {
                    check_pem_cert(cert, "client certificate")?;
                    if key.len() > MAX_CERT_BYTES || syslog::parse_key(key).is_none() {
                        return Err(invalid("The client key is not a valid PEM private key."));
                    }
                }
                (None, None) => {}
                _ => {
                    return Err(invalid(
                        "A client certificate needs its private key, and the other way round.",
                    ));
                }
            }
            (client_cert, client_key)
        } else {
            if non_empty(self.client_cert).is_some() || non_empty(self.client_key).is_some() {
                return Err(invalid(
                    "A client certificate only applies to syslog over tls://.",
                ));
            }
            (None, None)
        };

        // Custom headers: generic HTTP only.
        let headers = if stream_type == StreamType::Http {
            match self.headers {
                Some(inputs) => secrets.headers(inputs)?,
                None => {
                    let stored = std::mem::take(&mut secrets.stored.headers);
                    secrets.kept |= !stored.is_empty();
                    stored
                }
            }
        } else {
            Vec::new()
        };
        if username.is_some()
            && headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("authorization"))
        {
            return Err(invalid(
                "Use either a username and password or an Authorization header, not both.",
            ));
        }

        let body_format = match stream_type {
            StreamType::Http => self.body_format.unwrap_or(BodyFormat::JsonArray),
            _ => BodyFormat::Ndjson,
        };

        let (splunk, token) = if stream_type == StreamType::SplunkHec {
            let options = self.splunk.unwrap_or_default();
            let sourcetype = non_empty(options.sourcetype);
            let source = non_empty(options.source);
            let index = non_empty(options.index);
            for value in [&sourcetype, &source, &index].into_iter().flatten() {
                if !is_splunk_field(value) {
                    return Err(invalid(
                        "Use up to 100 letters, digits and _ - . : / for the sourcetype, source and index.",
                    ));
                }
            }
            let Some(token) = secrets.pick(self.token, |stored| &stored.token) else {
                return Err(invalid("Enter the HEC token."));
            };
            if token.len() > MAX_TOKEN_BYTES || !is_print_ascii(&token) {
                return Err(invalid("The HEC token is not valid."));
            }
            (
                Some(SplunkOptions {
                    sourcetype,
                    source,
                    index,
                }),
                Some(token),
            )
        } else {
            (None, None)
        };

        let syslog = if stream_type == StreamType::Syslog {
            let mut options = self.syslog.unwrap_or_default();
            if options.facility > 23 {
                return Err(invalid("The syslog facility is a number from 0 to 23."));
            }
            options.app_name = non_empty(options.app_name);
            if let Some(app_name) = &options.app_name
                && (app_name.len() > MAX_APP_NAME_BYTES || !is_print_ascii(app_name))
            {
                return Err(invalid(
                    "Use an app name of up to 48 ASCII characters without spaces.",
                ));
            }
            options.hostname = non_empty(options.hostname);
            if let Some(hostname) = &options.hostname
                && (hostname.len() > MAX_HOSTNAME_BYTES || !is_print_ascii(hostname))
            {
                return Err(invalid(
                    "Use a host name of up to 255 ASCII characters without spaces.",
                ));
            }
            Some(options)
        } else {
            None
        };

        if secrets.kept && !same_origin {
            return Err(invalid(
                "The address changed: enter the password, token, header values or client key again.",
            ));
        }

        let config = StoredConfig {
            url: url_string,
            username,
            password,
            cert,
            tls_verify,
            client_cert,
            client_key,
            body_format,
            headers,
            syslog,
            splunk,
            token,
        };
        // Secrets travel only over TLS, or to this machine.
        if config.has_secrets() && !is_protected(&url) {
            return Err(invalid(
                "Credentials, tokens and custom headers are only sent over TLS. Use an https:// URL, or remove them.",
            ));
        }
        Ok((name, stream_type, config))
    }
}

#[derive(FromRow)]
struct Row {
    id: Id,
    name: String,
    stream_type: String,
    config: Json<StoredConfig>,
}

impl Row {
    fn stream_type(&self) -> StreamType {
        StreamType::parse(&self.stream_type).unwrap_or(StreamType::VectorHttp)
    }

    fn into_view(self) -> ActivityLogStream {
        let stream_type = self.stream_type();
        let config = self.config.0;
        ActivityLogStream {
            id: self.id,
            name: self.name,
            stream_type,
            password_set: config.password.is_some(),
            url: config.url,
            username: config.username,
            cert: config.cert,
            tls_verify: config.tls_verify,
            client_cert: config.client_cert,
            client_key_set: config.client_key.is_some(),
            body_format: config.body_format,
            headers: config
                .headers
                .into_iter()
                .map(|header| HeaderView {
                    name: header.name,
                    value_set: !header.value.is_empty(),
                })
                .collect(),
            syslog: config.syslog,
            splunk: config.splunk,
            token_set: config.token.is_some(),
        }
    }

    fn into_target(self) -> StreamTarget {
        StreamTarget {
            stream_type: self.stream_type(),
            id: self.id,
            name: self.name,
            config: self.config.0,
        }
    }
}

impl ActivityLogStream {
    pub async fn all<'e, E: PgExecutor<'e>>(executor: E) -> Result<Vec<Self>, sqlx::Error> {
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, name, stream_type, config FROM activity_log_stream ORDER BY id",
        )
        .fetch_all(executor)
        .await?;
        Ok(rows.into_iter().map(Row::into_view).collect())
    }

    pub async fn find_by_id<'e, E: PgExecutor<'e>>(
        executor: E,
        id: Id,
    ) -> Result<Option<Self>, sqlx::Error> {
        let row: Option<Row> = sqlx::query_as(
            "SELECT id, name, stream_type, config FROM activity_log_stream WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(executor)
        .await?;
        Ok(row.map(Row::into_view))
    }

    /// The stored configuration of a destination, with its secrets.
    pub async fn stored_config<'e, E: PgExecutor<'e>>(
        executor: E,
        id: Id,
    ) -> Result<Option<StoredConfig>, sqlx::Error> {
        let config: Option<Json<StoredConfig>> =
            sqlx::query_scalar("SELECT config FROM activity_log_stream WHERE id = $1")
                .bind(id)
                .fetch_optional(executor)
                .await?;
        Ok(config.map(|config| config.0))
    }

    pub async fn create(
        conn: &mut sqlx::PgConnection,
        input: StreamInput,
    ) -> Result<Self, StreamError> {
        let (name, stream_type, config) = input.into_config(None)?;
        // Serialize concurrent creations so the limit holds. The lock needs a transaction;
        // inside a caller's transaction this is a savepoint.
        let mut tx = sqlx::Acquire::begin(&mut *conn).await?;
        sqlx::query("LOCK TABLE activity_log_stream IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM activity_log_stream")
            .fetch_one(&mut *tx)
            .await?;
        if count >= MAX_STREAMS {
            // Release the lock now; a dropped transaction would hold it until the connection is
            // next used.
            tx.rollback().await?;
            return Err(StreamError::TooMany);
        }
        let row: Row = sqlx::query_as(
            "INSERT INTO activity_log_stream (name, stream_type, config) VALUES ($1, $2, $3) \
             RETURNING id, name, stream_type, config",
        )
        .bind(name)
        .bind(stream_type.as_str())
        .bind(Json(config))
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.into_view())
    }

    pub async fn update(
        conn: &mut sqlx::PgConnection,
        id: Id,
        input: StreamInput,
    ) -> Result<Self, StreamError> {
        let stored = Self::stored_config(&mut *conn, id)
            .await?
            .ok_or(StreamError::NotFound)?;
        let (name, stream_type, config) = input.into_config(Some(stored))?;
        let row: Row = sqlx::query_as(
            "UPDATE activity_log_stream SET name = $2, stream_type = $3, config = $4 \
             WHERE id = $1 RETURNING id, name, stream_type, config",
        )
        .bind(id)
        .bind(name)
        .bind(stream_type.as_str())
        .bind(Json(config))
        .fetch_one(&mut *conn)
        .await?;
        Ok(row.into_view())
    }

    pub async fn delete<'e, E: PgExecutor<'e>>(executor: E, id: Id) -> Result<Self, StreamError> {
        let row: Option<Row> = sqlx::query_as(
            "DELETE FROM activity_log_stream WHERE id = $1 RETURNING id, name, stream_type, config",
        )
        .bind(id)
        .fetch_optional(executor)
        .await?;
        row.map(Row::into_view).ok_or(StreamError::NotFound)
    }

    /// Destinations with their secrets, for the sender.
    pub async fn targets<'e, E: PgExecutor<'e>>(
        executor: E,
    ) -> Result<Vec<StreamTarget>, sqlx::Error> {
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, name, stream_type, config FROM activity_log_stream ORDER BY id",
        )
        .fetch_all(executor)
        .await?;
        Ok(rows.into_iter().map(Row::into_target).collect())
    }
}
