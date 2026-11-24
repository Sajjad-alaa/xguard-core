//! Destination-specific formatting and transport for activity log streams.

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use chrono::{NaiveDateTime, TimeZone, Utc};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue};
use serde_json::{Map, Value};

use super::{
    BodyFormat, DEFAULT_SPLUNK_SOURCETYPE, StoredConfig, StreamType, syslog::SyslogSender,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub enum Output {
    Http(Box<HttpOutput>),
    Syslog(Box<SyslogSender>),
}

pub struct HttpOutput {
    client: reqwest::Client,
    stream_type: StreamType,
    config: StoredConfig,
}

impl Output {
    pub fn from_target(stream_type: StreamType, config: StoredConfig) -> Result<Self, String> {
        if stream_type.is_http() {
            Ok(Self::Http(Box::new(HttpOutput::new(stream_type, config)?)))
        } else {
            Ok(Self::Syslog(Box::new(SyslogSender::new(&config)?)))
        }
    }

    pub async fn send_batch(&mut self, lines: &[Bytes]) -> Result<(), String> {
        match self {
            Self::Http(http) => http.send_batch(lines).await,
            Self::Syslog(syslog) => syslog.send_batch(lines).await,
        }
    }
}

impl HttpOutput {
    pub fn new(stream_type: StreamType, config: StoredConfig) -> Result<Self, String> {
        let mut builder = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!config.url.starts_with("http://"));

        if !config.tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        } else if let Some(cert) = &config.cert {
            let cert = reqwest::Certificate::from_pem(cert.as_bytes())
                .map_err(|err| format!("invalid CA certificate: {err}"))?;
            builder = builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(cert);
        }
        let client = builder.build().map_err(|err| err.to_string())?;
        Ok(Self {
            client,
            stream_type,
            config,
        })
    }

    pub async fn send_batch(&self, lines: &[Bytes]) -> Result<(), String> {
        if lines.is_empty() {
            return Ok(());
        }
        match self.stream_type {
            StreamType::VectorHttp | StreamType::LogstashHttp => {
                let body = join_ndjson(lines);
                self.post("application/x-ndjson", body).await
            }
            StreamType::Http => match self.config.body_format {
                BodyFormat::Ndjson => {
                    let body = join_ndjson(lines);
                    self.post("application/x-ndjson", body).await
                }
                BodyFormat::JsonArray => {
                    let body = join_json_array(lines);
                    self.post("application/json", body).await
                }
                BodyFormat::Json => {
                    for line in lines {
                        let trimmed = trim_newline(line);
                        self.post("application/json", Bytes::copy_from_slice(trimmed))
                            .await?;
                    }
                    Ok(())
                }
            },
            StreamType::SplunkHec => {
                let body = build_splunk_hec_batch(lines, self.config.splunk.as_ref());
                self.post("application/json", body).await
            }
            StreamType::Syslog => Err("syslog target cannot use HTTP output".to_owned()),
        }
    }

    async fn post(&self, content_type: &'static str, body: Bytes) -> Result<(), String> {
        let mut request = self
            .client
            .post(&self.config.url)
            .header(CONTENT_TYPE, content_type)
            .body(body);

        if self.stream_type == StreamType::SplunkHec {
            if let Some(token) = &self.config.token {
                let auth = HeaderValue::from_str(&format!("Splunk {token}"))
                    .map_err(|_| "invalid Splunk HEC token header".to_owned())?;
                request = request.header(AUTHORIZATION, auth);
            }
        } else {
            if let Some(username) = &self.config.username {
                request = request.basic_auth(username, self.config.password.as_deref());
            }
            for header in &self.config.headers {
                let name = HeaderName::from_bytes(header.name.as_bytes())
                    .map_err(|_| format!("invalid header name: {}", header.name))?;
                let value = HeaderValue::from_str(&header.value)
                    .map_err(|_| format!("invalid header value for {}", header.name))?;
                request = request.header(name, value);
            }
        }

        let response = request
            .send()
            .await
            .map_err(|err| err.without_url().to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("the collector answered {}", response.status()))
        }
    }
}

fn trim_newline(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    &line[..end]
}

fn join_ndjson(lines: &[Bytes]) -> Bytes {
    let total: usize = lines.iter().map(|l| trim_newline(l).len() + 1).sum();
    let mut out = BytesMut::with_capacity(total);
    for line in lines {
        out.extend_from_slice(trim_newline(line));
        out.extend_from_slice(b"\n");
    }
    out.freeze()
}

fn join_json_array(lines: &[Bytes]) -> Bytes {
    let total: usize = lines
        .iter()
        .map(|l| trim_newline(l).len() + 1)
        .sum::<usize>()
        + 2;
    let mut out = BytesMut::with_capacity(total);
    out.extend_from_slice(b"[");
    for (idx, line) in lines.iter().enumerate() {
        if idx > 0 {
            out.extend_from_slice(b",");
        }
        out.extend_from_slice(trim_newline(line));
    }
    out.extend_from_slice(b"]");
    out.freeze()
}

fn entry_unix_time(entry: &Value) -> f64 {
    if let Some(ts) = entry.get("timestamp").and_then(Value::as_str) {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
            return dt.timestamp() as f64 + f64::from(dt.timestamp_subsec_millis()) / 1000.0;
        }
        if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
            let dt = Utc.from_utc_datetime(&ndt);
            return dt.timestamp() as f64 + f64::from(dt.timestamp_subsec_millis()) / 1000.0;
        }
        if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S%.f") {
            let dt = Utc.from_utc_datetime(&ndt);
            return dt.timestamp() as f64 + f64::from(dt.timestamp_subsec_millis()) / 1000.0;
        }
    }
    let now = Utc::now();
    now.timestamp() as f64 + f64::from(now.timestamp_subsec_millis()) / 1000.0
}

fn build_splunk_hec_batch(lines: &[Bytes], options: Option<&super::SplunkOptions>) -> Bytes {
    let sourcetype = options
        .and_then(|o| o.sourcetype.as_deref())
        .unwrap_or(DEFAULT_SPLUNK_SOURCETYPE);
    let source = options.and_then(|o| o.source.as_deref());
    let index = options.and_then(|o| o.index.as_deref());

    let mut out = BytesMut::new();
    for line in lines {
        let trimmed = trim_newline(line);
        let event: Value = serde_json::from_slice(trimmed)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(trimmed).into_owned()));
        let mut envelope = Map::new();
        envelope.insert("time".to_owned(), Value::from(entry_unix_time(&event)));
        envelope.insert(
            "sourcetype".to_owned(),
            Value::String(sourcetype.to_owned()),
        );
        if let Some(src) = source {
            envelope.insert("source".to_owned(), Value::String(src.to_owned()));
        }
        if let Some(idx) = index {
            envelope.insert("index".to_owned(), Value::String(idx.to_owned()));
        }
        envelope.insert("event".to_owned(), event);
        if let Ok(encoded) = serde_json::to_vec(&Value::Object(envelope)) {
            out.extend_from_slice(&encoded);
            out.extend_from_slice(b"\n");
        }
    }
    out.freeze()
}
