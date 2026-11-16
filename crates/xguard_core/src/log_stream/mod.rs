//! Activity log streaming: every activity log entry is sent, as one JSON object per line, to
//! HTTP log collectors such as Vector or Logstash. New code, AGPL-3.0.
//!
//! - Destinations are stored in `activity_log_stream`. The password is kept server-side and is
//!   never returned by the API.
//! - [`sender`] runs one worker per destination; see there for buffering and retries.

pub mod sender;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    VectorHttp,
    LogstashHttp,
}

impl StreamType {
    fn as_str(self) -> &'static str {
        match self {
            Self::VectorHttp => "vector_http",
            Self::LogstashHttp => "logstash_http",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "vector_http" => Some(Self::VectorHttp),
            "logstash_http" => Some(Self::LogstashHttp),
            _ => None,
        }
    }
}

/// What is stored in the `config` column.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct StoredConfig {
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
}

/// A destination as the API shows it: no password, only whether one is set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ActivityLogStream {
    pub id: Id,
    pub name: String,
    pub stream_type: StreamType,
    pub url: String,
    pub username: Option<String>,
    /// PEM CA certificate trusted for this destination, instead of the system ones.
    pub cert: Option<String>,
    pub password_set: bool,
}

/// A destination with everything the sender needs.
#[derive(Clone)]
pub struct StreamTarget {
    pub id: Id,
    pub name: String,
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

/// Whether `url` is HTTPS, or HTTP to this machine.
fn is_protected(url: &Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    url.host_str().is_some_and(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    })
}

impl StreamInput {
    /// Checks the input and builds what is stored. `stored_password` is kept when no new
    /// password is given.
    pub fn into_config(
        self,
        stored_password: Option<String>,
    ) -> Result<(String, StreamType, StoredConfig), StreamError> {
        let name = self.name.trim().to_owned();
        if name.chars().count() > MAX_NAME_CHARS || !xguard_common::names::is_safe_name(&name) {
            return Err(invalid(
                "Use a name of up to 100 letters, digits, spaces and - _ . ( ) : /.",
            ));
        }
        let url = Url::parse(self.url.trim()).map_err(|_| invalid("The URL is not valid."))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(invalid("Use an http:// or https:// URL."));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(invalid(
                "Put credentials in the username and password fields, not in the URL.",
            ));
        }
        let username = non_empty(self.username);
        let password = match self.password {
            Some(password) if password.is_empty() => None,
            Some(password) => Some(password),
            None => stored_password,
        };
        if (username.is_some() || password.is_some()) && !is_protected(&url) {
            return Err(invalid(
                "Credentials are only sent over HTTPS. Use an https:// URL, or remove them.",
            ));
        }
        if password.is_some() && username.is_none() {
            return Err(invalid("A password needs a username."));
        }
        let cert = non_empty(self.cert);
        if let Some(cert) = &cert {
            if cert.len() > MAX_CERT_BYTES {
                return Err(invalid("The certificate is too large."));
            }
            if url.scheme() != "https" {
                return Err(invalid("A CA certificate only applies to https:// URLs."));
            }
            reqwest::Certificate::from_pem(cert.as_bytes())
                .map_err(|_| invalid("The CA certificate is not valid PEM."))?;
        }
        Ok((
            name,
            self.stream_type,
            StoredConfig {
                url: url.to_string(),
                username,
                password,
                cert,
            },
        ))
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
    fn into_view(self) -> ActivityLogStream {
        ActivityLogStream {
            id: self.id,
            name: self.name,
            stream_type: StreamType::parse(&self.stream_type).unwrap_or(StreamType::VectorHttp),
            password_set: self.config.password.is_some(),
            url: self.config.0.url,
            username: self.config.0.username,
            cert: self.config.0.cert,
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

    async fn stored_password<'e, E: PgExecutor<'e>>(
        executor: E,
        id: Id,
    ) -> Result<Option<Option<String>>, sqlx::Error> {
        let config: Option<Json<StoredConfig>> =
            sqlx::query_scalar("SELECT config FROM activity_log_stream WHERE id = $1")
                .bind(id)
                .fetch_optional(executor)
                .await?;
        Ok(config.map(|config| config.0.password))
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
        let stored = Self::stored_password(&mut *conn, id)
            .await?
            .ok_or(StreamError::NotFound)?;
        let (name, stream_type, config) = input.into_config(stored)?;
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
        Ok(rows
            .into_iter()
            .map(|row| StreamTarget {
                id: row.id,
                name: row.name,
                config: row.config.0,
            })
            .collect())
    }
}
