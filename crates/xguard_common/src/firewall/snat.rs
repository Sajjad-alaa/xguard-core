//! Source NAT bindings: traffic from a user's devices at a location leaves the gateway with a
//! chosen public address.

use std::{net::IpAddr, str::FromStr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};

use crate::db::Id;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SnatBinding {
    pub id: Id,
    pub user_id: Id,
    pub location_id: Id,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub public_ip: IpAddr,
}

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SnatBindingInput {
    pub user_id: Id,
    pub location_id: Id,
    /// The address traffic leaves with; it must be configured on the location's gateways.
    pub public_ip: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SnatError {
    #[error("{0}")]
    Invalid(String),
    #[error("SNAT binding not found")]
    NotFound,
    #[error("this user already has a SNAT binding at this location")]
    Duplicate,
    #[error("the user or location does not exist")]
    UnknownReference,
    #[error(transparent)]
    Database(sqlx::Error),
}

impl From<sqlx::Error> for SnatError {
    fn from(err: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &err {
            match db.code().as_deref() {
                Some("23505") => return Self::Duplicate,
                Some("23503") => return Self::UnknownReference,
                _ => {}
            }
        }
        Self::Database(err)
    }
}

/// Parses the public address, refusing ones that can never be a valid SNAT target.
pub fn parse_public_ip(input: &str) -> Result<IpAddr, SnatError> {
    let address = IpAddr::from_str(input.trim())
        .map_err(|_| SnatError::Invalid(format!("\"{input}\" is not an IP address.")))?;
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return Err(SnatError::Invalid(format!(
            "{address} cannot be used as a source address."
        )));
    }
    if let IpAddr::V4(v4) = address
        && v4.is_broadcast()
    {
        return Err(SnatError::Invalid(format!(
            "{address} cannot be used as a source address."
        )));
    }
    Ok(address)
}

#[derive(FromRow)]
struct Row {
    id: Id,
    user_id: Id,
    location_id: Id,
    public_ip: IpNetwork,
}

impl From<Row> for SnatBinding {
    fn from(row: Row) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            location_id: row.location_id,
            public_ip: row.public_ip.ip(),
        }
    }
}

impl SnatBinding {
    pub async fn all<'e, E: PgExecutor<'e>>(executor: E) -> Result<Vec<Self>, sqlx::Error> {
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, user_id, location_id, public_ip FROM user_snat_binding ORDER BY id",
        )
        .fetch_all(executor)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn find_by_id<'e, E: PgExecutor<'e>>(
        executor: E,
        id: Id,
    ) -> Result<Option<Self>, sqlx::Error> {
        let row: Option<Row> = sqlx::query_as(
            "SELECT id, user_id, location_id, public_ip FROM user_snat_binding WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(executor)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn create<'e, E: PgExecutor<'e>>(
        executor: E,
        input: &SnatBindingInput,
    ) -> Result<Self, SnatError> {
        let public_ip = parse_public_ip(&input.public_ip)?;
        let row: Row = sqlx::query_as(
            "INSERT INTO user_snat_binding (user_id, location_id, public_ip) VALUES ($1, $2, $3) \
            RETURNING id, user_id, location_id, public_ip",
        )
        .bind(input.user_id)
        .bind(input.location_id)
        .bind(IpNetwork::from(public_ip))
        .fetch_one(executor)
        .await?;
        Ok(row.into())
    }

    /// Changes the public address of binding `id`.
    pub async fn set_public_ip<'e, E: PgExecutor<'e>>(
        executor: E,
        id: Id,
        public_ip: &str,
    ) -> Result<Self, SnatError> {
        let public_ip = parse_public_ip(public_ip)?;
        let row: Option<Row> = sqlx::query_as(
            "UPDATE user_snat_binding SET public_ip = $2 WHERE id = $1 \
            RETURNING id, user_id, location_id, public_ip",
        )
        .bind(id)
        .bind(IpNetwork::from(public_ip))
        .fetch_optional(executor)
        .await?;
        row.map(Into::into).ok_or(SnatError::NotFound)
    }

    pub async fn delete<'e, E: PgExecutor<'e>>(executor: E, id: Id) -> Result<(), SnatError> {
        let deleted = sqlx::query("DELETE FROM user_snat_binding WHERE id = $1")
            .bind(id)
            .execute(executor)
            .await?;
        if deleted.rows_affected() == 0 {
            return Err(SnatError::NotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_public_ip;

    #[test]
    fn public_ip_validation() {
        assert!(parse_public_ip(" 203.0.113.7 ").is_ok());
        assert!(parse_public_ip("2001:db8::7").is_ok());
        for bad in [
            "",
            "203.0.113.0/24",
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
        ] {
            assert!(parse_public_ip(bad).is_err(), "{bad}");
        }
    }
}
